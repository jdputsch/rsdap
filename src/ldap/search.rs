//! LDAP search operations: paged, scoped, with deleted-object support.

use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{Scope, SearchEntry};
use tracing::{debug, error};

use crate::ldap::connection::LdapError;

pub struct SearchParams {
    pub base: String,
    pub scope: Scope,
    pub filter: String,
    pub attrs: Vec<String>,
    pub page_size: u32,
    pub include_deleted: bool,
}

/// Execute a paged LDAP search, collecting all result pages into one vec.
pub async fn search_all(
    ldap: &mut ldap3::Ldap,
    params: &SearchParams,
) -> Result<Vec<SearchEntry>, LdapError> {
    debug!(
        base = %params.base,
        filter = %params.filter,
        scope = ?params.scope,
        page_size = params.page_size,
        "search_all starting"
    );

    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(params.page_size as i32)),
    ];

    let mut stream = ldap
        .streaming_search_with(
            adapters,
            &params.base,
            params.scope,
            &params.filter,
            params.attrs.clone(),
        )
        .await
        .map_err(|e| {
            error!(error = %e, "streaming_search_with failed");
            e
        })?;

    let mut entries = Vec::new();
    while let Some(entry) = stream.next().await.map_err(|e| {
        error!(error = %e, "stream.next() error");
        e
    })? {
        entries.push(SearchEntry::construct(entry));
    }

    stream.finish().await.success().map_err(|e| {
        error!(error = %e, "stream.finish() error");
        LdapError::Connect(e)
    })?;

    debug!(count = entries.len(), "search_all complete");
    Ok(entries)
}

/// Auto-wrap a bare search term: `(|(samAccountName=X)(cn=X)(ou=X)(name=X))`
pub fn auto_wrap_filter(input: &str) -> String {
    if input.starts_with('(') {
        input.to_owned()
    } else {
        format!("(|(samAccountName={input})(cn={input})(ou={input})(name={input}))")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_wrap_passes_through_explicit_filter() {
        assert_eq!(auto_wrap_filter("(cn=foo)"), "(cn=foo)");
    }

    #[test]
    fn auto_wrap_wraps_bare_term() {
        let result = auto_wrap_filter("foo");
        assert!(result.starts_with("(|(samAccountName=foo)"));
    }
}
