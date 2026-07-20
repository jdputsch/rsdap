//! LDAP search operations: paged, scoped, with deleted-object support.

use anyhow::Result;
use ldap3::{Scope, SearchEntry};

use crate::ldap::connection::LdapError;

pub struct SearchParams {
    pub base: String,
    pub scope: Scope,
    pub filter: String,
    pub attrs: Vec<String>,
    pub page_size: u32,
    pub include_deleted: bool,
}

/// Execute a paged LDAP search, collecting all result pages.
pub async fn search_all(
    ldap: &mut ldap3::Ldap,
    params: &SearchParams,
) -> Result<Vec<SearchEntry>, LdapError> {
    todo!("run paged search using ldap3 paged-results control, return all entries")
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
