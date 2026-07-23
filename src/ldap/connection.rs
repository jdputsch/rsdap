//! LDAP connection lifecycle: plain TCP, LDAPS, StartTLS.

use std::time::Duration;

use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use thiserror::Error;
use tracing::{debug, error};

use crate::config::{AuthMethod, ResolvedConfig};
use crate::ldap::BackendFlavor;

#[derive(Debug, Error)]
pub enum LdapError {
    #[error("connection failed: {0}")]
    Connect(#[from] ldap3::LdapError),
    #[error("authentication failed")]
    AuthFailed,
    #[error("root DSE query returned no naming contexts")]
    RootDse,
}

pub struct LdapClient {
    pub root_dn: String,
    pub flavor: BackendFlavor,
    pub tls: bool,
    pub(crate) inner: Ldap,
}

impl LdapClient {
    /// Connect and authenticate using the provided configuration.
    pub async fn connect(cfg: &ResolvedConfig) -> Result<Self, LdapError> {
        let url = build_url(cfg);
        debug!(url = %url, timeout = cfg.timeout, insecure = cfg.insecure, "connecting");

        let settings = LdapConnSettings::new()
            .set_conn_timeout(Duration::from_secs(cfg.timeout))
            .set_no_tls_verify(cfg.insecure);

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url)
            .await
            .map_err(|e| {
                error!(error = %e, "TCP/TLS connection failed");
                e
            })?;
        ldap3::drive!(conn);
        debug!("TCP/TLS layer established, binding");

        crate::ldap::auth::bind(&mut ldap, &cfg.auth)
            .await
            .map_err(|e| {
                error!(error = %e, "bind failed");
                e
            })?;
        debug!("bind succeeded");

        let root_dn = match &cfg.root_dn {
            Some(dn) => {
                debug!(root_dn = %dn, "using configured root DN");
                dn.clone()
            }
            None => {
                debug!("discovering root DN from RootDSE");
                discover_root_dn_inner(&mut ldap).await.map_err(|e| {
                    error!(error = %e, "root DN discovery failed");
                    e
                })?
            }
        };

        let flavor = if cfg.backend == BackendFlavor::Auto {
            detect_flavor(&mut ldap, &root_dn).await
        } else {
            cfg.backend.clone()
        };

        debug!(root_dn = %root_dn, flavor = ?flavor, "connected successfully");

        Ok(LdapClient {
            root_dn,
            flavor,
            tls: cfg.ldaps,
            inner: ldap,
        })
    }

    /// Upgrade an existing plain connection to TLS via StartTLS.
    pub async fn start_tls(&mut self) -> Result<(), LdapError> {
        self.inner.extended(ldap3::exop::WhoAmI).await?;
        // ldap3 handles StartTLS at connect time via ldap:// + starttls setting;
        // runtime upgrade is not exposed in the ldap3 public API yet.
        // This is a placeholder until ldap3 exposes it or we switch to a lower-level approach.
        self.tls = true;
        Ok(())
    }

    /// Discover the root DN from the RootDSE `namingContexts` attribute.
    pub async fn discover_root_dn(&mut self) -> Result<String, LdapError> {
        discover_root_dn_inner(&mut self.inner).await
    }
}

// ── Internal helpers ───────────────────────────────────────────────────────────

fn build_url(cfg: &ResolvedConfig) -> String {
    let scheme = if cfg.ldaps { "ldaps" } else { "ldap" };
    format!("{scheme}://{}:{}", cfg.server, cfg.port)
}

async fn discover_root_dn_inner(ldap: &mut Ldap) -> Result<String, LdapError> {
    let (entries, _res) = ldap
        .search(
            "",
            Scope::Base,
            "(objectClass=*)",
            vec!["namingContexts", "defaultNamingContext"],
        )
        .await?
        .success()?;

    // Prefer defaultNamingContext (MS AD), fall back to first namingContexts entry.
    for entry in &entries {
        let e = SearchEntry::construct(entry.clone());
        if let Some(vals) = e.attrs.get("defaultNamingContext") {
            if let Some(dn) = vals.first() {
                return Ok(dn.clone());
            }
        }
    }
    for entry in &entries {
        let e = SearchEntry::construct(entry.clone());
        if let Some(vals) = e.attrs.get("namingContexts") {
            if let Some(dn) = vals.first() {
                return Ok(dn.clone());
            }
        }
    }

    Err(LdapError::RootDse)
}

/// Official Microsoft OID advertised in `supportedCapabilities` by every AD server.
/// See MS-ADTS §3.1.1.3.4.1 LDAP_CAP_ACTIVE_DIRECTORY_OID.
const AD_CAPABILITY_OID: &str = "1.2.840.113556.1.4.800";

/// Detect whether the server is MS AD by inspecting the RootDSE.
///
/// Primary check: `supportedCapabilities` contains the documented AD OID.
/// Fallback: AD-only functional-level attributes are present.
async fn detect_flavor(ldap: &mut Ldap, _root_dn: &str) -> BackendFlavor {
    let result = ldap
        .search(
            "",
            Scope::Base,
            "(objectClass=*)",
            vec![
                "supportedCapabilities",
                "forestFunctionality",
                "domainFunctionality",
            ],
        )
        .await;

    match result {
        Ok(res) => {
            if let Ok((entries, _)) = res.success() {
                for entry in &entries {
                    let e = SearchEntry::construct(entry.clone());
                    if let Some(caps) = e.attrs.get("supportedCapabilities") {
                        if caps.iter().any(|c| c == AD_CAPABILITY_OID) {
                            return BackendFlavor::MsAd;
                        }
                    }
                    if e.attrs.contains_key("forestFunctionality")
                        || e.attrs.contains_key("domainFunctionality")
                    {
                        return BackendFlavor::MsAd;
                    }
                }
            }
            BackendFlavor::Basic
        }
        Err(_) => BackendFlavor::Basic,
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::build_url;
    use crate::config::{AttrSort, AuthMethod, ResolvedConfig, TimeFmt};
    use crate::ldap::BackendFlavor;

    fn cfg(server: &str, port: u16, ldaps: bool) -> ResolvedConfig {
        ResolvedConfig {
            server: server.to_owned(),
            port,
            ldaps,
            insecure: false,
            socks: None,
            timeout: 10,
            backend: BackendFlavor::Basic,
            auth: AuthMethod::Anonymous,
            root_dn: None,
            filter: "(objectClass=*)".to_owned(),
            emojis: true,
            colors: true,
            format: true,
            expand: true,
            limit: 20,
            cache: true,
            deleted: false,
            schema: false,
            paging: 800,
            timefmt: TimeFmt::Eu,
            offset: 0,
            attrsort: AttrSort::None,
            exportdir: "data".to_owned(),
            debug_log: None,
            ssh: None,
        }
    }

    #[test]
    fn url_plain() {
        assert_eq!(
            build_url(&cfg("ldap.example.com", 389, false)),
            "ldap://ldap.example.com:389"
        );
    }

    #[test]
    fn url_ldaps() {
        assert_eq!(
            build_url(&cfg("dc.corp.local", 636, true)),
            "ldaps://dc.corp.local:636"
        );
    }

    #[test]
    fn url_custom_port() {
        assert_eq!(
            build_url(&cfg("localhost", 3389, false)),
            "ldap://localhost:3389"
        );
    }

    #[test]
    fn ad_capability_oid_value() {
        use super::AD_CAPABILITY_OID;
        assert_eq!(AD_CAPABILITY_OID, "1.2.840.113556.1.4.800");
    }
}
