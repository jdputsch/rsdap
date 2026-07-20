//! LDAP connection lifecycle: plain TCP, LDAPS, StartTLS.

use anyhow::Result;
use thiserror::Error;

use crate::config::{AuthMethod, ResolvedConfig};
use crate::ldap::BackendFlavor;

#[derive(Debug, Error)]
pub enum LdapError {
    #[error("connection failed: {0}")]
    Connect(#[from] ldap3::LdapError),
    #[error("authentication failed")]
    AuthFailed,
    #[error("root DSE query failed")]
    RootDse,
}

pub struct LdapClient {
    pub root_dn: String,
    pub flavor: BackendFlavor,
    inner: ldap3::Ldap,
}

impl LdapClient {
    /// Connect and authenticate using the provided configuration.
    pub async fn connect(cfg: &ResolvedConfig) -> Result<Self, LdapError> {
        todo!("establish LDAP connection with TLS/plain/StartTLS based on cfg")
    }

    /// Discover the root DN from RootDSE `namingContexts`.
    pub async fn discover_root_dn(&mut self) -> Result<String, LdapError> {
        todo!("query RootDSE namingContexts and pick the primary naming context")
    }

    /// Upgrade an existing plain connection to TLS via StartTLS.
    pub async fn start_tls(&mut self) -> Result<(), LdapError> {
        todo!("send StartTLS extended operation and upgrade the connection")
    }
}
