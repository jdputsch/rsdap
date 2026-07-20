//! LDAP connection lifecycle, authentication, search, and mutation operations.

pub mod auth;
pub mod connection;
pub mod mutation;
pub mod search;

pub use connection::LdapClient;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackendFlavor {
    #[default]
    MsAd,
    Basic,
    Auto,
}
