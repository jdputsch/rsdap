//! Configuration types shared across CLI and file config.

use serde::{Deserialize, Serialize};

use crate::ldap::BackendFlavor;

/// Fully resolved runtime configuration after merging CLI flags and config file.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    // Connection
    pub server: String,
    pub port: u16,
    pub ldaps: bool,
    pub insecure: bool,
    pub socks: Option<String>,
    pub timeout: u64,
    pub backend: BackendFlavor,

    // Authentication
    pub auth: AuthMethod,

    // TUI behavior
    pub root_dn: Option<String>,
    pub filter: String,
    pub emojis: bool,
    pub colors: bool,
    pub format: bool,
    pub expand: bool,
    pub limit: usize,
    pub cache: bool,
    pub deleted: bool,
    pub schema: bool,
    pub paging: u32,
    pub timefmt: TimeFmt,
    pub offset: i32,
    pub attrsort: AttrSort,
    pub exportdir: String,
    pub debug_log: Option<String>,

    // SSH tunnel
    pub ssh: Option<SshConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    Anonymous,
    Simple {
        username: String,
        password: String,
    },
    Ntlm {
        domain: String,
        username: String,
        hash: String,
    },
    Kerberos {
        spn: Option<String>,
        kdc: Option<String>,
    },
    Certificate {
        crt: String,
        key: String,
    },
    CertificatePkcs12 {
        pfx: String,
        passphrase: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum TimeFmt {
    #[default]
    Eu,
    Us,
    Iso8601,
    #[serde(untagged)]
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttrSort {
    #[default]
    None,
    Asc,
    Desc,
}

#[cfg(test)]
impl Default for ResolvedConfig {
    fn default() -> Self {
        Self {
            server: String::new(),
            port: 389,
            ldaps: false,
            insecure: false,
            socks: None,
            timeout: 5,
            backend: BackendFlavor::MsAd,
            auth: AuthMethod::Anonymous,
            root_dn: None,
            filter: String::new(),
            emojis: true,
            colors: true,
            format: true,
            expand: false,
            limit: 0,
            cache: false,
            deleted: false,
            schema: false,
            paging: 500,
            timefmt: TimeFmt::Eu,
            offset: 0,
            attrsort: AttrSort::None,
            exportdir: String::new(),
            debug_log: None,
            ssh: None,
        }
    }
}

impl AttrSort {
    pub fn next(&self) -> Self {
        match self {
            AttrSort::None => AttrSort::Asc,
            AttrSort::Asc => AttrSort::Desc,
            AttrSort::Desc => AttrSort::None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            AttrSort::None => "OFF",
            AttrSort::Asc => "ASC",
            AttrSort::Desc => "DESC",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: SshAuthMethod,
    pub ignore_host_key: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SshAuthMethod {
    Password {
        password: String,
    },
    PasswordFile {
        path: String,
    },
    Agent,
    Key {
        path: String,
        passphrase: Option<String>,
    },
}
