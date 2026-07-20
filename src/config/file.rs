//! YAML configuration file loading and discovery.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::types::{AttrSort, SshConfig, TimeFmt};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileConfig {
    pub default_connection: Option<String>,
    #[serde(default)]
    pub global: GlobalConfig,
    #[serde(default)]
    pub connections: Vec<ConnectionConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalConfig {
    pub emojis: Option<bool>,
    pub colors: Option<bool>,
    pub format: Option<bool>,
    pub expand: Option<bool>,
    pub limit: Option<usize>,
    pub cache: Option<bool>,
    pub attrsort: Option<AttrSort>,
    pub timefmt: Option<TimeFmt>,
    pub offset: Option<i32>,
    pub exportdir: Option<String>,
    pub debug_log: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfig {
    pub name: String,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub ldaps: Option<bool>,
    pub insecure: Option<bool>,
    pub socks: Option<String>,
    pub timeout: Option<u64>,
    pub backend: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub passfile: Option<String>,
    pub domain: Option<String>,
    pub hash: Option<String>,
    pub hashfile: Option<String>,
    pub kerberos: Option<bool>,
    pub spn: Option<String>,
    pub kdc: Option<String>,
    pub crt: Option<String>,
    pub key: Option<String>,
    pub pfx: Option<String>,
    pub root_dn: Option<String>,
    pub filter: Option<String>,
    pub paging: Option<u32>,
    pub schema: Option<bool>,
    pub deleted: Option<bool>,
    pub ssh: Option<SshConfig>,
}

/// Discover and load the config file. Returns `None` if no config file is found.
pub fn load(args: &super::cli::Cli) -> Result<Option<FileConfig>> {
    let path = match &args.config {
        Some(p) => PathBuf::from(p),
        None => match discover_config_path() {
            Some(p) => p,
            None => return Ok(None),
        },
    };

    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("reading config file {}", path.display()))?;
    let cfg: FileConfig = serde_yaml::from_str(&content)
        .with_context(|| format!("parsing config file {}", path.display()))?;
    Ok(Some(cfg))
}

fn discover_config_path() -> Option<PathBuf> {
    // 1. ./rsdap.yaml
    let local = PathBuf::from("rsdap.yaml");
    if local.exists() {
        return Some(local);
    }

    // 2. ~/.config/rsdap/config.yaml (Linux/macOS) or %APPDATA%\rsdap\config.yaml (Windows)
    #[cfg(not(windows))]
    {
        if let Some(home) = dirs_home() {
            let p = home.join(".config/rsdap/config.yaml");
            if p.exists() {
                return Some(p);
            }
        }
    }
    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            let p = PathBuf::from(appdata).join("rsdap\\config.yaml");
            if p.exists() {
                return Some(p);
            }
        }
    }

    None
}

#[cfg(not(windows))]
fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Generate a fully-documented sample config YAML string.
pub fn sample_config() -> &'static str {
    include_str!("../../docs/sample-config.yaml")
}
