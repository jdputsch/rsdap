//! SSH local port forwarding tunnel using `russh`.

use anyhow::Result;
use thiserror::Error;

use crate::config::SshConfig;

#[derive(Debug, Error)]
pub enum SshError {
    #[error("SSH connection failed: {0}")]
    Connect(String),
    #[error("SSH authentication failed")]
    AuthFailed,
    #[error("SSH host key unknown — run `ssh-keyscan {host}` and add to known_hosts")]
    UnknownHostKey { host: String },
    #[error("tunnel setup failed: {0}")]
    Tunnel(String),
}

/// An active SSH tunnel forwarding a local port to the remote LDAP server.
pub struct SshTunnel {
    pub local_port: u16,
    // session handle goes here once implemented
}

impl SshTunnel {
    /// Establish a tunnel and return the bound local port.
    pub async fn open(
        cfg: &SshConfig,
        remote_host: &str,
        remote_port: u16,
    ) -> Result<Self, SshError> {
        todo!(
            "connect to cfg.host:cfg.port via russh, authenticate, \
             open local port forwarding to remote_host:remote_port, \
             bind random 127.0.0.1:PORT and return it"
        )
    }

    /// Close the tunnel gracefully.
    pub async fn close(self) -> Result<()> {
        todo!("send SSH disconnect and clean up the session")
    }
}
