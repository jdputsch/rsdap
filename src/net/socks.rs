//! SOCKS5 proxy dialing for LDAP connections.

use anyhow::Result;
use tokio::net::TcpStream;

/// Dial `target_host:target_port` through the given SOCKS5 proxy address.
///
/// `proxy_addr` format: `socks5://host:port` or `host:port`.
pub async fn dial_through_socks5(
    proxy_addr: &str,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream> {
    todo!(
        "parse proxy_addr, connect to proxy with tokio-socks, \
         send CONNECT request for target_host:target_port, \
         return the negotiated TcpStream"
    )
}
