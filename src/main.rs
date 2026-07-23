#![allow(dead_code, unused_variables, unused_imports)]

use anyhow::Result;

mod app;
mod cache;
mod config;
mod dns;
mod export;
mod formats;
mod ldap;
mod net;
mod security;
mod tui;

#[tokio::main]
async fn main() -> Result<()> {
    let args = config::cli::parse();
    let resolved = config::resolve(args)?;

    if let Some(path) = resolved.debug_log.as_deref() {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| anyhow::anyhow!("opening debug log {path}: {e}"))?;
        tracing_subscriber::fmt()
            .with_env_filter("rsdap=debug,ldap3=debug")
            .with_writer(std::sync::Mutex::new(file))
            .with_ansi(false)
            .init();
    }

    app::run(resolved).await
}
