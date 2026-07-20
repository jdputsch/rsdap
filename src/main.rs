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
    let cfg = config::file::load(&args)?;
    let resolved = config::resolve(args, cfg)?;

    tracing_subscriber::fmt()
        .with_env_filter(
            resolved
                .debug_log
                .as_deref()
                .map(|_| "debug")
                .unwrap_or("warn"),
        )
        .init();

    app::run(resolved).await
}
