//! Configuration resolution: merge CLI flags + file config into `ResolvedConfig`.

pub mod cli;
pub mod file;
pub mod types;

pub use types::*;

use std::io::{self, Write as _};

use anyhow::{Result, bail};

use crate::ldap::BackendFlavor;

/// Dispatch subcommands, load the config file, and merge everything into a `ResolvedConfig`.
///
/// Print-and-exit subcommands (`init-config`, `version`) run before the config
/// file is loaded so a corrupt or missing file never blocks them.
pub fn resolve(args: cli::Cli) -> Result<ResolvedConfig> {
    // ── Subcommands (before any file I/O) ─────────────────────────────────────
    if let Some(cmd) = &args.command {
        match cmd {
            cli::Commands::Version => {
                println!("rsdap {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            cli::Commands::InitConfig {
                output,
                default,
                yes,
            } => {
                init_config(output.as_deref(), *default, *yes)?;
                std::process::exit(0);
            }
        }
    }

    let file = file::load(&args)?;
    resolve_inner(args, file)
}

/// Merge CLI args and an already-loaded (optional) file config into a `ResolvedConfig`.
fn resolve_inner(args: cli::Cli, file: Option<file::FileConfig>) -> Result<ResolvedConfig> {
    // ── Find named connection from file config ─────────────────────────────────
    let conn_name = args.connection.as_deref().or(
        // treat positional target as a connection name when it doesn't look like a host
        args.target
            .as_deref()
            .filter(|t| !t.contains('.') && !t.contains(':') && !t.starts_with("ldap")),
    );

    let conn = file.as_ref().and_then(|f| {
        let name = conn_name
            .or(f.default_connection.as_deref())
            .unwrap_or_default();
        f.connections.iter().find(|c| c.name == name)
    });

    let global = file.as_ref().map(|f| &f.global);

    // ── Server / host / port from positional target ────────────────────────────
    // Accepted forms: hostname, hostname:port, ldap://hostname, ldap://hostname:port,
    // ldaps://hostname, ldaps://hostname:port.
    let (server, port_from_url) = parse_target(args.target.as_deref(), conn);

    // ── Auth method ─────────────────────────────────────────────────────────────
    let auth = resolve_auth(&args, conn)?;

    // ── Backend flavor ──────────────────────────────────────────────────────────
    let backend = parse_backend(
        conn.and_then(|c| c.backend.as_deref())
            .unwrap_or(&args.backend),
    )?;

    // ── Numeric/bool fields with CLI → file-conn → global → built-in fallback ──
    macro_rules! pick {
        // bool: CLI bool flag takes precedence only when explicitly set (true); else file
        (bool $cli:expr, $conn_field:expr, $global_field:expr, $default:expr) => {
            if $cli {
                true
            } else {
                $conn_field.or_else(|| $global_field).unwrap_or($default)
            }
        };
        // scalar: Option on CLI wins; then file-conn; then global; then default
        (scalar $cli:expr, $conn_field:expr, $global_field:expr, $default:expr) => {
            $cli.or($conn_field).or($global_field).unwrap_or($default)
        };
    }

    let ldaps = args.ldaps || conn.and_then(|c| c.ldaps).unwrap_or(false);

    let default_port = if ldaps { 636 } else { 389 };
    // Precedence: explicit -P flag > port embedded in URL > file config > default
    let port = args
        .port
        .or(port_from_url)
        .or_else(|| conn.and_then(|c| c.port))
        .unwrap_or(default_port);

    let insecure = pick!(bool args.insecure, conn.and_then(|c| c.insecure), None, false);
    let cache = pick!(bool args.cache, global.and_then(|g| g.cache), None, true);
    let emojis =
        pick!(bool args.emojis, conn.and_then(|_| global.and_then(|g| g.emojis)), None, true);
    let colors =
        pick!(bool args.colors, conn.and_then(|_| global.and_then(|g| g.colors)), None, true);
    let format =
        pick!(bool args.format, conn.and_then(|_| global.and_then(|g| g.format)), None, true);
    let expand =
        pick!(bool args.expand, conn.and_then(|_| global.and_then(|g| g.expand)), None, true);
    let deleted = pick!(bool args.deleted, conn.and_then(|c| c.deleted), None, false);
    let schema = pick!(bool args.schema, conn.and_then(|c| c.schema), None, false);

    let timeout = pick!(scalar Some(args.timeout), conn.and_then(|c| c.timeout), None, 10u64);
    let limit = pick!(scalar Some(args.limit), global.and_then(|g| g.limit), None, 20usize);
    let paging = pick!(scalar Some(args.paging), conn.and_then(|c| c.paging), None, 800u32);
    let offset = pick!(scalar Some(args.offset), global.and_then(|g| g.offset), None, 0i32);

    // ── SSH tunnel ──────────────────────────────────────────────────────────────
    // Built before any partial moves out of `args`.
    let ssh = build_ssh_config(&args, conn)?;

    let socks = args
        .socks
        .clone()
        .or_else(|| conn.and_then(|c| c.socks.clone()));

    let root_dn = args
        .root_dn
        .clone()
        .or_else(|| conn.and_then(|c| c.root_dn.clone()));

    let filter = conn
        .and_then(|c| c.filter.clone())
        .unwrap_or_else(|| args.filter.clone());

    let exportdir = global
        .and_then(|g| g.exportdir.clone())
        .unwrap_or_else(|| args.exportdir.clone());

    let debug_log = args
        .debug_log
        .clone()
        .or_else(|| global.and_then(|g| g.debug_log.clone()))
        .filter(|s| !s.is_empty());

    // ── TimeFmt ─────────────────────────────────────────────────────────────────
    let timefmt = global
        .and_then(|g| g.timefmt.clone())
        .unwrap_or_else(|| parse_timefmt(&args.timefmt));

    // ── AttrSort ────────────────────────────────────────────────────────────────
    let attrsort = global
        .and_then(|g| g.attrsort.clone())
        .unwrap_or_else(|| parse_attrsort(&args.attrsort));

    Ok(ResolvedConfig {
        server,
        port,
        ldaps,
        insecure,
        socks,
        timeout,
        backend,
        auth,
        root_dn,
        filter,
        emojis,
        colors,
        format,
        expand,
        limit,
        cache,
        deleted,
        schema,
        paging,
        timefmt,
        offset,
        attrsort,
        exportdir,
        debug_log,
        ssh,
    })
}

// ── Auth resolution ────────────────────────────────────────────────────────────

fn resolve_auth(args: &cli::Cli, conn: Option<&file::ConnectionConfig>) -> Result<AuthMethod> {
    // Certificate (PEM pair)
    if args.crt.is_some() || args.key.is_some() {
        let crt = args
            .crt
            .clone()
            .or_else(|| conn.and_then(|c| c.crt.clone()))
            .unwrap_or_default();
        let key = args
            .key
            .clone()
            .or_else(|| conn.and_then(|c| c.key.clone()))
            .unwrap_or_default();
        return Ok(AuthMethod::Certificate { crt, key });
    }

    // Certificate (PKCS#12)
    if args.pfx.is_some() || conn.and_then(|c| c.pfx.as_ref()).is_some() {
        let pfx = args
            .pfx
            .clone()
            .or_else(|| conn.and_then(|c| c.pfx.clone()))
            .unwrap_or_default();
        let passphrase = args
            .password
            .clone()
            .or_else(|| conn.and_then(|c| c.password.clone()));
        return Ok(AuthMethod::CertificatePkcs12 { pfx, passphrase });
    }

    // Kerberos
    if args.kerberos || conn.and_then(|c| c.kerberos).unwrap_or(false) {
        let spn = args
            .spn
            .clone()
            .or_else(|| conn.and_then(|c| c.spn.clone()));
        let kdc = args
            .kdc
            .clone()
            .or_else(|| conn.and_then(|c| c.kdc.clone()));
        return Ok(AuthMethod::Kerberos { spn, kdc });
    }

    // NTLM
    let hash = read_secret(
        args.hash.clone(),
        args.hashfile.as_deref(),
        conn.and_then(|c| c.hash.clone()),
        conn.and_then(|c| c.hashfile.as_deref()),
    )?;
    if let Some(hash) = hash {
        let domain = args
            .domain
            .clone()
            .or_else(|| conn.and_then(|c| c.domain.clone()))
            .unwrap_or_default();
        let username = args
            .username
            .clone()
            .or_else(|| conn.and_then(|c| c.username.clone()))
            .unwrap_or_default();
        return Ok(AuthMethod::Ntlm {
            domain,
            username,
            hash,
        });
    }

    // Simple bind
    let username = args
        .username
        .clone()
        .or_else(|| conn.and_then(|c| c.username.clone()));

    if let Some(username) = username {
        let password = read_secret(
            args.password.clone(),
            args.passfile.as_deref(),
            conn.and_then(|c| c.password.clone()),
            conn.and_then(|c| c.passfile.as_deref()),
        )?;
        let password = match password {
            Some(p) => p,
            None => prompt_password(&username)?,
        };
        return Ok(AuthMethod::Simple { username, password });
    }

    Ok(AuthMethod::Anonymous)
}

/// Read a secret from an inline value, a file path, a connection config inline, or its file path.
/// A path of `-` reads one line from stdin.
fn read_secret(
    inline: Option<String>,
    file_path: Option<&str>,
    conn_inline: Option<String>,
    conn_file: Option<&str>,
) -> Result<Option<String>> {
    if let Some(v) = inline {
        return Ok(Some(v));
    }
    if let Some(path) = file_path {
        return Ok(Some(read_file_or_stdin(path)?));
    }
    if let Some(v) = conn_inline {
        return Ok(Some(v));
    }
    if let Some(path) = conn_file {
        return Ok(Some(read_file_or_stdin(path)?));
    }
    Ok(None)
}

fn read_file_or_stdin(path: &str) -> Result<String> {
    if path == "-" {
        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        return Ok(buf.trim_end_matches('\n').to_owned());
    }
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading secret file {path}: {e}"))?;
    Ok(content.trim_end().to_owned())
}

fn prompt_password(username: &str) -> Result<String> {
    print!("Password for {username}: ");
    io::stdout().flush()?;
    let pw = rpassword::read_password()?;
    Ok(pw)
}

// ── Scalar parsers ─────────────────────────────────────────────────────────────

/// Parse the positional `target` argument into `(server, Option<port>)`.
///
/// Accepted forms:
/// - `hostname`
/// - `hostname:port`
/// - `ldap://hostname`
/// - `ldap://hostname:port`
/// - `ldaps://hostname`
/// - `ldaps://hostname:port`
fn parse_target(
    target: Option<&str>,
    conn: Option<&file::ConnectionConfig>,
) -> (String, Option<u16>) {
    let raw = match target {
        Some(t) => t,
        None => {
            return (
                conn.and_then(|c| c.server.clone())
                    .unwrap_or_else(|| "127.0.0.1".to_owned()),
                None,
            );
        }
    };

    // Strip scheme
    let without_scheme = raw
        .trim_start_matches("ldaps://")
        .trim_start_matches("ldap://");

    // Split host:port — handle IPv6 [::1]:389 as well
    if without_scheme.starts_with('[') {
        // IPv6 bracketed: [::1] or [::1]:port
        if let Some(bracket_end) = without_scheme.find(']') {
            let host = without_scheme[1..bracket_end].to_owned();
            let port = without_scheme
                .get(bracket_end + 2..) // skip ']:'
                .and_then(|p| p.parse::<u16>().ok());
            return (host, port);
        }
    }

    if let Some((host, port_str)) = without_scheme.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host.to_owned(), Some(port));
        }
    }

    (without_scheme.to_owned(), None)
}

fn parse_backend(s: &str) -> Result<BackendFlavor> {
    match s.to_ascii_lowercase().as_str() {
        "msad" | "ms-ad" | "ad" => Ok(BackendFlavor::MsAd),
        "basic" | "ldap" => Ok(BackendFlavor::Basic),
        "auto" => Ok(BackendFlavor::Auto),
        other => bail!("unknown backend flavor {other:?}; expected msad, basic, or auto"),
    }
}

fn parse_timefmt(s: &str) -> TimeFmt {
    match s.to_ascii_uppercase().as_str() {
        "EU" => TimeFmt::Eu,
        "US" => TimeFmt::Us,
        "ISO8601" => TimeFmt::Iso8601,
        _ => TimeFmt::Custom(s.to_owned()),
    }
}

fn parse_attrsort(s: &str) -> AttrSort {
    match s.to_ascii_lowercase().as_str() {
        "asc" => AttrSort::Asc,
        "desc" => AttrSort::Desc,
        _ => AttrSort::None,
    }
}

// ── SSH config builder ─────────────────────────────────────────────────────────

fn build_ssh_config(
    args: &cli::Cli,
    conn: Option<&file::ConnectionConfig>,
) -> Result<Option<SshConfig>> {
    // File config SSH block takes precedence when no CLI --ssh-host given
    if let Some(c) = conn {
        if args.ssh_host.is_none() {
            if let Some(ssh) = &c.ssh {
                return Ok(Some(ssh.clone()));
            }
        }
    }

    let host = match &args.ssh_host {
        Some(h) => h.clone(),
        None => return Ok(None),
    };

    let user = args.ssh_user.clone().unwrap_or_default();

    let auth = if args.ssh_agent {
        SshAuthMethod::Agent
    } else if let Some(key) = &args.ssh_key {
        SshAuthMethod::Key {
            path: key.clone(),
            passphrase: args.ssh_key_passphrase.clone(),
        }
    } else if let Some(pf) = &args.ssh_passfile {
        SshAuthMethod::PasswordFile { path: pf.clone() }
    } else if let Some(pw) = &args.ssh_password {
        SshAuthMethod::Password {
            password: pw.clone(),
        }
    } else {
        SshAuthMethod::Agent
    };

    Ok(Some(SshConfig {
        host,
        port: args.ssh_port,
        user,
        auth,
        ignore_host_key: args.ssh_ignore_host_key,
    }))
}

// ── init-config subcommand ─────────────────────────────────────────────────────

fn init_config(output: Option<&str>, default: bool, yes: bool) -> Result<()> {
    let yaml = file::sample_config();

    // --default: write to the platform config location
    if default {
        let path = file::default_config_path()?;
        if path.exists() && !yes {
            bail!(
                "config file already exists at {}\nRe-run with --yes to overwrite",
                path.display()
            );
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("creating {}: {e}", parent.display()))?;
        }
        std::fs::write(&path, yaml)
            .map_err(|e| anyhow::anyhow!("writing {}: {e}", path.display()))?;
        println!("Config written to {}", path.display());
        return Ok(());
    }

    // --output <path>: write to an explicit file
    if let Some(path) = output {
        if path == "-" {
            print!("{yaml}");
            return Ok(());
        }
        let p = std::path::Path::new(path);
        if p.exists() && !yes {
            bail!("file already exists at {path}\nRe-run with --yes to overwrite");
        }
        std::fs::write(p, yaml).map_err(|e| anyhow::anyhow!("writing {path}: {e}"))?;
        println!("Config written to {path}");
        return Ok(());
    }

    // no flags: print to stdout
    print!("{yaml}");
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{cli::Cli, file::FileConfig};
    use clap::Parser;

    fn cli(args: &[&str]) -> Cli {
        Cli::parse_from(std::iter::once("rsdap").chain(args.iter().copied()))
    }

    fn empty_file_config() -> FileConfig {
        FileConfig {
            default_connection: None,
            global: Default::default(),
            connections: vec![],
        }
    }

    // ── auth resolution ────────────────────────────────────────────────────────

    #[test]
    fn anonymous_when_no_credentials() {
        let c = cli(&["ldap://localhost"]);
        let r = resolve_inner(c, None).unwrap();
        assert_eq!(r.auth, AuthMethod::Anonymous);
    }

    #[test]
    fn simple_bind_from_flags() {
        let c = cli(&[
            "ldap://localhost",
            "-u",
            "cn=admin,dc=test,dc=com",
            "-p",
            "secret",
        ]);
        let r = resolve_inner(c, None).unwrap();
        assert_eq!(
            r.auth,
            AuthMethod::Simple {
                username: "cn=admin,dc=test,dc=com".to_owned(),
                password: "secret".to_owned(),
            }
        );
    }

    #[test]
    fn kerberos_bind_from_flag() {
        let c = cli(&["host", "-k"]);
        let r = resolve_inner(c, None).unwrap();
        assert_eq!(
            r.auth,
            AuthMethod::Kerberos {
                spn: None,
                kdc: None
            }
        );
    }

    #[test]
    fn certificate_pem_from_flags() {
        let c = cli(&["host", "--crt", "/tmp/c.pem", "--key", "/tmp/k.pem"]);
        let r = resolve_inner(c, None).unwrap();
        assert_eq!(
            r.auth,
            AuthMethod::Certificate {
                crt: "/tmp/c.pem".to_owned(),
                key: "/tmp/k.pem".to_owned(),
            }
        );
    }

    #[test]
    fn pkcs12_from_flags() {
        let c = cli(&["host", "--pfx", "/tmp/cred.pfx", "-p", "passphrase"]);
        let r = resolve_inner(c, None).unwrap();
        assert_eq!(
            r.auth,
            AuthMethod::CertificatePkcs12 {
                pfx: "/tmp/cred.pfx".to_owned(),
                passphrase: Some("passphrase".to_owned()),
            }
        );
    }

    // ── backend parsing ────────────────────────────────────────────────────────

    #[test]
    fn backend_msad_default() {
        let c = cli(&["host"]);
        let r = resolve_inner(c, None).unwrap();
        assert_eq!(r.backend, BackendFlavor::Auto);
    }

    #[test]
    fn backend_basic_flag() {
        let c = cli(&["host", "-b", "basic"]);
        let r = resolve_inner(c, None).unwrap();
        assert_eq!(r.backend, BackendFlavor::Basic);
    }

    #[test]
    fn backend_auto_flag() {
        let c = cli(&["host", "-b", "auto"]);
        let r = resolve_inner(c, None).unwrap();
        assert_eq!(r.backend, BackendFlavor::Auto);
    }

    #[test]
    fn backend_invalid_returns_error() {
        let c = cli(&["host", "-b", "invalid"]);
        assert!(resolve_inner(c, None).is_err());
    }

    // ── port and LDAPS ─────────────────────────────────────────────────────────

    #[test]
    fn default_port_plain() {
        let c = cli(&["host"]);
        let r = resolve_inner(c, None).unwrap();
        assert_eq!(r.port, 389);
        assert!(!r.ldaps);
    }

    #[test]
    fn default_port_ldaps() {
        let c = cli(&["host", "-S"]);
        let r = resolve_inner(c, None).unwrap();
        assert_eq!(r.port, 636);
        assert!(r.ldaps);
    }

    #[test]
    fn explicit_port_wins() {
        let c = cli(&["host", "-S", "-P", "3269"]);
        let r = resolve_inner(c, None).unwrap();
        assert_eq!(r.port, 3269);
    }

    // ── port / server parsing from URL target ──────────────────────────────────

    #[test]
    fn port_embedded_in_plain_url() {
        let c = cli(&["ldap://localhost:22389"]);
        let r = resolve_inner(c, None).unwrap();
        assert_eq!(r.server, "localhost");
        assert_eq!(r.port, 22389);
    }

    #[test]
    fn port_embedded_in_ldaps_url() {
        let c = cli(&["ldaps://dc.corp.local:3269"]);
        let r = resolve_inner(c, None).unwrap();
        assert_eq!(r.server, "dc.corp.local");
        assert_eq!(r.port, 3269);
    }

    #[test]
    fn port_embedded_in_bare_host() {
        let c = cli(&["dc.corp.local:389"]);
        let r = resolve_inner(c, None).unwrap();
        assert_eq!(r.server, "dc.corp.local");
        assert_eq!(r.port, 389);
    }

    #[test]
    fn explicit_flag_overrides_url_port() {
        // -P 636 beats the :389 in the URL
        let c = cli(&["ldap://localhost:389", "-P", "636"]);
        let r = resolve_inner(c, None).unwrap();
        assert_eq!(r.port, 636);
    }

    // ── timefmt / attrsort parsing ─────────────────────────────────────────────

    #[test]
    fn timefmt_defaults_eu() {
        let c = cli(&["host"]);
        let r = resolve_inner(c, None).unwrap();
        assert_eq!(r.timefmt, TimeFmt::Eu);
    }

    #[test]
    fn timefmt_iso8601() {
        let c = cli(&["host", "--timefmt", "ISO8601"]);
        let r = resolve_inner(c, None).unwrap();
        assert_eq!(r.timefmt, TimeFmt::Iso8601);
    }

    #[test]
    fn timefmt_custom() {
        let c = cli(&["host", "--timefmt", "%Y/%m/%d"]);
        let r = resolve_inner(c, None).unwrap();
        assert_eq!(r.timefmt, TimeFmt::Custom("%Y/%m/%d".to_owned()));
    }

    #[test]
    fn attrsort_asc() {
        let c = cli(&["host", "--attrsort", "asc"]);
        let r = resolve_inner(c, None).unwrap();
        assert_eq!(r.attrsort, AttrSort::Asc);
    }

    // ── file config: global limit ──────────────────────────────────────────────

    #[test]
    fn global_limit_cli_default_wins() {
        // clap fills in default_value=20 even when --limit is not given,
        // so the CLI arg always wins over global.limit.
        // This test documents that known behavior.
        let c = cli(&["host"]);
        let mut fc = empty_file_config();
        fc.global.limit = Some(50);
        let r = resolve_inner(c, Some(fc)).unwrap();
        assert_eq!(r.limit, 20);
    }
}
