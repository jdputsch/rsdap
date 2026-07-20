//! clap-based CLI argument definitions.

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "rsdap",
    about = "TUI LDAP client with Active Directory support"
)]
#[command(version)]
pub struct Cli {
    /// Server address or named connection from config
    pub target: Option<String>,

    #[command(subcommand)]
    pub command: Option<Commands>,

    // ── Connection ────────────────────────────────────────────────────────────
    /// LDAP server port (default: 389 or 636 for LDAPS)
    #[arg(short = 'P', long)]
    pub port: Option<u16>,

    /// LDAP username
    #[arg(short = 'u', long)]
    pub username: Option<String>,

    /// LDAP password
    #[arg(short = 'p', long, env = "RSDAP_PASSWD")]
    pub password: Option<String>,

    /// Path to password file (or `-` for stdin)
    #[arg(long)]
    pub passfile: Option<String>,

    /// NTLM/Kerberos domain
    #[arg(short = 'd', long)]
    pub domain: Option<String>,

    /// NTLM hash
    #[arg(short = 'H', long)]
    pub hash: Option<String>,

    /// Path to NTLM hash file (or `-` for stdin)
    #[arg(long)]
    pub hashfile: Option<String>,

    /// Use Kerberos (KRB5CCNAME env)
    #[arg(short = 'k', long)]
    pub kerberos: bool,

    /// Target SPN for Kerberos
    #[arg(short = 't', long)]
    pub spn: Option<String>,

    /// KDC address (if different from server)
    #[arg(long)]
    pub kdc: Option<String>,

    /// Client certificate path (PEM)
    #[arg(long)]
    pub crt: Option<String>,

    /// Client private key path (PEM)
    #[arg(long)]
    pub key: Option<String>,

    /// PKCS#12 file path
    #[arg(long)]
    pub pfx: Option<String>,

    /// Use LDAPS
    #[arg(short = 'S', long)]
    pub ldaps: bool,

    /// Skip TLS verification
    #[arg(short = 'I', long)]
    pub insecure: bool,

    /// SOCKS5 proxy address (e.g. socks5://host:port)
    #[arg(short = 'x', long)]
    pub socks: Option<String>,

    /// Connection timeout in seconds
    #[arg(short = 'T', long, default_value = "10")]
    pub timeout: u64,

    /// Backend flavor: msad, basic, auto
    #[arg(short = 'b', long, default_value = "msad")]
    pub backend: String,

    // ── TUI behavior ─────────────────────────────────────────────────────────
    /// Initial root DN (auto-detected from RootDSE if omitted)
    #[arg(short = 'r', long)]
    pub root_dn: Option<String>,

    /// Initial search filter
    #[arg(short = 'f', long, default_value = "(objectClass=*)")]
    pub filter: String,

    /// Prefix objects with emojis
    #[arg(short = 'E', long, default_value = "true")]
    pub emojis: bool,

    /// Colorize objects
    #[arg(short = 'C', long, default_value = "true")]
    pub colors: bool,

    /// Format attributes human-readably
    #[arg(short = 'F', long, default_value = "true")]
    pub format: bool,

    /// Expand multi-value attributes
    #[arg(short = 'A', long, default_value = "true")]
    pub expand: bool,

    /// Max attribute values shown when expanded
    #[arg(short = 'L', long, default_value = "20")]
    pub limit: usize,

    /// Cache entries in memory
    #[arg(short = 'M', long, default_value = "true")]
    pub cache: bool,

    /// Include deleted objects (MS AD)
    #[arg(short = 'D', long)]
    pub deleted: bool,

    /// Load schema GUIDs at startup
    #[arg(short = 's', long)]
    pub schema: bool,

    /// LDAP paging size
    #[arg(short = 'G', long, default_value = "800")]
    pub paging: u32,

    /// Timestamp format: EU, US, ISO8601, or custom strftime pattern
    #[arg(long, default_value = "EU")]
    pub timefmt: String,

    /// Hours offset for timestamps
    #[arg(long, default_value = "0")]
    pub offset: i32,

    /// Attribute sort: none, asc, desc
    #[arg(long, default_value = "none")]
    pub attrsort: String,

    /// Export directory
    #[arg(long, default_value = "data")]
    pub exportdir: String,

    /// Debug log file path
    #[arg(long)]
    pub debug_log: Option<String>,

    // ── SSH tunnel ────────────────────────────────────────────────────────────
    /// SSH server hostname (enables tunnel when set)
    #[arg(long)]
    pub ssh_host: Option<String>,

    /// SSH port
    #[arg(long, default_value = "22")]
    pub ssh_port: u16,

    /// SSH username
    #[arg(long)]
    pub ssh_user: Option<String>,

    /// SSH password
    #[arg(long, env = "RSDAP_SSH_PASSWORD")]
    pub ssh_password: Option<String>,

    /// SSH password file (or `-` for stdin)
    #[arg(long)]
    pub ssh_passfile: Option<String>,

    /// Use SSH agent
    #[arg(long)]
    pub ssh_agent: bool,

    /// SSH private key path
    #[arg(long)]
    pub ssh_key: Option<String>,

    /// Passphrase for SSH key
    #[arg(long)]
    pub ssh_key_passphrase: Option<String>,

    /// Skip SSH host key verification
    #[arg(long)]
    pub ssh_ignore_host_key: bool,

    // ── Config/connection ─────────────────────────────────────────────────────
    /// Config file path (overrides discovery)
    #[arg(short = 'c', long)]
    pub config: Option<String>,

    /// Named connection from config file
    #[arg(long)]
    pub connection: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Print a sample config to stdout (or write to --output)
    InitConfig {
        /// Output file path
        #[arg(long)]
        output: Option<String>,
    },
    /// Print version information
    Version,
}

pub fn parse() -> Cli {
    Cli::parse()
}
