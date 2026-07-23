//! Connection configuration modal form.
//!
//! `l` opens this form; Tab/Shift+Tab cycle fields; Enter submits; Esc cancels.
//! Credential fields rebuild dynamically when the Auth Type dropdown changes.

use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;

use crate::config::{AuthMethod, ResolvedConfig, SshAuthMethod, SshConfig};
use crate::tui::widgets::form::{FormField, ModalForm};

const AUTH_TYPE_LABELS: &[&str] = &[
    "Anonymous",
    "Simple (password)",
    "NTLM",
    "Kerberos",
    "Certificate (PEM)",
    "Certificate (PKCS#12)",
];

/// Index of the Auth Type Select field in the fixed-field list.
const AUTH_TYPE_FIELD_IDX: usize = 6;

/// Number of fixed connection fields before the credential section.
const CONN_FIELD_COUNT: usize = 7; // Server, Port, LDAPS, Insecure, SOCKS, Timeout, Auth Type

pub struct ConnectionForm {
    pub form: ModalForm,
    pub auth_type_idx: usize,
}

impl ConnectionForm {
    pub fn new(cfg: &ResolvedConfig) -> Self {
        let auth_type_idx = auth_method_to_idx(&cfg.auth);
        let fields = build_fields(cfg, auth_type_idx);
        let form = ModalForm::new("Connection Configuration", fields);
        Self {
            form,
            auth_type_idx,
        }
    }

    pub fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        self.form.render(frame, area);
        self.form.render_dropdown(frame, area);
    }

    pub fn is_submitted(&self) -> bool {
        self.form.submitted
    }

    pub fn is_cancelled(&self) -> bool {
        self.form.cancelled
    }

    /// Handle a key event, delegating to the inner form and rebuilding credential
    /// fields when the Auth Type selection changes.
    pub fn handle_key(&mut self, code: KeyCode, mods: KeyModifiers) {
        let was_on_auth = self.form.focused == AUTH_TYPE_FIELD_IDX;

        match (code, mods) {
            (KeyCode::Tab, KeyModifiers::NONE) => self.form.next_field(),
            (KeyCode::BackTab, KeyModifiers::SHIFT) | (KeyCode::BackTab, KeyModifiers::NONE) => {
                self.form.prev_field();
            }
            (KeyCode::Up, KeyModifiers::NONE) => {
                if was_on_auth {
                    self.form.prev_option();
                } else {
                    self.form.prev_field();
                }
            }
            (KeyCode::Down, KeyModifiers::NONE) => {
                if was_on_auth {
                    self.form.next_option();
                } else {
                    self.form.next_field();
                }
            }
            (KeyCode::Enter, KeyModifiers::NONE) => {
                self.form.submitted = true;
            }
            (KeyCode::Esc, KeyModifiers::NONE) => {
                self.form.cancelled = true;
            }
            (KeyCode::Backspace, KeyModifiers::NONE) => self.form.handle_backspace(),
            (KeyCode::Char(ch), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                self.form.handle_char(ch);
            }
            _ => {}
        }

        // If we were on the auth type field and the value changed, rebuild creds.
        if was_on_auth || self.form.focused == AUTH_TYPE_FIELD_IDX {
            let new_idx = auth_label_to_idx(&self.form.fields[AUTH_TYPE_FIELD_IDX].value);
            if new_idx != self.auth_type_idx {
                self.auth_type_idx = new_idx;
                self.rebuild_creds();
            }
        }
    }

    /// Rebuild credential fields when Auth Type changes, preserving all other values.
    pub fn rebuild_creds(&mut self) {
        // Save connection field values (indices 0..CONN_FIELD_COUNT).
        let conn_values: Vec<String> = self
            .form
            .fields
            .iter()
            .take(CONN_FIELD_COUNT)
            .map(|f| f.value.clone())
            .collect();

        // Save SSH field values (everything after the credential section).
        let cred_count = cred_field_count(self.auth_type_idx);
        let ssh_start = CONN_FIELD_COUNT + cred_count;
        let ssh_values: Vec<String> = if ssh_start <= self.form.fields.len() {
            self.form.fields[ssh_start..]
                .iter()
                .map(|f| f.value.clone())
                .collect()
        } else {
            Vec::new()
        };

        // Build a fresh cfg snapshot from current field values so build_fields works.
        // We only need auth_type_idx correct; other fields don't matter for cred building.
        let dummy_cfg = dummy_cfg_for_auth(self.auth_type_idx);
        let mut new_fields = build_fields(&dummy_cfg, self.auth_type_idx);

        // Restore connection field values.
        for (i, val) in conn_values.into_iter().enumerate() {
            if let Some(f) = new_fields.get_mut(i) {
                f.value = val;
            }
        }

        // Restore SSH field values.
        let new_ssh_start = CONN_FIELD_COUNT + cred_field_count(self.auth_type_idx);
        for (i, val) in ssh_values.into_iter().enumerate() {
            if let Some(f) = new_fields.get_mut(new_ssh_start + i) {
                f.value = val;
            }
        }

        let old_focused = self.form.focused;
        self.form.fields = new_fields;
        self.form.focused = old_focused.min(self.form.fields.len().saturating_sub(1));
    }

    /// Extract a new `ResolvedConfig` from the current field values, falling back to
    /// `base` for fields that cannot be parsed.
    pub fn to_config(&self, base: &ResolvedConfig) -> ResolvedConfig {
        let f = &self.form.fields;
        let get = |i: usize| f.get(i).map(|ff| ff.value.as_str()).unwrap_or("");

        let server = get(0).to_owned();
        let port = get(1).parse::<u16>().unwrap_or(base.port);
        let ldaps = get(2) == "true";
        let insecure = get(3) == "true";
        let socks = {
            let v = get(4);
            if v.is_empty() {
                None
            } else {
                Some(v.to_owned())
            }
        };
        let timeout = get(5).parse::<u64>().unwrap_or(base.timeout);

        let auth = fields_to_auth(self.auth_type_idx, f, CONN_FIELD_COUNT);
        let ssh = fields_to_ssh(f, CONN_FIELD_COUNT + cred_field_count(self.auth_type_idx));

        ResolvedConfig {
            server,
            port,
            ldaps,
            insecure,
            socks,
            timeout,
            auth,
            ssh,
            // Preserve all other fields from base.
            backend: base.backend.clone(),
            root_dn: base.root_dn.clone(),
            filter: base.filter.clone(),
            emojis: base.emojis,
            colors: base.colors,
            format: base.format,
            expand: base.expand,
            limit: base.limit,
            cache: base.cache,
            deleted: base.deleted,
            schema: base.schema,
            paging: base.paging,
            timefmt: base.timefmt.clone(),
            offset: base.offset,
            attrsort: base.attrsort.clone(),
            exportdir: base.exportdir.clone(),
            debug_log: base.debug_log.clone(),
        }
    }
}

// ── Field builders ───────────────────────────────────────────────────────────

fn build_fields(cfg: &ResolvedConfig, auth_idx: usize) -> Vec<FormField> {
    let mut fields = vec![
        FormField::text("Server", cfg.server.as_str()),
        FormField::text("Port", cfg.port.to_string()),
        FormField::select(
            "LDAPS",
            vec!["false".into(), "true".into()],
            bool_str(cfg.ldaps),
        ),
        FormField::select(
            "Insecure",
            vec!["false".into(), "true".into()],
            bool_str(cfg.insecure),
        ),
        FormField::text("SOCKS Proxy", cfg.socks.as_deref().unwrap_or("")),
        FormField::text("Timeout (s)", cfg.timeout.to_string()),
        FormField::select(
            "Auth Type",
            AUTH_TYPE_LABELS.iter().map(|s| s.to_string()).collect(),
            AUTH_TYPE_LABELS[auth_idx],
        ),
    ];

    // Dynamic credential fields.
    fields.extend(cred_fields_for_auth(auth_idx, &cfg.auth));

    // SSH tunnel fields.
    let ssh = cfg.ssh.as_ref();
    fields.push(FormField::text(
        "SSH Host",
        ssh.map_or("", |s| s.host.as_str()),
    ));
    fields.push(FormField::text(
        "SSH Port",
        ssh.map_or_else(|| "22".into(), |s| s.port.to_string()),
    ));
    fields.push(FormField::text(
        "SSH User",
        ssh.map_or("", |s| s.user.as_str()),
    ));
    match ssh.map(|s| &s.auth) {
        Some(SshAuthMethod::Password { password }) => {
            let mut f = FormField::password("SSH Password");
            f.value = password.clone();
            fields.push(f);
        }
        Some(SshAuthMethod::Key { path, .. }) => {
            fields.push(FormField::text("SSH Key Path", path.as_str()));
        }
        _ => {
            // Agent or PasswordFile: show a read-only hint.
            fields.push(FormField::text("SSH Password", ""));
        }
    }

    fields
}

fn cred_fields_for_auth(idx: usize, auth: &AuthMethod) -> Vec<FormField> {
    match idx {
        0 => vec![], // Anonymous
        1 => {
            // Simple
            let (u, p) = match auth {
                AuthMethod::Simple { username, password } => (username.as_str(), password.as_str()),
                _ => ("", ""),
            };
            let mut pw = FormField::password("Password");
            pw.value = p.to_owned();
            vec![FormField::text("Username", u), pw]
        }
        2 => {
            // NTLM
            let (d, u, h) = match auth {
                AuthMethod::Ntlm {
                    domain,
                    username,
                    hash,
                } => (domain.as_str(), username.as_str(), hash.as_str()),
                _ => ("", "", ""),
            };
            let mut hash_f = FormField::password("NT Hash");
            hash_f.value = h.to_owned();
            vec![
                FormField::text("Domain", d),
                FormField::text("Username", u),
                hash_f,
            ]
        }
        3 => {
            // Kerberos
            let (spn, kdc) = match auth {
                AuthMethod::Kerberos { spn, kdc } => {
                    (spn.as_deref().unwrap_or(""), kdc.as_deref().unwrap_or(""))
                }
                _ => ("", ""),
            };
            vec![FormField::text("SPN", spn), FormField::text("KDC", kdc)]
        }
        4 => {
            // Certificate PEM
            let (crt, key) = match auth {
                AuthMethod::Certificate { crt, key } => (crt.as_str(), key.as_str()),
                _ => ("", ""),
            };
            vec![
                FormField::text("Cert File", crt),
                FormField::text("Key File", key),
            ]
        }
        5 => {
            // Certificate PKCS#12
            let (pfx, pass) = match auth {
                AuthMethod::CertificatePkcs12 { pfx, passphrase } => {
                    (pfx.as_str(), passphrase.as_deref().unwrap_or(""))
                }
                _ => ("", ""),
            };
            let mut pass_f = FormField::password("Passphrase");
            pass_f.value = pass.to_owned();
            vec![FormField::text("PFX File", pfx), pass_f]
        }
        _ => vec![],
    }
}

fn cred_field_count(auth_idx: usize) -> usize {
    match auth_idx {
        0 => 0,
        1 => 2, // username + password
        2 => 3, // domain + username + hash
        3 => 2, // spn + kdc
        4 => 2, // crt + key
        5 => 2, // pfx + passphrase
        _ => 0,
    }
}

fn fields_to_auth(idx: usize, fields: &[FormField], cred_start: usize) -> AuthMethod {
    let get = |offset: usize| {
        fields
            .get(cred_start + offset)
            .map(|f| f.value.as_str())
            .unwrap_or("")
            .to_owned()
    };
    match idx {
        1 => AuthMethod::Simple {
            username: get(0),
            password: get(1),
        },
        2 => AuthMethod::Ntlm {
            domain: get(0),
            username: get(1),
            hash: get(2),
        },
        3 => AuthMethod::Kerberos {
            spn: non_empty(get(0)),
            kdc: non_empty(get(1)),
        },
        4 => AuthMethod::Certificate {
            crt: get(0),
            key: get(1),
        },
        5 => AuthMethod::CertificatePkcs12 {
            pfx: get(0),
            passphrase: non_empty(get(1)),
        },
        _ => AuthMethod::Anonymous,
    }
}

fn fields_to_ssh(fields: &[FormField], ssh_start: usize) -> Option<SshConfig> {
    let get = |offset: usize| {
        fields
            .get(ssh_start + offset)
            .map(|f| f.value.as_str())
            .unwrap_or("")
            .to_owned()
    };
    let host = get(0);
    if host.is_empty() {
        return None;
    }
    let port = get(1).parse::<u16>().unwrap_or(22);
    let user = get(2);
    let password = get(3);
    Some(SshConfig {
        host,
        port,
        user,
        auth: SshAuthMethod::Password { password },
        ignore_host_key: false,
    })
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn auth_method_to_idx(auth: &AuthMethod) -> usize {
    match auth {
        AuthMethod::Anonymous => 0,
        AuthMethod::Simple { .. } => 1,
        AuthMethod::Ntlm { .. } => 2,
        AuthMethod::Kerberos { .. } => 3,
        AuthMethod::Certificate { .. } => 4,
        AuthMethod::CertificatePkcs12 { .. } => 5,
    }
}

fn auth_label_to_idx(label: &str) -> usize {
    AUTH_TYPE_LABELS
        .iter()
        .position(|&l| l == label)
        .unwrap_or(0)
}

fn bool_str(b: bool) -> &'static str {
    if b { "true" } else { "false" }
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

/// Build a minimal `ResolvedConfig` that only needs correct `auth` for `build_fields`.
fn dummy_cfg_for_auth(auth_idx: usize) -> ResolvedConfig {
    let auth = match auth_idx {
        1 => AuthMethod::Simple {
            username: String::new(),
            password: String::new(),
        },
        2 => AuthMethod::Ntlm {
            domain: String::new(),
            username: String::new(),
            hash: String::new(),
        },
        3 => AuthMethod::Kerberos {
            spn: None,
            kdc: None,
        },
        4 => AuthMethod::Certificate {
            crt: String::new(),
            key: String::new(),
        },
        5 => AuthMethod::CertificatePkcs12 {
            pfx: String::new(),
            passphrase: None,
        },
        _ => AuthMethod::Anonymous,
    };
    ResolvedConfig {
        server: String::new(),
        port: 389,
        ldaps: false,
        insecure: false,
        socks: None,
        timeout: 5,
        backend: crate::ldap::BackendFlavor::Auto,
        auth,
        root_dn: None,
        filter: String::new(),
        emojis: false,
        colors: false,
        format: false,
        expand: false,
        limit: 0,
        cache: false,
        deleted: false,
        schema: false,
        paging: 500,
        timefmt: crate::config::TimeFmt::Eu,
        offset: 0,
        attrsort: crate::config::AttrSort::None,
        exportdir: String::new(),
        debug_log: None,
        ssh: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_cfg() -> ResolvedConfig {
        ResolvedConfig {
            server: "myhost".into(),
            port: 636,
            ldaps: true,
            ..Default::default()
        }
    }

    #[test]
    fn new_populates_server_and_port() {
        let cfg = base_cfg();
        let form = ConnectionForm::new(&cfg);
        assert_eq!(form.form.fields[0].value, "myhost");
        assert_eq!(form.form.fields[1].value, "636");
        assert_eq!(form.form.fields[2].value, "true");
    }

    #[test]
    fn to_config_round_trips_basic_fields() {
        let cfg = base_cfg();
        let form = ConnectionForm::new(&cfg);
        let out = form.to_config(&cfg);
        assert_eq!(out.server, "myhost");
        assert_eq!(out.port, 636);
        assert!(out.ldaps);
    }

    #[test]
    fn auth_type_change_rebuilds_credential_fields() {
        let cfg = ResolvedConfig::default(); // Anonymous
        let mut form = ConnectionForm::new(&cfg);
        let anon_count = form.form.fields.len();
        form.auth_type_idx = 1; // Simple (password)
        form.rebuild_creds();
        assert_eq!(form.form.fields.len(), anon_count + 2);
    }

    #[test]
    fn ntlm_has_three_cred_fields() {
        let cfg = ResolvedConfig::default();
        let mut form = ConnectionForm::new(&cfg);
        let base_count = form.form.fields.len();
        form.auth_type_idx = 2; // NTLM
        form.rebuild_creds();
        assert_eq!(form.form.fields.len(), base_count + 3);
    }

    #[test]
    fn to_config_builds_simple_auth() {
        let cfg = ResolvedConfig {
            auth: AuthMethod::Simple {
                username: "admin".into(),
                password: "secret".into(),
            },
            ..Default::default()
        };
        let form = ConnectionForm::new(&cfg);
        let out = form.to_config(&cfg);
        assert!(matches!(out.auth, AuthMethod::Simple { .. }));
        if let AuthMethod::Simple { username, password } = out.auth {
            assert_eq!(username, "admin");
            assert_eq!(password, "secret");
        }
    }

    #[test]
    fn cred_field_count_matches_variants() {
        assert_eq!(cred_field_count(0), 0); // Anonymous
        assert_eq!(cred_field_count(1), 2); // Simple
        assert_eq!(cred_field_count(2), 3); // NTLM
        assert_eq!(cred_field_count(3), 2); // Kerberos
        assert_eq!(cred_field_count(4), 2); // Certificate PEM
        assert_eq!(cred_field_count(5), 2); // PKCS#12
    }
}
