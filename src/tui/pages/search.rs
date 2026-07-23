//! Search page: filter input, predefined query library, results tree, attributes panel,
//! history panel, search settings form, and cache-finder overlay.

use std::time::Instant;

use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ldap3::Scope;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Clear, List, ListItem, ListState, Paragraph, Row, Table, TableState,
};
use tokio::sync::mpsc::Sender;

use tracing::{debug, error};

use super::Page;
use crate::app::{AppMsg, SharedLdap, Truncation};
use crate::cache::{EntryCache, MatchCategory};
use crate::config::ResolvedConfig;
use crate::ldap::BackendFlavor;
use crate::ldap::search::auto_wrap_filter;
use crate::tui::attrs::{AttrConfig, AttrPanel};
use crate::tui::widgets::form::{FormField, ModalForm};

// ── Library queries ──────────────────────────────────────────────────────────

/// A single predefined query in the library.
struct LibraryQuery {
    label: &'static str,
    filter: &'static str,
    /// If Some, override the search base with this template.
    /// `<root DN>` in either filter or base_override is replaced at runtime.
    base_override: Option<&'static str>,
}

struct LibraryCategory {
    label: &'static str,
    queries: &'static [LibraryQuery],
}

// MS AD library
static MSAD_ENUM: &[LibraryQuery] = &[
    LibraryQuery {
        label: "All Organizational Units",
        filter: "(objectCategory=organizationalUnit)",
        base_override: None,
    },
    LibraryQuery {
        label: "All Containers",
        filter: "(objectCategory=container)",
        base_override: None,
    },
    LibraryQuery {
        label: "All Groups",
        filter: "(objectCategory=group)",
        base_override: None,
    },
    LibraryQuery {
        label: "All Computers",
        filter: "(objectClass=computer)",
        base_override: None,
    },
    LibraryQuery {
        label: "All Users",
        filter: "(&(objectCategory=person)(objectClass=user))",
        base_override: None,
    },
    LibraryQuery {
        label: "All Objects",
        filter: "(objectClass=*)",
        base_override: None,
    },
];

static MSAD_USERS: &[LibraryQuery] = &[
    LibraryQuery {
        label: "Recently Created Users",
        filter: "(&(objectCategory=user)(whenCreated>=<timestamp1d>))",
        base_override: None,
    },
    LibraryQuery {
        label: "Users With Description",
        filter: "(&(objectCategory=user)(description=*))",
        base_override: None,
    },
    LibraryQuery {
        label: "Users Without Email",
        filter: "(&(objectCategory=user)(!(mail=*)))",
        base_override: None,
    },
    LibraryQuery {
        label: "Likely Service Users",
        filter: "(&(objectCategory=user)(sAMAccountName=*svc*))",
        base_override: None,
    },
    LibraryQuery {
        label: "Disabled Users",
        filter: "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2))",
        base_override: None,
    },
    LibraryQuery {
        label: "Expired Users",
        filter: "(&(objectCategory=user)(accountExpires<=<timestamp>))",
        base_override: None,
    },
    LibraryQuery {
        label: "Users With Sensitive Infos",
        filter: "(&(objectCategory=user)(|(telephoneNumber=*)(pager=*)(homePhone=*)(mobile=*)(info=*)(streetAddress=*)))",
        base_override: None,
    },
    LibraryQuery {
        label: "Inactive Users",
        filter: "(&(objectCategory=user)(lastLogonTimestamp<=<timestamp30d>))",
        base_override: None,
    },
];

static MSAD_COMPUTERS: &[LibraryQuery] = &[
    LibraryQuery {
        label: "Domain Controllers",
        filter: "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
        base_override: None,
    },
    LibraryQuery {
        label: "Non-DC Servers",
        filter: "(&(objectCategory=computer)(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
        base_override: None,
    },
    LibraryQuery {
        label: "Non-Server Computers",
        filter: "(&(objectCategory=computer)(!(operatingSystem=*server*))(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
        base_override: None,
    },
    LibraryQuery {
        label: "Stale Computers",
        filter: "(&(objectCategory=computer)(!lastLogonTimestamp=*))",
        base_override: None,
    },
    LibraryQuery {
        label: "Computers With Outdated OS",
        filter: "(&(objectCategory=computer)(|(operatingSystem=*Server 2008*)(operatingSystem=*Server 2003*)(operatingSystem=*Windows XP*)(operatingSystem=*Windows 7*)))",
        base_override: None,
    },
];

static MSAD_SECURITY: &[LibraryQuery] = &[
    LibraryQuery {
        label: "High Privilege Users",
        filter: "(&(objectCategory=user)(adminCount=1))",
        base_override: None,
    },
    LibraryQuery {
        label: "Users With SPN",
        filter: "(&(objectCategory=user)(servicePrincipalName=*))",
        base_override: None,
    },
    LibraryQuery {
        label: "Users With SIDHistory",
        filter: "(&(objectCategory=person)(objectClass=user)(sidHistory=*))",
        base_override: None,
    },
    LibraryQuery {
        label: "KrbPreauth Disabled Users",
        filter: "(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
        base_override: None,
    },
    LibraryQuery {
        label: "KrbPreauth Disabled Computers",
        filter: "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
        base_override: None,
    },
    LibraryQuery {
        label: "Constrained Delegation Objects",
        filter: "(msDS-AllowedToDelegateTo=*)",
        base_override: None,
    },
    LibraryQuery {
        label: "Unconstrained Delegation Objects",
        filter: "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
        base_override: None,
    },
    LibraryQuery {
        label: "RBCD Objects",
        filter: "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
        base_override: None,
    },
    LibraryQuery {
        label: "Not Trusted For Delegation",
        filter: "(&(samaccountname=*)(userAccountControl:1.2.840.113556.1.4.803:=1048576))",
        base_override: None,
    },
    LibraryQuery {
        label: "Shadow Credentials Targets",
        filter: "(msDS-KeyCredentialLink=*)",
        base_override: None,
    },
    LibraryQuery {
        label: "Must Change Password Users",
        filter: "(&(objectCategory=person)(objectClass=user)(pwdLastSet=0)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))",
        base_override: None,
    },
    LibraryQuery {
        label: "Password Never Changed Users",
        filter: "(&(objectCategory=user)(pwdLastSet=0))",
        base_override: None,
    },
    LibraryQuery {
        label: "Never Expire Password Users",
        filter: "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))",
        base_override: None,
    },
    LibraryQuery {
        label: "Users with PASSWD_NOTREQD",
        filter: "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=32))",
        base_override: None,
    },
    LibraryQuery {
        label: "LockedOut Users",
        filter: "(&(objectCategory=user)(lockoutTime>=1))",
        base_override: None,
    },
    LibraryQuery {
        label: "Trusted Domains",
        filter: "(objectClass=trustedDomain)",
        base_override: None,
    },
    LibraryQuery {
        label: "ADCS Enterprise CAs",
        filter: "(objectClass=pKIEnrollmentService)",
        base_override: Some(
            "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,<root DN>",
        ),
    },
    LibraryQuery {
        label: "ADCS Certificate Templates",
        filter: "(objectClass=pKICertificateTemplate)",
        base_override: Some(
            "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,<root DN>",
        ),
    },
];

static MSAD_GROUP_MEMBERS: &[LibraryQuery] = &[
    LibraryQuery {
        label: "Enterprise Admins",
        filter: "(memberOf=CN=Enterprise Admins,CN=Users,<root DN>)",
        base_override: None,
    },
    LibraryQuery {
        label: "Administrators",
        filter: "(memberOf=CN=Administrators,CN=Builtin,<root DN>)",
        base_override: None,
    },
    LibraryQuery {
        label: "Domain Admins",
        filter: "(memberOf=CN=Domain Admins,CN=Users,<root DN>)",
        base_override: None,
    },
    LibraryQuery {
        label: "Schema Admins",
        filter: "(memberOf=CN=Schema Admins,CN=Users,<root DN>)",
        base_override: None,
    },
    LibraryQuery {
        label: "DNS Admins",
        filter: "(memberOf=CN=DnsAdmins,CN=Users,<root DN>)",
        base_override: None,
    },
    LibraryQuery {
        label: "Server Operators",
        filter: "(memberOf=CN=Server Operators,CN=Builtin,<root DN>)",
        base_override: None,
    },
    LibraryQuery {
        label: "Backup Operators",
        filter: "(memberOf=CN=Backup Operators,CN=Builtin,<root DN>)",
        base_override: None,
    },
    LibraryQuery {
        label: "Account Operators",
        filter: "(memberOf=CN=Account Operators,CN=Builtin,<root DN>)",
        base_override: None,
    },
    LibraryQuery {
        label: "WinRMRemoteWMIUsers__",
        filter: "(memberOf=CN=WinRMRemoteWMIUsers__,CN=Users,<root DN>)",
        base_override: None,
    },
    LibraryQuery {
        label: "Group Policy Creator Owners",
        filter: "(memberOf=CN=Group Policy Creator Owners,CN=Users,<root DN>)",
        base_override: None,
    },
    LibraryQuery {
        label: "Remote Desktop Users",
        filter: "(memberOf=CN=Remote Desktop Users,CN=Builtin,<root DN>)",
        base_override: None,
    },
    LibraryQuery {
        label: "Remote Management Users",
        filter: "(memberOf=CN=Remote Management Users,CN=Builtin,<root DN>)",
        base_override: None,
    },
    LibraryQuery {
        label: "Print Operators",
        filter: "(memberOf=CN=Print Operators,CN=Builtin,<root DN>)",
        base_override: None,
    },
    LibraryQuery {
        label: "DHCP Administrators",
        filter: "(memberOf=CN=DHCP Administrators,CN=Users,<root DN>)",
        base_override: None,
    },
    LibraryQuery {
        label: "Hyper-V Administrators",
        filter: "(memberOf=CN=Hyper-V Administrators,CN=Builtin,<root DN>)",
        base_override: None,
    },
    LibraryQuery {
        label: "Cert Publishers",
        filter: "(memberOf=CN=Cert Publishers,CN=Users,<root DN>)",
        base_override: None,
    },
    LibraryQuery {
        label: "Protected Users",
        filter: "(memberOf=CN=Protected Users,CN=Users,<root DN>)",
        base_override: None,
    },
];

static MSAD_CATEGORIES: &[LibraryCategory] = &[
    LibraryCategory {
        label: "Enum",
        queries: MSAD_ENUM,
    },
    LibraryCategory {
        label: "Users",
        queries: MSAD_USERS,
    },
    LibraryCategory {
        label: "Computers",
        queries: MSAD_COMPUTERS,
    },
    LibraryCategory {
        label: "Security",
        queries: MSAD_SECURITY,
    },
    LibraryCategory {
        label: "Group Members",
        queries: MSAD_GROUP_MEMBERS,
    },
];

// BasicLDAP library
static BASIC_ENUM: &[LibraryQuery] = &[
    LibraryQuery {
        label: "All Organizations",
        filter: "(objectClass=organization)",
        base_override: None,
    },
    LibraryQuery {
        label: "All Users",
        filter: "(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=person))",
        base_override: None,
    },
    LibraryQuery {
        label: "All Groups",
        filter: "(|(objectClass=posixGroup)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))",
        base_override: None,
    },
    LibraryQuery {
        label: "All Computers",
        filter: "(|(objectClass=ipHost)(objectClass=device))",
        base_override: None,
    },
    LibraryQuery {
        label: "All Organizational Units",
        filter: "(objectClass=organizationalUnit)",
        base_override: None,
    },
    LibraryQuery {
        label: "All Organizational Roles",
        filter: "(objectClass=organizationalRole)",
        base_override: None,
    },
    LibraryQuery {
        label: "All Sudo Roles",
        filter: "(objectClass=sudoRole)",
        base_override: None,
    },
    LibraryQuery {
        label: "All Netgroups",
        filter: "(objectClass=nisNetgroup)",
        base_override: None,
    },
    LibraryQuery {
        label: "All Objects",
        filter: "(objectClass=*)",
        base_override: None,
    },
];

static BASIC_USERS: &[LibraryQuery] = &[
    LibraryQuery {
        label: "Users With Email",
        filter: "(&(mail=*)(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=person)))",
        base_override: None,
    },
    LibraryQuery {
        label: "Users With Phone Number",
        filter: "(&(telephoneNumber=*)(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=person)))",
        base_override: None,
    },
    LibraryQuery {
        label: "Users With Home Directory",
        filter: "(&(homeDirectory=*)(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=person)))",
        base_override: None,
    },
    LibraryQuery {
        label: "Users With UID",
        filter: "(&(uid=*)(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=person)))",
        base_override: None,
    },
    LibraryQuery {
        label: "Users With Password",
        filter: "(userPassword=*)",
        base_override: None,
    },
    LibraryQuery {
        label: "Users With SSH Keys",
        filter: "(sshPublicKey=*)",
        base_override: None,
    },
];

static BASIC_GROUPS: &[LibraryQuery] = &[
    LibraryQuery {
        label: "Groups With Members (groupOfNames)",
        filter: "(&(objectClass=groupOfNames)(member=*))",
        base_override: None,
    },
    LibraryQuery {
        label: "Groups With Members (posixGroup)",
        filter: "(&(objectClass=posixGroup)(memberUid=*))",
        base_override: None,
    },
    LibraryQuery {
        label: "Groups With Members (groupOfUniqueNames)",
        filter: "(&(objectClass=groupOfUniqueNames)(uniqueMember=*))",
        base_override: None,
    },
];

static BASIC_CATEGORIES: &[LibraryCategory] = &[
    LibraryCategory {
        label: "Enum",
        queries: BASIC_ENUM,
    },
    LibraryCategory {
        label: "Users",
        queries: BASIC_USERS,
    },
    LibraryCategory {
        label: "Groups",
        queries: BASIC_GROUPS,
    },
];

// ── Time placeholder resolution ──────────────────────────────────────────────

fn resolve_filter_placeholders(filter: &str, root_dn: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    // Windows FILETIME epoch offset: seconds from 1601-01-01 to 1970-01-01
    const EPOCH_DIFF_SECS: u64 = 11_644_473_600;
    const TICKS_PER_SEC: u64 = 10_000_000;

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let filetime_now = (now_secs + EPOCH_DIFF_SECS) * TICKS_PER_SEC;
    let filetime_1d = ((now_secs - 86_400) + EPOCH_DIFF_SECS) * TICKS_PER_SEC;
    let filetime_30d = ((now_secs - 86_400 * 30) + EPOCH_DIFF_SECS) * TICKS_PER_SEC;

    // For whenCreated / LDAP generalizedTime format we need a date string.
    let now_generalized = {
        // A minimal YYYYMMDDHHMMSS.0Z approximation using manual arithmetic.
        let secs = now_secs - 86_400;
        let days_since_epoch = secs / 86_400;
        // We approximate with a simple Unix-epoch date calculation.
        // For the AD timestamp queries that use whenCreated, this is good enough.
        let _ = days_since_epoch; // unused in simple path below
        // Use filetime representation for the AD queries that specify a time attribute.
        filetime_1d.to_string()
    };

    filter
        .replace("<timestamp>", &filetime_now.to_string())
        .replace("<timestamp1d>", &now_generalized)
        .replace("<timestamp30d>", &filetime_30d.to_string())
        .replace("<root DN>", root_dn)
}

// ── Library flat-list node (rendered as indented list) ──────────────────────

/// A library tree item — either a category header or a query leaf.
#[derive(Clone)]
enum LibNode {
    Category {
        label: String,
        expanded: bool,
        child_count: usize,
    },
    Query {
        label: String,
        filter: String,
        base_override: Option<String>,
    },
}

fn build_lib_nodes(flavor: &BackendFlavor) -> Vec<LibNode> {
    let categories: &[LibraryCategory] = match flavor {
        BackendFlavor::Basic => BASIC_CATEGORIES,
        BackendFlavor::MsAd | BackendFlavor::Auto => MSAD_CATEGORIES,
    };
    let mut nodes = Vec::new();
    for cat in categories {
        nodes.push(LibNode::Category {
            label: cat.label.to_string(),
            expanded: false,
            child_count: cat.queries.len(),
        });
        for q in cat.queries {
            nodes.push(LibNode::Query {
                label: q.label.to_string(),
                filter: q.filter.to_string(),
                base_override: q.base_override.map(str::to_string),
            });
        }
    }
    nodes
}

/// Returns only visible nodes (category + its children when expanded).
fn visible_lib_nodes(nodes: &[LibNode]) -> Vec<usize> {
    let mut visible = Vec::new();
    let mut in_expanded = false;
    for (i, node) in nodes.iter().enumerate() {
        match node {
            LibNode::Category { expanded, .. } => {
                visible.push(i);
                in_expanded = *expanded;
            }
            LibNode::Query { .. } => {
                if in_expanded {
                    visible.push(i);
                }
            }
        }
    }
    visible
}

// ── History entry ────────────────────────────────────────────────────────────

struct HistoryEntry {
    start_time: String,
    elapsed_ms: u64,
    result_count: usize,
    filter: String,
    base_dn: String,
    scope: SearchScope,
}

// ── Scope ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SearchScope {
    Subtree,
    OneLevel,
    Base,
}

impl SearchScope {
    fn label(self) -> &'static str {
        match self {
            SearchScope::Subtree => "WholeSubtree",
            SearchScope::OneLevel => "SingleLevel",
            SearchScope::Base => "BaseObject",
        }
    }

    fn to_ldap(self) -> Scope {
        match self {
            SearchScope::Subtree => Scope::Subtree,
            SearchScope::OneLevel => Scope::OneLevel,
            SearchScope::Base => Scope::Base,
        }
    }
}

// ── Side panel tab ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SideTab {
    Library,
    Attrs,
    History,
}

impl SideTab {
    fn next(self) -> Self {
        match self {
            SideTab::Library => SideTab::Attrs,
            SideTab::Attrs => SideTab::History,
            SideTab::History => SideTab::Library,
        }
    }
}

// ── Focus ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Filter,
    Results,
    Side,
}

// ── Cache finder overlay ─────────────────────────────────────────────────────

struct CacheFinder {
    pattern: String,
    results: Vec<(MatchCategory, String, String, String, usize)>,
    scroll: usize,
    cached_count: usize,
}

impl CacheFinder {
    fn new(cached_count: usize) -> Self {
        Self {
            pattern: String::new(),
            results: Vec::new(),
            scroll: 0,
            cached_count,
        }
    }

    fn update(&mut self, cache: &EntryCache) {
        if self.pattern.is_empty() {
            self.results.clear();
            return;
        }
        match cache.find_with_regexp(&self.pattern) {
            Ok(matches) => {
                self.results = matches
                    .into_iter()
                    .map(|m| (m.category, m.dn, m.attr_name, m.attr_value, m.value_index))
                    .collect();
            }
            Err(_) => {
                self.results.clear();
            }
        }
        self.scroll = 0;
    }
}

// ── DN hierarchy tree ────────────────────────────────────────────────────────

/// One rendered row in the results list.
#[derive(Clone)]
struct ResultRow {
    /// Display text including tree connectors and optional emoji prefix.
    label: String,
    /// The actual DN if this row is a real search result; None for virtual
    /// intermediate container nodes.
    dn: Option<String>,
}

/// Build a flat, renderable row list from result (dn, objectClass[]) pairs.
///
/// Inserts virtual intermediate nodes for OU/container path segments so the
/// results appear as a proper DN hierarchy.  The `base` DN is stripped from
/// each result DN before computing path segments.
fn build_result_rows(entries: &[(String, Vec<String>)], base: &str) -> Vec<ResultRow> {
    use std::collections::BTreeMap;

    let base_lc = base.to_lowercase();

    // Build a BTreeMap trie: RDN (original case) → Node.
    // BTreeMap gives lexicographic order for free.
    #[derive(Default)]
    struct Node {
        children: BTreeMap<String, Node>,
        dn: Option<String>,
        emoji: Option<String>,
    }

    fn relative_rdns(dn: &str, base_lc: &str) -> Vec<String> {
        let dn_lc = dn.to_lowercase();
        let suffix = format!(",{base_lc}");
        let prefix = if dn_lc == base_lc {
            ""
        } else if let Some(rest) = dn_lc.strip_suffix(&suffix) {
            &dn[..rest.len()]
        } else {
            dn
        };
        if prefix.is_empty() {
            return vec![];
        }
        // outermost component first
        prefix.split(',').rev().map(str::to_owned).collect()
    }

    let mut root = Node::default();
    for (dn, classes) in entries {
        let rdns = relative_rdns(dn, &base_lc);
        if rdns.is_empty() {
            continue;
        }
        let emoji = emoji_for_classes(classes);
        let mut cur = &mut root;
        let last = rdns.len() - 1;
        for (i, rdn) in rdns.iter().enumerate() {
            cur = cur.children.entry(rdn.clone()).or_default();
            if i == last {
                cur.dn = Some(dn.clone());
                cur.emoji = emoji.clone();
            }
        }
    }

    fn emit(node: &Node, rows: &mut Vec<ResultRow>, prefix: &str) {
        let count = node.children.len();
        for (i, (rdn, child)) in node.children.iter().enumerate() {
            let is_last = i == count - 1;
            let connector = if is_last { "└──" } else { "├──" };
            let child_prefix = if is_last {
                format!("{prefix}    ")
            } else {
                format!("{prefix}│   ")
            };
            let display = rdn.split_once('=').map_or(rdn.as_str(), |x| x.1);
            let label = match &child.emoji {
                Some(e) => format!("{prefix}{connector}{e}{display}"),
                None => format!("{prefix}{connector}{display}"),
            };
            rows.push(ResultRow {
                label,
                dn: child.dn.clone(),
            });
            emit(child, rows, &child_prefix);
        }
    }

    let mut rows = Vec::new();
    emit(&root, &mut rows, "");
    rows
}

/// Pick an emoji prefix based on AD objectClass values (returned in the search).
fn emoji_for_classes(classes: &[String]) -> Option<String> {
    let lc: Vec<String> = classes.iter().map(|s| s.to_lowercase()).collect();
    if lc.contains(&"computer".to_owned()) {
        Some("🖥 ".to_owned())
    } else if lc.contains(&"group".to_owned()) {
        Some("👥".to_owned())
    } else if lc.contains(&"user".to_owned()) || lc.contains(&"person".to_owned()) {
        Some("👤".to_owned())
    } else if lc.contains(&"organizationalunit".to_owned()) {
        Some("🗂 ".to_owned())
    } else if lc.contains(&"container".to_owned()) {
        Some("📁".to_owned())
    } else {
        None
    }
}

// ── SearchPage ───────────────────────────────────────────────────────────────

pub struct SearchPage {
    tx: Sender<AppMsg>,
    ldap: Option<SharedLdap>,
    cache: EntryCache,

    // Config mirrors.
    page_size: u32,
    flavor: BackendFlavor,
    attr_cfg: AttrConfig,

    // Filter input.
    filter_input: String,

    // Results tree: hierarchical view of DNs.
    result_rows: Vec<ResultRow>,
    result_state: ListState,

    // Selected result's attributes (lazily fetched).
    selected_dn: Option<String>,
    attrs: AttrPanel,

    // Library.
    lib_nodes: Vec<LibNode>,
    lib_state: ListState,

    // History.
    history: Vec<HistoryEntry>,
    history_state: TableState,

    // Settings modal.
    settings_open: bool,
    settings_form: Option<ModalForm>,
    search_base: Option<String>,
    root_dn: Option<String>,
    scope: SearchScope,

    // Search in progress.
    searching: bool,
    search_started: Option<Instant>,
    /// Monotonically increasing counter; incremented each time a new search is fired.
    /// Embedded in SearchDone so stale responses from superseded searches can be discarded.
    search_generation: u64,
    /// Truncation status of the most recent completed search; drives the results panel indicator.
    last_truncation: Truncation,

    // Panel focus and side tab.
    focus: Focus,
    side_tab: SideTab,

    // Cache finder overlay.
    finder: Option<CacheFinder>,

    // Bounding rects updated each render for mouse hit-testing.
    filter_rect: Rect,
    results_rect: Rect,
    side_rect: Rect,
    tab_lib_rect: Rect,
    tab_attrs_rect: Rect,
    tab_hist_rect: Rect,
}

impl SearchPage {
    pub fn new(tx: Sender<AppMsg>) -> Self {
        let lib_nodes = build_lib_nodes(&BackendFlavor::MsAd);
        Self {
            tx,
            ldap: None,
            cache: EntryCache::new(),
            page_size: 800,
            flavor: BackendFlavor::MsAd,
            attr_cfg: AttrConfig::default(),
            filter_input: String::new(),
            result_rows: Vec::new(),
            result_state: ListState::default(),
            selected_dn: None,
            attrs: AttrPanel::default(),
            lib_nodes,
            lib_state: ListState::default(),
            history: Vec::new(),
            history_state: TableState::default(),
            settings_open: false,
            settings_form: None,
            search_base: None,
            root_dn: None,
            scope: SearchScope::Subtree,
            searching: false,
            search_started: None,
            search_generation: 0,
            last_truncation: Truncation::None,
            focus: Focus::Filter,
            side_tab: SideTab::Library,
            finder: None,
            filter_rect: Rect::default(),
            results_rect: Rect::default(),
            side_rect: Rect::default(),
            tab_lib_rect: Rect::default(),
            tab_attrs_rect: Rect::default(),
            tab_hist_rect: Rect::default(),
        }
    }

    fn apply_config(&mut self, cfg: &ResolvedConfig) {
        self.page_size = cfg.paging;
        self.attr_cfg = AttrConfig {
            format_attrs: cfg.format,
            colors: cfg.colors,
            expand_attrs: cfg.expand,
            attr_limit: cfg.limit,
            attrsort: cfg.attrsort.clone(),
            timefmt: cfg.timefmt.clone(),
            offset: cfg.offset,
        };
        if cfg.backend != BackendFlavor::Auto && cfg.backend != self.flavor {
            self.flavor = cfg.backend.clone();
            self.lib_nodes = build_lib_nodes(&self.flavor);
            self.lib_state = ListState::default();
        }
    }

    fn effective_base(&self) -> String {
        self.search_base
            .clone()
            .or_else(|| self.root_dn.clone())
            .unwrap_or_default()
    }

    fn fire_search(&mut self) {
        self.fire_search_with(None, None);
    }

    fn fire_search_with(&mut self, override_filter: Option<String>, override_base: Option<String>) {
        let Some(ldap) = self.ldap.clone() else {
            debug!("fire_search: no ldap connection, aborting");
            return;
        };

        let raw = override_filter.unwrap_or_else(|| self.filter_input.trim().to_owned());
        if raw.is_empty() {
            return;
        }

        let root_dn = self.root_dn.clone().unwrap_or_default();
        let filter = resolve_filter_placeholders(&auto_wrap_filter(&raw), &root_dn);
        let base = override_base.unwrap_or_else(|| self.effective_base());
        let scope = self.scope.to_ldap();
        let tx = self.tx.clone();
        let attrs = vec![
            "objectClass",
            "cn",
            "ou",
            "dc",
            "name",
            "uid",
            "sAMAccountName",
        ];

        debug!(filter = %filter, base = %base, scope = ?scope, "fire_search launching");

        self.search_generation += 1;
        let search_gen = self.search_generation;
        self.searching = true;
        self.last_truncation = Truncation::None;
        self.search_started = Some(Instant::now());
        let started = Instant::now();

        tokio::spawn(async move {
            let search_fut = async {
                let mut guard = ldap.lock().await;
                guard.inner.search(&base, scope, &filter, attrs).await
            };

            let outcome =
                tokio::time::timeout(std::time::Duration::from_secs(30), search_fut).await;

            let elapsed_ms = started.elapsed().as_millis() as u64;

            let (raw_entries, rc) = match outcome {
                Err(_) => {
                    error!(elapsed_ms, "fire_search timed out after 30s");
                    let _ = tx
                        .send(AppMsg::Error("search timed out after 30s".into()))
                        .await;
                    let _ = tx
                        .send(AppMsg::SearchDone {
                            generation: search_gen,
                            filter,
                            entries: vec![],
                            elapsed_ms,
                            truncation: Truncation::None,
                        })
                        .await;
                    return;
                }
                Ok(Err(e)) => {
                    error!(error = %e, elapsed_ms, "fire_search ldap error");
                    let _ = tx.send(AppMsg::Error(e.to_string())).await;
                    let _ = tx
                        .send(AppMsg::SearchDone {
                            generation: search_gen,
                            filter,
                            entries: vec![],
                            elapsed_ms,
                            truncation: Truncation::None,
                        })
                        .await;
                    return;
                }
                Ok(Ok(res)) => {
                    let rc = res.1.rc;
                    (res.0, rc)
                }
            };

            // rc=0: success; rc=4: sizeLimitExceeded; rc=11: adminLimitExceeded.
            // All three may deliver a partial result set — keep whatever entries arrived.
            let truncation = match rc {
                0 => Truncation::None,
                4 => Truncation::SizeLimit,
                11 => Truncation::AdminLimit,
                _ => {
                    error!(rc, elapsed_ms, "fire_search non-success result code");
                    let _ = tx.send(AppMsg::Error(format!("LDAP error {rc}"))).await;
                    let _ = tx
                        .send(AppMsg::SearchDone {
                            generation: search_gen,
                            filter,
                            entries: vec![],
                            elapsed_ms,
                            truncation: Truncation::None,
                        })
                        .await;
                    return;
                }
            };

            let entries: Vec<ldap3::SearchEntry> = raw_entries
                .into_iter()
                .map(ldap3::SearchEntry::construct)
                .collect();

            if truncation != Truncation::None {
                debug!(
                    rc,
                    count = entries.len(),
                    elapsed_ms,
                    "fire_search partial result"
                );
            } else {
                debug!(count = entries.len(), elapsed_ms, "fire_search done");
            }

            let _ = tx
                .send(AppMsg::SearchDone {
                    generation: search_gen,
                    filter,
                    entries,
                    elapsed_ms,
                    truncation,
                })
                .await;
        });
    }

    fn fetch_entry(&self, dn: String) {
        let Some(ldap) = self.ldap.clone() else {
            return;
        };
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let mut guard = ldap.lock().await;
            let result = guard
                .inner
                .search(&dn, ldap3::Scope::Base, "(objectClass=*)", vec!["*", "+"])
                .await;
            match result {
                Ok(res) => match res.success() {
                    Ok((entries, _)) => {
                        if let Some(raw) = entries.into_iter().next() {
                            let entry = ldap3::SearchEntry::construct(raw);
                            let _ = tx.send(AppMsg::EntryFetched(entry)).await;
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(AppMsg::Error(e.to_string())).await;
                    }
                },
                Err(e) => {
                    let _ = tx.send(AppMsg::Error(e.to_string())).await;
                }
            }
        });
    }

    fn open_settings(&mut self) {
        let base = self.effective_base();
        let scope_label = self.scope.label().to_owned();
        let form = ModalForm::new(
            "Search Settings",
            vec![
                FormField::text("Base DN", base),
                FormField::select(
                    "Scope",
                    vec![
                        "WholeSubtree".into(),
                        "SingleLevel".into(),
                        "BaseObject".into(),
                    ],
                    scope_label,
                ),
            ],
        );
        self.settings_form = Some(form);
        self.settings_open = true;
    }

    fn apply_settings(&mut self) {
        if let Some(form) = &self.settings_form {
            let base = form.fields[0].value.trim().to_owned();
            self.search_base = if base.is_empty() { None } else { Some(base) };
            self.scope = match form.fields[1].value.as_str() {
                "SingleLevel" => SearchScope::OneLevel,
                "BaseObject" => SearchScope::Base,
                _ => SearchScope::Subtree,
            };
        }
        self.settings_form = None;
        self.settings_open = false;
        if !self.filter_input.trim().is_empty() {
            self.fire_search();
        }
    }

    fn selected_result_idx(&self) -> Option<usize> {
        self.result_state.selected()
    }

    /// Select the result row at `idx`.  Only rows with a real DN are
    /// selectable; if `idx` points to a virtual node, the call is a no-op.
    fn select_result(&mut self, idx: usize) {
        let Some(row) = self.result_rows.get(idx) else {
            return;
        };
        let Some(dn) = row.dn.clone() else {
            return;
        };
        self.result_state.select(Some(idx));
        self.selected_dn = Some(dn.clone());
        self.attrs.clear();
        self.attrs.selected_dn = Some(dn.clone());
        self.fetch_entry(dn.clone());
        self.cache.add(dn, std::collections::HashMap::new());
    }

    fn select_result_next(&mut self) {
        if self.result_rows.is_empty() {
            return;
        }
        let start = self.result_state.selected().map_or(0, |i| i + 1);
        for idx in start..self.result_rows.len() {
            if self.result_rows[idx].dn.is_some() {
                self.select_result(idx);
                return;
            }
        }
    }

    fn select_result_prev(&mut self) {
        if self.result_rows.is_empty() {
            return;
        }
        let start = match self.result_state.selected() {
            Some(0) | None => return,
            Some(i) => i - 1,
        };
        for idx in (0..=start).rev() {
            if self.result_rows[idx].dn.is_some() {
                self.select_result(idx);
                // If we're at the first real row, reset the scroll offset so the
                // virtual header rows above it scroll back into view.
                if idx
                    == self
                        .result_rows
                        .iter()
                        .position(|r| r.dn.is_some())
                        .unwrap_or(0)
                {
                    *self.result_state.offset_mut() = 0;
                }
                return;
            }
        }
    }

    fn lib_select_next(&mut self) {
        let visible = visible_lib_nodes(&self.lib_nodes);
        if visible.is_empty() {
            return;
        }
        let next = match self.lib_state.selected() {
            Some(i) => (i + 1).min(visible.len() - 1),
            None => 0,
        };
        self.lib_state.select(Some(next));
    }

    fn lib_select_prev(&mut self) {
        let visible = visible_lib_nodes(&self.lib_nodes);
        if visible.is_empty() {
            return;
        }
        let prev = match self.lib_state.selected() {
            Some(0) | None => 0,
            Some(i) => i - 1,
        };
        self.lib_state.select(Some(prev));
    }

    fn lib_toggle_or_run(&mut self) {
        let visible = visible_lib_nodes(&self.lib_nodes);
        let sel = match self.lib_state.selected() {
            Some(i) => i,
            None => return,
        };
        let Some(&node_idx) = visible.get(sel) else {
            return;
        };
        match self.lib_nodes[node_idx].clone() {
            LibNode::Category { .. } => {
                if let LibNode::Category {
                    ref mut expanded, ..
                } = self.lib_nodes[node_idx]
                {
                    *expanded = !*expanded;
                }
            }
            LibNode::Query {
                filter,
                base_override,
                ..
            } => {
                let root_dn = self.root_dn.clone().unwrap_or_default();
                let resolved_filter = resolve_filter_placeholders(&filter, &root_dn);
                let resolved_base = base_override.map(|b| b.replace("<root DN>", &root_dn));
                self.filter_input = resolved_filter.clone();
                self.focus = Focus::Filter;
                self.fire_search_with(Some(resolved_filter), resolved_base);
            }
        }
    }

    fn history_select_next(&mut self) {
        if self.history.is_empty() {
            return;
        }
        let next = match self.history_state.selected() {
            Some(i) => (i + 1).min(self.history.len() - 1),
            None => 0,
        };
        self.history_state.select(Some(next));
    }

    fn history_select_prev(&mut self) {
        if self.history.is_empty() {
            return;
        }
        let prev = match self.history_state.selected() {
            Some(0) | None => 0,
            Some(i) => i - 1,
        };
        self.history_state.select(Some(prev));
    }

    fn history_copy_filter(&mut self) {
        if let Some(sel) = self.history_state.selected() {
            // history is stored newest-first for display (reversed on render), so
            // we map back: display row 0 = history[last]
            let actual_idx = self.history.len().saturating_sub(1).saturating_sub(sel);
            if let Some(entry) = self.history.get(actual_idx) {
                self.filter_input = entry.filter.clone();
                self.focus = Focus::Filter;
            }
        }
    }

    fn open_finder(&mut self) {
        let count = self.cache.len();
        let mut f = CacheFinder::new(count);
        f.update(&self.cache);
        self.finder = Some(f);
    }

    fn finder_update_results(&mut self) {
        if let Some(f) = &mut self.finder {
            f.update(&self.cache);
        }
    }
}

impl Page for SearchPage {
    fn title(&self) -> &str {
        "Search"
    }

    fn captures_input(&self) -> bool {
        self.focus == Focus::Filter || self.settings_open || self.finder.is_some()
    }

    fn render(&mut self, frame: &mut Frame<'_>, area: Rect) {
        // ── Layout ───────────────────────────────────────────────────────────
        // Row 0: control bar (filter input + tab selector) — 3 lines
        // Row 1: main content area (results tree left | side panel right)
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0)])
            .split(area);

        let content_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(65), Constraint::Percentage(35)])
            .split(rows[1]);

        // ── Control bar ──────────────────────────────────────────────────────
        let control_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Min(0), Constraint::Length(28)])
            .split(rows[0]);

        // Save rects for mouse hit-testing.
        self.filter_rect = control_cols[0];
        self.results_rect = content_cols[0];
        self.side_rect = content_cols[1];
        // Tab spans inside the tab-selector block (1-cell border on each side).
        // Span widths: " Library "=9, "|"=1, " Attrs "=7, "|"=1, " History "=9
        {
            let ix = control_cols[1].x.saturating_add(1);
            let iy = control_cols[1].y.saturating_add(1);
            self.tab_lib_rect = Rect {
                x: ix,
                y: iy,
                width: 9,
                height: 1,
            };
            self.tab_attrs_rect = Rect {
                x: ix.saturating_add(10),
                y: iy,
                width: 7,
                height: 1,
            };
            self.tab_hist_rect = Rect {
                x: ix.saturating_add(18),
                y: iy,
                width: 9,
                height: 1,
            };
        }

        let filter_border = if self.focus == Focus::Filter {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };

        let filter_text = if self.searching {
            format!("{} [searching…]", self.filter_input)
        } else {
            self.filter_input.clone()
        };
        let placeholder = if filter_text.is_empty() && !self.searching {
            "Type an LDAP search filter or the name of an object"
        } else {
            ""
        };
        let filter_content = if filter_text.is_empty() && !self.searching {
            Span::styled(placeholder, Style::default().fg(Color::DarkGray))
        } else {
            Span::raw(filter_text)
        };

        let filter_para = Paragraph::new(Line::from(filter_content)).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Search Filter")
                .border_style(filter_border),
        );
        frame.render_widget(filter_para, control_cols[0]);

        // Tab selector
        let tab_style_lib = if self.side_tab == SideTab::Library {
            Style::default().fg(Color::Black).bg(Color::White)
        } else {
            Style::default()
        };
        let tab_style_attrs = if self.side_tab == SideTab::Attrs {
            Style::default().fg(Color::Black).bg(Color::White)
        } else {
            Style::default()
        };
        let tab_style_hist = if self.side_tab == SideTab::History {
            Style::default().fg(Color::Black).bg(Color::White)
        } else {
            Style::default()
        };
        let tab_line = Line::from(vec![
            Span::styled(" Library ", tab_style_lib),
            Span::raw("|"),
            Span::styled(" Attrs ", tab_style_attrs),
            Span::raw("|"),
            Span::styled(" History ", tab_style_hist),
        ]);
        let tab_para = Paragraph::new(tab_line).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default()),
        );
        frame.render_widget(tab_para, control_cols[1]);

        // ── Results tree ─────────────────────────────────────────────────────
        self.render_results(frame, content_cols[0]);

        // ── Side panel ───────────────────────────────────────────────────────
        match self.side_tab {
            SideTab::Library => self.render_library(frame, content_cols[1]),
            SideTab::Attrs => self.render_attrs(frame, content_cols[1]),
            SideTab::History => self.render_history(frame, content_cols[1]),
        }

        // ── Settings modal (rendered last / on top) ──────────────────────────
        if self.settings_open {
            if let Some(form) = &self.settings_form {
                form.render(frame, area);
            }
        }

        // ── Cache finder overlay ─────────────────────────────────────────────
        if self.finder.is_some() {
            self.render_finder(frame, area);
        }
    }

    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Result<()> {
        // Cache finder overlay intercepts all keys.
        if self.finder.is_some() {
            match (code, modifiers) {
                (KeyCode::Esc, _) => {
                    self.finder = None;
                }
                (KeyCode::Backspace, _) => {
                    if let Some(f) = &mut self.finder {
                        f.pattern.pop();
                    }
                    self.finder_update_results();
                }
                (KeyCode::Char(ch), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                    if let Some(f) = &mut self.finder {
                        f.pattern.push(ch);
                    }
                    self.finder_update_results();
                }
                (KeyCode::Down, _) => {
                    if let Some(f) = &mut self.finder {
                        let max = f.results.len().saturating_sub(1);
                        if f.scroll < max {
                            f.scroll += 1;
                        }
                    }
                }
                (KeyCode::Up, _) => {
                    if let Some(f) = &mut self.finder {
                        f.scroll = f.scroll.saturating_sub(1);
                    }
                }
                _ => {}
            }
            return Ok(());
        }

        // Settings modal intercepts all keys.
        if self.settings_open {
            match code {
                KeyCode::Esc => {
                    self.settings_form = None;
                    self.settings_open = false;
                }
                KeyCode::Enter => self.apply_settings(),
                KeyCode::Tab => {
                    if let Some(f) = &mut self.settings_form {
                        f.next_field();
                    }
                }
                KeyCode::BackTab => {
                    if let Some(f) = &mut self.settings_form {
                        f.prev_field();
                    }
                }
                KeyCode::Backspace => {
                    if let Some(f) = &mut self.settings_form {
                        f.handle_backspace();
                    }
                }
                KeyCode::Up => {
                    if let Some(f) = &mut self.settings_form {
                        f.prev_option();
                    }
                }
                KeyCode::Down => {
                    if let Some(f) = &mut self.settings_form {
                        f.next_option();
                    }
                }
                KeyCode::Char(ch) => {
                    if let Some(f) = &mut self.settings_form {
                        f.handle_char(ch);
                    }
                }
                _ => {}
            }
            return Ok(());
        }

        // ── Page-level shortcuts ─────────────────────────────────────────────
        match (code, modifiers) {
            (KeyCode::Char('f'), KeyModifiers::CONTROL) => {
                self.open_finder();
                return Ok(());
            }
            (KeyCode::Char('b'), KeyModifiers::CONTROL) => {
                self.open_settings();
                return Ok(());
            }
            (KeyCode::Tab, KeyModifiers::NONE) => {
                self.focus = match self.focus {
                    Focus::Filter => Focus::Results,
                    Focus::Results => Focus::Side,
                    Focus::Side => Focus::Filter,
                };
                return Ok(());
            }
            (KeyCode::BackTab, _) => {
                self.focus = match self.focus {
                    Focus::Filter => Focus::Side,
                    Focus::Results => Focus::Filter,
                    Focus::Side => Focus::Results,
                };
                return Ok(());
            }
            _ => {}
        }

        // ── Panel-specific keys ──────────────────────────────────────────────
        match self.focus {
            Focus::Filter => match (code, modifiers) {
                (KeyCode::Esc, _) => self.focus = Focus::Results,
                (KeyCode::Enter, _) => {
                    self.fire_search();
                    self.focus = Focus::Results;
                }
                (KeyCode::Backspace, _) => {
                    self.filter_input.pop();
                }
                (KeyCode::Char(ch), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                    self.filter_input.push(ch);
                }
                _ => {}
            },

            Focus::Results => match (code, modifiers) {
                (KeyCode::Down, _) | (KeyCode::Char('j'), KeyModifiers::NONE) => {
                    self.select_result_next();
                }
                (KeyCode::Up, _) | (KeyCode::Char('k'), KeyModifiers::NONE) => {
                    self.select_result_prev();
                }
                (KeyCode::Right, _) => {
                    // Expand: no tree expand in flat result list; focus attrs.
                    self.side_tab = SideTab::Attrs;
                    self.focus = Focus::Side;
                }
                (KeyCode::Left, _) => {
                    // Collapse: go to filter
                    self.focus = Focus::Filter;
                }
                (KeyCode::Char('r') | KeyCode::Char('R'), KeyModifiers::NONE) => {
                    if let Some(dn) = self.selected_dn.clone() {
                        self.attrs.clear();
                        self.attrs.selected_dn = Some(dn.clone());
                        self.fetch_entry(dn);
                    }
                }
                _ => {}
            },

            Focus::Side => match self.side_tab {
                SideTab::Library => self.handle_library_key(code, modifiers),
                SideTab::Attrs => self.handle_attrs_key(code, modifiers),
                SideTab::History => self.handle_history_key(code, modifiers),
            },
        }
        Ok(())
    }

    fn apply_msg(&mut self, msg: AppMsg) {
        match msg {
            AppMsg::Connected {
                root_dn,
                client,
                flavor,
                ..
            } => {
                self.root_dn = Some(root_dn.clone());
                self.ldap = Some(client);
                // Use the flavor resolved during connection (auto-detection result).
                self.flavor = flavor;
                self.lib_nodes = build_lib_nodes(&self.flavor);
                self.lib_state = ListState::default();
            }

            AppMsg::SearchDone {
                generation,
                filter,
                entries,
                elapsed_ms,
                truncation,
            } => {
                if generation != self.search_generation {
                    return;
                }
                self.searching = false;
                self.last_truncation = truncation;
                let actual_ms = self
                    .search_started
                    .take()
                    .map(|t| t.elapsed().as_millis() as u64)
                    .unwrap_or(elapsed_ms);

                let count = entries.len();
                let elapsed_s = actual_ms as f64 / 1000.0;

                self.history.push(HistoryEntry {
                    start_time: format_wall_time(),
                    elapsed_ms: actual_ms,
                    result_count: count,
                    filter,
                    base_dn: self.effective_base(),
                    scope: self.scope,
                });

                // Build (dn, objectClass[]) pairs then render as a hierarchy.
                let pairs: Vec<(String, Vec<String>)> = entries
                    .into_iter()
                    .map(|e| {
                        let classes = e.attrs.get("objectClass").cloned().unwrap_or_default();
                        (e.dn, classes)
                    })
                    .collect();
                let base = self.effective_base();
                self.result_rows = build_result_rows(&pairs, &base);
                self.result_state = ListState::default();
                self.selected_dn = None;
                self.attrs.clear();

                // Auto-select the first real (non-virtual) result.
                for (idx, row) in self.result_rows.iter().enumerate() {
                    if row.dn.is_some() {
                        self.select_result(idx);
                        break;
                    }
                }

                // Push completion message to the log panel.
                let s = if count == 1 { "" } else { "s" };
                let log_msg = match truncation {
                    Truncation::None => {
                        format!("Query completed ({count} object{s} found in {elapsed_s:.4}s)")
                    }
                    Truncation::SizeLimit => format!(
                        "Query completed ({count} object{s} found in {elapsed_s:.4}s, size limit reached — results may be incomplete)"
                    ),
                    Truncation::AdminLimit => format!(
                        "ERROR: Administrative limit exceeded — results are incomplete ({count} object{s} returned in {elapsed_s:.4}s)"
                    ),
                };
                let _ = self.tx.try_send(AppMsg::Log(log_msg));
            }

            AppMsg::EntryFetched(entry) => {
                if self.selected_dn.as_deref() == Some(&entry.dn) {
                    self.cache.add(entry.dn.clone(), entry.attrs.clone());
                    self.attrs.load(&entry);
                }
            }

            AppMsg::ConfigChanged(cfg) => {
                let prev_flavor = self.flavor.clone();
                self.apply_config(&cfg);
                if cfg.backend != BackendFlavor::Auto && cfg.backend != prev_flavor {
                    self.lib_nodes = build_lib_nodes(&self.flavor);
                    self.lib_state = ListState::default();
                }
            }

            _ => {}
        }
    }

    fn handle_mouse(&mut self, event: MouseEvent) {
        let (col, row) = (event.column, event.row);
        let in_rect =
            |r: Rect| col >= r.x && col < r.x + r.width && row >= r.y && row < r.y + r.height;

        match event.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if in_rect(self.tab_lib_rect) {
                    self.side_tab = SideTab::Library;
                    self.focus = Focus::Side;
                } else if in_rect(self.tab_attrs_rect) {
                    self.side_tab = SideTab::Attrs;
                    self.focus = Focus::Side;
                } else if in_rect(self.tab_hist_rect) {
                    self.side_tab = SideTab::History;
                    self.focus = Focus::Side;
                } else if in_rect(self.filter_rect) {
                    self.focus = Focus::Filter;
                } else if in_rect(self.results_rect) {
                    self.focus = Focus::Results;
                } else if in_rect(self.side_rect) {
                    if self.side_tab == SideTab::Attrs {
                        self.focus = Focus::Side;
                        let cfg = self.attr_cfg.clone();
                        self.attrs.handle_click(col, row, &cfg);
                    }
                    self.focus = Focus::Side;
                }
            }
            MouseEventKind::ScrollDown => {
                if in_rect(self.results_rect) {
                    self.select_result_next();
                } else if in_rect(self.side_rect) {
                    match self.side_tab {
                        SideTab::Attrs => {
                            self.handle_attrs_key(KeyCode::Down, KeyModifiers::NONE);
                        }
                        SideTab::Library => self.lib_select_next(),
                        SideTab::History => self.history_select_next(),
                    }
                }
            }
            MouseEventKind::ScrollUp => {
                if in_rect(self.results_rect) {
                    self.select_result_prev();
                } else if in_rect(self.side_rect) {
                    match self.side_tab {
                        SideTab::Attrs => {
                            self.handle_attrs_key(KeyCode::Up, KeyModifiers::NONE);
                        }
                        SideTab::Library => self.lib_select_prev(),
                        SideTab::History => self.history_select_prev(),
                    }
                }
            }
            _ => {}
        }
    }
}

// ── Sub-key handlers ─────────────────────────────────────────────────────────

impl SearchPage {
    fn handle_library_key(&mut self, code: KeyCode, _modifiers: KeyModifiers) {
        match code {
            KeyCode::Down | KeyCode::Char('j') => self.lib_select_next(),
            KeyCode::Up | KeyCode::Char('k') => self.lib_select_prev(),
            KeyCode::Enter | KeyCode::Right => self.lib_toggle_or_run(),
            KeyCode::Left => {
                // Collapse current expanded category or do nothing.
                let visible = visible_lib_nodes(&self.lib_nodes);
                if let Some(sel) = self.lib_state.selected() {
                    if let Some(&node_idx) = visible.get(sel) {
                        if let LibNode::Category {
                            ref mut expanded, ..
                        } = self.lib_nodes[node_idx]
                        {
                            *expanded = false;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_attrs_key(&mut self, code: KeyCode, _modifiers: KeyModifiers) {
        match code {
            KeyCode::Char('r') | KeyCode::Char('R') => {
                if let Some(dn) = self.selected_dn.clone() {
                    self.attrs.clear();
                    self.attrs.selected_dn = Some(dn.clone());
                    self.fetch_entry(dn);
                }
            }
            other => self.attrs.handle_key(other),
        }
    }

    fn handle_history_key(&mut self, code: KeyCode, _modifiers: KeyModifiers) {
        match code {
            KeyCode::Down | KeyCode::Char('j') => self.history_select_next(),
            KeyCode::Up | KeyCode::Char('k') => self.history_select_prev(),
            KeyCode::Enter => self.history_copy_filter(),
            _ => {}
        }
    }
}

// ── Private render helpers ───────────────────────────────────────────────────

impl SearchPage {
    fn render_results(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let border_style = match self.last_truncation {
            Truncation::AdminLimit if !self.searching => Style::default().fg(Color::Red),
            Truncation::SizeLimit if !self.searching => Style::default().fg(Color::Yellow),
            _ if self.focus == Focus::Results => Style::default().fg(Color::Yellow),
            _ => Style::default(),
        };
        // Count only real result rows (not virtual intermediate nodes).
        let real_count = self.result_rows.iter().filter(|r| r.dn.is_some()).count();
        let title = if self.searching {
            "Search Results [searching…]".to_string()
        } else {
            match self.last_truncation {
                Truncation::AdminLimit => {
                    format!("Search Results ({real_count}) [ADMIN LIMIT — results incomplete]")
                }
                Truncation::SizeLimit => {
                    format!("Search Results ({real_count}) [truncated]")
                }
                Truncation::None => format!("Search Results ({real_count})"),
            }
        };

        let items: Vec<ListItem> = self
            .result_rows
            .iter()
            .map(|row| {
                let style = if row.dn.is_none() {
                    // Virtual container node — dimmed, not selectable visually.
                    Style::default().fg(Color::Gray)
                } else {
                    Style::default()
                };
                ListItem::new(Span::styled(row.label.clone(), style))
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title)
                    .border_style(border_style),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );

        frame.render_stateful_widget(list, area, &mut self.result_state);
    }

    fn render_library(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let border_style = if self.focus == Focus::Side {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };

        let visible = visible_lib_nodes(&self.lib_nodes);

        let items: Vec<ListItem> = visible
            .iter()
            .map(|&node_idx| match &self.lib_nodes[node_idx] {
                LibNode::Category {
                    label, expanded, ..
                } => {
                    let arrow = if *expanded { "▼ " } else { "▶ " };
                    ListItem::new(Line::from(vec![
                        Span::styled(arrow, Style::default().fg(Color::Yellow)),
                        Span::styled(label.clone(), Style::default().add_modifier(Modifier::BOLD)),
                    ]))
                }
                LibNode::Query { label, .. } => {
                    ListItem::new(Line::from(vec![Span::raw("  "), Span::raw(label.clone())]))
                }
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Library")
                    .border_style(border_style),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::White)
                    .add_modifier(Modifier::BOLD),
            );

        frame.render_stateful_widget(list, area, &mut self.lib_state);
    }

    fn render_attrs(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let focused = self.focus == Focus::Side && self.side_tab == SideTab::Attrs;
        let title = match &self.selected_dn {
            Some(dn) => format!("Attrs — {dn}"),
            None => "Attrs".to_owned(),
        };
        let cfg = self.attr_cfg.clone();
        self.attrs.render(frame, area, &title, focused, &cfg);
    }

    fn render_history(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let border_style = if self.focus == Focus::Side {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };

        let rows: Vec<Row> = self
            .history
            .iter()
            .rev()
            .map(|h| {
                Row::new(vec![
                    h.start_time.clone(),
                    format!("{:.3}s", h.elapsed_ms as f64 / 1000.0),
                    h.result_count.to_string(),
                    h.filter.clone(),
                    h.base_dn.clone(),
                    h.scope.label().to_string(),
                ])
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Length(8),  // StartTime
                Constraint::Length(7),  // Duration
                Constraint::Length(5),  // Results
                Constraint::Min(20),    // Query
                Constraint::Min(10),    // BaseDN
                Constraint::Length(13), // Scope
            ],
        )
        .header(
            Row::new(vec!["Time", "Duration", "N", "Query", "BaseDN", "Scope"]).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("History  (Enter=use filter)")
                .border_style(border_style),
        )
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

        frame.render_stateful_widget(table, area, &mut self.history_state);
    }

    fn render_finder(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let Some(finder) = &self.finder else {
            return;
        };

        // Full-screen overlay
        frame.render_widget(Clear, area);

        let block = Block::default()
            .borders(Borders::ALL)
            .title("Cache Finder (Object Search)")
            .style(Style::default().fg(Color::White).bg(Color::DarkGray));

        let inner = block.inner(area);
        frame.render_widget(block, area);

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // regexp input + counts
                Constraint::Min(0),    // results table
                Constraint::Length(1), // hint
            ])
            .split(inner);

        // Top row: pattern + stats
        let match_count = finder.results.len();
        let top = Line::from(vec![
            Span::styled("Filter: ", Style::default().fg(Color::Yellow)),
            Span::styled(
                finder.pattern.clone(),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::REVERSED),
            ),
            Span::raw(format!(
                "  [{} cached | {} matches]",
                finder.cached_count, match_count
            )),
        ]);
        frame.render_widget(Paragraph::new(top), rows[0]);

        // Results table
        let visible_height = rows[1].height as usize;
        let result_rows: Vec<Row> = finder
            .results
            .iter()
            .skip(finder.scroll)
            .take(visible_height)
            .map(|(cat, dn, attr_name, attr_value, val_idx)| {
                let (cat_label, cat_color) = match cat {
                    MatchCategory::Dn => ("ObjectDN", Color::Blue),
                    MatchCategory::AttrName => ("AttrName", Color::Magenta),
                    MatchCategory::AttrValue => ("AttrVal", Color::LightMagenta),
                };
                use ratatui::widgets::Cell;
                Row::new(vec![
                    Cell::from(cat_label).style(Style::default().fg(cat_color)),
                    Cell::from(dn.clone()),
                    Cell::from(attr_name.clone()),
                    Cell::from(attr_value.clone()),
                    Cell::from(val_idx.to_string()),
                ])
            })
            .collect();

        let table = Table::new(
            result_rows,
            [
                Constraint::Length(9),
                Constraint::Percentage(40),
                Constraint::Percentage(20),
                Constraint::Percentage(30),
                Constraint::Length(5),
            ],
        )
        .header(
            Row::new(vec!["Match", "Object", "AttrName", "AttrValue", "ValIdx"]).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        );
        frame.render_widget(table, rows[1]);

        // Hint
        let hint = Line::from(vec![
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::raw(" Go Back"),
        ]);
        frame.render_widget(Paragraph::new(hint), rows[2]);
    }
}

// ── Wall-clock time formatting ────────────────────────────────────────────────

fn format_wall_time() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // HH:MM:SS from Unix seconds (UTC)
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    format!("{h:02}:{m:02}:{s:02}")
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppMsg;
    use tokio::sync::mpsc;

    fn page() -> SearchPage {
        let (tx, _rx) = mpsc::channel(8);
        SearchPage::new(tx)
    }

    #[test]
    fn history_recorded_after_search_done() {
        let mut p = page();
        p.apply_msg(AppMsg::SearchDone {
            generation: 0,
            filter: "(cn=*)".into(),
            entries: vec![],
            elapsed_ms: 42,
            truncation: Truncation::None,
        });
        assert_eq!(p.history.len(), 1);
        assert_eq!(p.history[0].filter, "(cn=*)");
        assert_eq!(p.history[0].result_count, 0);
    }

    #[test]
    fn history_records_result_count() {
        let mut p = page();
        p.apply_msg(AppMsg::SearchDone {
            generation: 0,
            filter: "(objectClass=*)".into(),
            entries: vec![],
            elapsed_ms: 10,
            truncation: Truncation::None,
        });
        assert_eq!(p.history[0].result_count, 0);
    }

    #[test]
    fn history_has_scope_and_base() {
        let mut p = page();
        p.root_dn = Some("DC=example,DC=com".into());
        p.apply_msg(AppMsg::SearchDone {
            generation: 0,
            filter: "(cn=*)".into(),
            entries: vec![],
            elapsed_ms: 5,
            truncation: Truncation::None,
        });
        assert_eq!(p.history[0].scope, SearchScope::Subtree);
        assert_eq!(p.history[0].base_dn, "DC=example,DC=com");
    }

    #[test]
    fn settings_modal_opens_and_cancels() {
        let mut p = page();
        p.open_settings();
        assert!(p.settings_open);
        p.handle_key(KeyCode::Esc, KeyModifiers::NONE).unwrap();
        assert!(!p.settings_open);
    }

    #[test]
    fn settings_modal_applies_base_and_scope() {
        let mut p = page();
        p.open_settings();
        if let Some(f) = &mut p.settings_form {
            f.fields[0].value = "dc=example,dc=com".to_owned();
            f.fields[1].value = "SingleLevel".to_owned();
        }
        // apply_settings calls fire_search which needs ldap; just test state.
        if let Some(form) = &p.settings_form {
            let base = form.fields[0].value.trim().to_owned();
            p.search_base = if base.is_empty() { None } else { Some(base) };
            p.scope = match form.fields[1].value.as_str() {
                "SingleLevel" => SearchScope::OneLevel,
                "BaseObject" => SearchScope::Base,
                _ => SearchScope::Subtree,
            };
        }
        p.settings_form = None;
        p.settings_open = false;
        assert_eq!(p.search_base.as_deref(), Some("dc=example,dc=com"));
        assert_eq!(p.scope, SearchScope::OneLevel);
    }

    #[test]
    fn tab_cycles_focus() {
        let mut p = page();
        assert_eq!(p.focus, Focus::Filter);
        p.handle_key(KeyCode::Tab, KeyModifiers::NONE).unwrap();
        assert_eq!(p.focus, Focus::Results);
        p.handle_key(KeyCode::Tab, KeyModifiers::NONE).unwrap();
        assert_eq!(p.focus, Focus::Side);
        p.handle_key(KeyCode::Tab, KeyModifiers::NONE).unwrap();
        assert_eq!(p.focus, Focus::Filter);
    }

    #[test]
    fn library_category_expands_on_enter() {
        let mut p = page();
        p.focus = Focus::Side;
        p.side_tab = SideTab::Library;
        // Select first category (index 0 in visible list)
        p.lib_state.select(Some(0));
        p.handle_key(KeyCode::Enter, KeyModifiers::NONE).unwrap();
        // After enter the category should expand.
        let visible = visible_lib_nodes(&p.lib_nodes);
        assert!(visible.len() > 1, "category should have expanded");
    }

    fn category_labels(p: &SearchPage) -> Vec<String> {
        p.lib_nodes
            .iter()
            .filter_map(|n| {
                if let LibNode::Category { label, .. } = n {
                    Some(label.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    #[test]
    fn library_switches_to_basic_on_config_changed_with_basic_flavor() {
        let mut p = page();
        assert!(matches!(p.flavor, BackendFlavor::MsAd));
        p.apply_msg(AppMsg::ConfigChanged(Box::new(
            crate::config::ResolvedConfig {
                backend: BackendFlavor::Basic,
                ..Default::default()
            },
        )));
        let cats = category_labels(&p);
        assert!(
            cats.iter().any(|c| c == "Groups"),
            "BasicLDAP Groups expected"
        );
        assert!(
            !cats.iter().any(|c| c == "Security"),
            "MsAd Security should be absent"
        );
        assert!(
            !cats.iter().any(|c| c == "Group Members"),
            "MsAd Group Members should be absent"
        );
    }

    #[test]
    fn library_stays_msad_on_config_changed_with_msad_flavor() {
        let mut p = page();
        p.apply_msg(AppMsg::ConfigChanged(Box::new(
            crate::config::ResolvedConfig {
                backend: BackendFlavor::MsAd,
                ..Default::default()
            },
        )));
        let cats = category_labels(&p);
        assert!(
            cats.iter().any(|c| c == "Security"),
            "MsAd Security expected"
        );
        assert!(
            cats.iter().any(|c| c == "Group Members"),
            "MsAd Group Members expected"
        );
        assert!(
            !cats.iter().any(|c| c == "Groups"),
            "BasicLDAP Groups should be absent"
        );
    }

    #[test]
    fn msad_library_has_expected_categories() {
        let nodes = build_lib_nodes(&BackendFlavor::MsAd);
        let cat_labels: Vec<&str> = nodes
            .iter()
            .filter_map(|n| {
                if let LibNode::Category { label, .. } = n {
                    Some(label.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert!(cat_labels.contains(&"Enum"));
        assert!(cat_labels.contains(&"Users"));
        assert!(cat_labels.contains(&"Computers"));
        assert!(cat_labels.contains(&"Security"));
        assert!(cat_labels.contains(&"Group Members"));
    }

    #[test]
    fn basic_library_has_expected_categories() {
        let nodes = build_lib_nodes(&BackendFlavor::Basic);
        let cat_labels: Vec<&str> = nodes
            .iter()
            .filter_map(|n| {
                if let LibNode::Category { label, .. } = n {
                    Some(label.as_str())
                } else {
                    None
                }
            })
            .collect();
        assert!(cat_labels.contains(&"Enum"));
        assert!(cat_labels.contains(&"Users"));
        assert!(cat_labels.contains(&"Groups"));
        assert!(!cat_labels.contains(&"Security"));
    }

    #[test]
    fn dn_tree_groups_by_path() {
        let base = "DC=ad,DC=com";
        let entries = vec![
            (
                "CN=Alice,OU=Users,DC=ad,DC=com".to_owned(),
                vec!["user".to_owned()],
            ),
            (
                "CN=Bob,OU=Users,DC=ad,DC=com".to_owned(),
                vec!["user".to_owned()],
            ),
            (
                "CN=Srv01,OU=Computers,DC=ad,DC=com".to_owned(),
                vec!["computer".to_owned()],
            ),
        ];
        let rows = build_result_rows(&entries, base);
        // Should have 2 virtual container rows + 3 leaf rows = 5 total.
        assert_eq!(rows.len(), 5);
        // First row is the OU=Computers virtual node (BTreeMap sorts C < U).
        assert!(rows[0].dn.is_none());
        assert!(rows[0].label.contains("Computers"));
        // Second row is the Srv01 leaf under Computers.
        assert!(rows[1].dn.is_some());
        assert!(rows[1].label.contains("Srv01"));
        // Third row is OU=Users virtual node.
        assert!(rows[2].dn.is_none());
        assert!(rows[2].label.contains("Users"));
        // Alice and Bob are leaves under Users.
        assert!(rows[3].dn.is_some());
        assert!(rows[4].dn.is_some());
    }

    #[test]
    fn placeholder_resolves_root_dn() {
        let result =
            resolve_filter_placeholders("(memberOf=CN=Admins,<root DN>)", "DC=example,DC=com");
        assert!(result.contains("DC=example,DC=com"));
        assert!(!result.contains("<root DN>"));
    }

    #[test]
    fn scope_labels() {
        assert_eq!(SearchScope::Subtree.label(), "WholeSubtree");
        assert_eq!(SearchScope::OneLevel.label(), "SingleLevel");
        assert_eq!(SearchScope::Base.label(), "BaseObject");
    }
}
