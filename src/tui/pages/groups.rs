//! Groups page: group-member lookup (left) and object group-membership lookup (right).

use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ldap3::Scope;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use tokio::sync::mpsc::Sender;

use super::Page;
use crate::app::{AppMsg, SharedLdap, Truncation};
use crate::ldap::BackendFlavor;

// ── Focus ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    GroupInput,
    ObjectInput,
    Members,
    ObjectGroups,
}

// ── Collapsible member tree ───────────────────────────────────────────────────

/// A node in the flat member tree.
#[derive(Debug, Clone)]
enum MemberNode {
    /// An intermediate path segment (domain root, OU, etc.).
    PathSegment {
        label: String,
        depth: usize,
        expanded: bool,
    },
    /// A matched group object with its full DN, member list, and expanded state.
    Group {
        dn: String,
        /// Display label = the full DN without the cn= prefix, e.g. `cn=c_66994 (316 members)`.
        label: String,
        depth: usize,
        members: Vec<String>,
        expanded: bool,
    },
    /// A single member entry (leaf, never expanded).
    Member { name: String, depth: usize },
}

impl MemberNode {
    fn depth(&self) -> usize {
        match self {
            MemberNode::PathSegment { depth, .. }
            | MemberNode::Group { depth, .. }
            | MemberNode::Member { depth, .. } => *depth,
        }
    }

    fn is_expanded(&self) -> bool {
        match self {
            MemberNode::PathSegment { expanded, .. } | MemberNode::Group { expanded, .. } => {
                *expanded
            }
            MemberNode::Member { .. } => false,
        }
    }

    fn toggle_expanded(&mut self) {
        match self {
            MemberNode::PathSegment { expanded, .. } | MemberNode::Group { expanded, .. } => {
                *expanded = !*expanded;
            }
            MemberNode::Member { .. } => {}
        }
    }

    fn has_children(&self) -> bool {
        match self {
            MemberNode::PathSegment { .. } => true,
            MemberNode::Group { members, .. } => !members.is_empty(),
            MemberNode::Member { .. } => false,
        }
    }
}

/// Build the flat node list from `(dn, member_names)` entries and a root_dn label.
///
/// The tree starts fully collapsed.  Path segments come from the DN's OU/DC
/// components; DC components are joined into the root label which matches
/// `root_dn`.
fn build_member_tree(root_dn: &str, entries: &[(String, Vec<String>)]) -> Vec<MemberNode> {
    // Decompose each entry into (ou_path, group_label, members).
    struct Leaf {
        /// Root-first path labels (including the domain root).
        path: Vec<String>,
        dn: String,
        label: String,
        members: Vec<String>,
    }

    let mut leaves: Vec<Leaf> = entries
        .iter()
        .map(|(dn, members)| {
            let parts: Vec<&str> = dn.split(',').collect();

            let cn_val = parts
                .first()
                .and_then(|s| s.split_once('='))
                .map(|(_, v)| v)
                .unwrap_or(dn.as_str());

            let rest = if parts.len() > 1 {
                &parts[1..]
            } else {
                &[] as &[&str]
            };

            // DC components → "dc=analog,dc=com" (keep the full base DN form).
            let dc_parts: Vec<&str> = rest
                .iter()
                .filter(|s| {
                    s.split_once('=')
                        .map(|(k, _)| k.eq_ignore_ascii_case("dc"))
                        .unwrap_or(false)
                })
                .copied()
                .collect();
            let domain_label = if dc_parts.is_empty() {
                root_dn.to_owned()
            } else {
                dc_parts.join(",")
            };

            // OU/other non-DC, non-CN components, deepest-first in DN → reverse for root-first.
            let ou_vals: Vec<String> = rest
                .iter()
                .filter_map(|s| {
                    s.split_once('=')
                        .filter(|(k, _)| {
                            !k.eq_ignore_ascii_case("dc") && !k.eq_ignore_ascii_case("cn")
                        })
                        .map(|(_, v)| v.to_owned())
                })
                .rev()
                .collect();

            // Full path: domain root → OU chain.
            let mut path = vec![domain_label];
            path.extend(ou_vals);

            let label = format!("{cn_val} ({} members)", members.len());

            Leaf {
                path,
                dn: dn.clone(),
                label,
                members: members.clone(),
            }
        })
        .collect();

    // Sort so shared path prefixes are adjacent.
    leaves.sort_by(|a, b| a.path.cmp(&b.path).then(a.dn.cmp(&b.dn)));

    let mut nodes: Vec<MemberNode> = Vec::new();
    let mut prev_path: Vec<String> = Vec::new();

    for leaf in &leaves {
        let path = &leaf.path;

        let common = prev_path
            .iter()
            .zip(path.iter())
            .take_while(|(a, b)| a == b)
            .count();

        // Emit new path-segment nodes.
        for (depth, label) in path.iter().enumerate().skip(common) {
            nodes.push(MemberNode::PathSegment {
                label: label.clone(),
                depth,
                expanded: false,
            });
        }

        // Emit the group node followed by its member children.
        let group_depth = path.len();
        nodes.push(MemberNode::Group {
            dn: leaf.dn.clone(),
            label: leaf.label.clone(),
            depth: group_depth,
            members: leaf.members.clone(),
            expanded: false,
        });
        for name in &leaf.members {
            nodes.push(MemberNode::Member {
                name: name.clone(),
                depth: group_depth + 1,
            });
        }

        prev_path = path.clone();
    }

    nodes
}

/// Compute the list of node indices that are currently visible given the
/// collapsed/expanded state of every node.
fn visible_indices(nodes: &[MemberNode]) -> Vec<usize> {
    let mut visible: Vec<usize> = Vec::new();
    // Stack of (depth, expanded): once we see a collapsed ancestor we skip children.
    // We track the depth of the deepest collapsed ancestor.
    let mut hidden_below: Option<usize> = None;

    for (i, node) in nodes.iter().enumerate() {
        let depth = node.depth();

        // If we were hiding children of a collapsed node, check whether we've
        // left its subtree.
        if let Some(hide_at) = hidden_below {
            if depth <= hide_at {
                hidden_below = None;
            } else {
                continue;
            }
        }

        visible.push(i);

        // If this node has children and is collapsed, hide everything deeper.
        if node.has_children() && !node.is_expanded() {
            hidden_below = Some(depth);
        }
    }
    visible
}

// ── AD range retrieval ────────────────────────────────────────────────────────

/// Fetch all `member` DNs from a single group DN using AD range retrieval.
///
/// AD caps `member` at 1500 per response and returns the attribute as
/// `member;range=0-1499` instead of `member`.  We loop issuing Base-scope
/// searches requesting successive ranges until the server responds with a key
/// ending in `;range=<N>-*`, which signals the last page.
async fn fetch_members_ranged(ldap: &mut ldap3::Ldap, group_dn: &str) -> Vec<String> {
    let mut all: Vec<String> = Vec::new();
    let mut low: usize = 0;

    loop {
        let attr_name = format!("member;range={low}-*");
        let res = ldap
            .search(
                group_dn,
                Scope::Base,
                "(objectClass=*)",
                vec![attr_name.as_str()],
            )
            .await;

        let entries = match res {
            Ok(r) => r.0,
            Err(_) => break,
        };

        let mut last_page = false;
        let mut high: usize = low;

        for raw in entries {
            let entry = ldap3::SearchEntry::construct(raw);
            for (key, vals) in &entry.attrs {
                let key_lc = key.to_ascii_lowercase();
                if !key_lc.starts_with("member;range=") {
                    continue;
                }
                if let Some(range_part) = key_lc.strip_prefix("member;range=") {
                    if let Some((_, hi)) = range_part.split_once('-') {
                        if hi == "*" {
                            last_page = true;
                        } else if let Ok(n) = hi.parse::<usize>() {
                            high = n;
                        }
                    }
                }
                all.extend(vals.iter().cloned());
            }
        }

        if last_page || high <= low {
            break;
        }
        low = high + 1;
    }

    all
}

// ── GroupsPage ────────────────────────────────────────────────────────────────

pub struct GroupsPage {
    tx: Sender<AppMsg>,
    ldap: Option<SharedLdap>,
    flavor: BackendFlavor,
    root_dn: String,
    attrsort: crate::config::AttrSort,

    // Input fields.
    group_input: String,
    object_input: String,

    // Group-members collapsible tree.
    member_nodes: Vec<MemberNode>,
    members_state: ListState,
    members_truncation: Truncation,
    /// Total number of top-level group entries (for the title count).
    group_count: usize,

    // Object-groups results.
    object_groups: Vec<String>,
    object_groups_state: ListState,
    object_groups_truncation: Truncation,

    focus: Focus,

    // Bounding rects updated each render for mouse hit-testing.
    group_input_rect: Rect,
    object_input_rect: Rect,
    members_rect: Rect,
    object_groups_rect: Rect,
}

impl GroupsPage {
    pub fn new(tx: Sender<AppMsg>) -> Self {
        Self {
            tx,
            ldap: None,
            flavor: BackendFlavor::Auto,
            root_dn: String::new(),
            attrsort: crate::config::AttrSort::None,
            group_input: String::new(),
            object_input: String::new(),
            member_nodes: Vec::new(),
            members_state: ListState::default(),
            members_truncation: Truncation::None,
            group_count: 0,
            object_groups: Vec::new(),
            object_groups_state: ListState::default(),
            object_groups_truncation: Truncation::None,
            focus: Focus::GroupInput,
            group_input_rect: Rect::default(),
            object_input_rect: Rect::default(),
            members_rect: Rect::default(),
            object_groups_rect: Rect::default(),
        }
    }

    // ── LDAP queries ──────────────────────────────────────────────────────────

    /// Fetch all group objects matching `group_input`, returning members per group.
    fn fire_group_lookup(&self) {
        let Some(ldap) = self.ldap.clone() else {
            return;
        };
        let raw = self.group_input.trim().to_owned();
        if raw.is_empty() {
            return;
        }
        let tx = self.tx.clone();
        let flavor = self.flavor.clone();
        let base = self.root_dn.clone();
        tokio::spawn(async move {
            let filter = if raw.starts_with('(') {
                raw.clone()
            } else {
                match flavor {
                    BackendFlavor::MsAd => {
                        format!(
                            "(&(objectCategory=group)(|(displayName={raw})(cn={raw})(sAMAccountName={raw})))"
                        )
                    }
                    _ => format!(
                        "(&(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))(|(cn={raw})(uid={raw})))"
                    ),
                }
            };

            let mut guard = ldap.lock().await;
            let res = guard
                .inner
                .search(
                    &base,
                    Scope::Subtree,
                    &filter,
                    vec!["member", "memberUid", "member;range=0-*"],
                )
                .await;

            let (raw_entries, rc) = match res {
                Ok(r) => {
                    let rc = r.1.rc;
                    (r.0, rc)
                }
                Err(e) => {
                    let _ = tx.send(AppMsg::Error(e.to_string())).await;
                    let _ = tx
                        .send(AppMsg::GroupMembers {
                            entries: vec![],
                            truncation: Truncation::None,
                        })
                        .await;
                    return;
                }
            };

            let truncation = match rc {
                0 => Truncation::None,
                4 => Truncation::SizeLimit,
                11 => Truncation::AdminLimit,
                _ => {
                    let _ = tx.send(AppMsg::Error(format!("LDAP error {rc}"))).await;
                    let _ = tx
                        .send(AppMsg::GroupMembers {
                            entries: vec![],
                            truncation: Truncation::None,
                        })
                        .await;
                    return;
                }
            };

            // Collect (dn, member_names) for every matching group.
            // For AD, the server may return `member;range=0-1499` instead of
            // `member` when the group has more than 1500 members. Detect that
            // and use ranged Base-scope fetches to retrieve all pages.
            let mut entries: Vec<(String, Vec<String>)> = Vec::new();
            for re in raw_entries {
                let entry = ldap3::SearchEntry::construct(re);

                let has_ranged = entry
                    .attrs
                    .keys()
                    .any(|k| k.to_ascii_lowercase().starts_with("member;range="));

                let names: Vec<String> = if has_ranged {
                    let raw_dns = fetch_members_ranged(&mut guard.inner, &entry.dn).await;
                    raw_dns.into_iter().map(|dn| rdn_value(&dn)).collect()
                } else {
                    let mut n: Vec<String> = Vec::new();
                    if let Some(vals) = entry.attrs.get("member") {
                        n.extend(vals.iter().map(|dn| rdn_value(dn)));
                    }
                    if let Some(vals) = entry.attrs.get("memberUid") {
                        n.extend(vals.iter().cloned());
                    }
                    n
                };

                entries.push((entry.dn, names));
            }

            let group_count = entries.len();
            let total_members: usize = entries.iter().map(|(_, m)| m.len()).sum();
            let log = match truncation {
                Truncation::None => format!(
                    "Found {group_count} groups named '{raw}' ({total_members} total members)"
                ),
                Truncation::SizeLimit => format!(
                    "Found {group_count} groups named '{raw}' (size limit — may be incomplete)"
                ),
                Truncation::AdminLimit => format!(
                    "Found {group_count} groups named '{raw}' (admin limit — results incomplete)"
                ),
            };
            let _ = tx.send(AppMsg::Log(log)).await;
            let _ = tx
                .send(AppMsg::GroupMembers {
                    entries,
                    truncation,
                })
                .await;
        });
    }

    /// Fetch all groups the object identified by `object_input` belongs to.
    fn fire_object_lookup(&self) {
        let Some(ldap) = self.ldap.clone() else {
            return;
        };
        let raw = self.object_input.trim().to_owned();
        if raw.is_empty() {
            return;
        }
        let tx = self.tx.clone();
        let flavor = self.flavor.clone();
        let base = self.root_dn.clone();
        tokio::spawn(async move {
            let mut guard = ldap.lock().await;

            let groups = match flavor {
                BackendFlavor::MsAd => {
                    let filter = if raw.starts_with('(') {
                        raw.clone()
                    } else {
                        format!("(sAMAccountName={raw})")
                    };
                    let res = guard
                        .inner
                        .search(&base, Scope::Subtree, &filter, vec!["memberOf"])
                        .await;
                    match res {
                        Err(e) => {
                            let _ = tx.send(AppMsg::Error(e.to_string())).await;
                            let _ = tx
                                .send(AppMsg::ObjectGroups {
                                    groups: vec![],
                                    truncation: Truncation::None,
                                })
                                .await;
                            return;
                        }
                        Ok(r) => {
                            let rc = r.1.rc;
                            let truncation = match rc {
                                0 => Truncation::None,
                                4 => Truncation::SizeLimit,
                                11 => Truncation::AdminLimit,
                                _ => {
                                    let _ =
                                        tx.send(AppMsg::Error(format!("LDAP error {rc}"))).await;
                                    let _ = tx
                                        .send(AppMsg::ObjectGroups {
                                            groups: vec![],
                                            truncation: Truncation::None,
                                        })
                                        .await;
                                    return;
                                }
                            };
                            let mut groups = Vec::new();
                            for raw_entry in r.0 {
                                let entry = ldap3::SearchEntry::construct(raw_entry);
                                if let Some(vals) = entry.attrs.get("memberOf") {
                                    for dn in vals {
                                        groups.push(rdn_value(dn));
                                    }
                                }
                                if !groups.is_empty() {
                                    break;
                                }
                            }
                            (groups, truncation)
                        }
                    }
                }
                _ => {
                    let obj_filter = if raw.starts_with('(') {
                        raw.clone()
                    } else {
                        format!("(|(cn={raw})(uid={raw}))")
                    };
                    let dn_res = guard
                        .inner
                        .search(&base, Scope::Subtree, &obj_filter, vec!["dn"])
                        .await;
                    let object_dn = match dn_res {
                        Ok(r) => {
                            r.0.into_iter()
                                .next()
                                .map(|e| ldap3::SearchEntry::construct(e).dn)
                        }
                        Err(_) => None,
                    };

                    let group_filter = if let Some(ref dn) = object_dn {
                        format!(
                            "(&(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))(|(memberUid={raw})(member={dn})))"
                        )
                    } else {
                        format!(
                            "(&(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))(memberUid={raw}))"
                        )
                    };

                    let res = guard
                        .inner
                        .search(&base, Scope::Subtree, &group_filter, vec!["cn"])
                        .await;
                    match res {
                        Err(e) => {
                            let _ = tx.send(AppMsg::Error(e.to_string())).await;
                            let _ = tx
                                .send(AppMsg::ObjectGroups {
                                    groups: vec![],
                                    truncation: Truncation::None,
                                })
                                .await;
                            return;
                        }
                        Ok(r) => {
                            let rc = r.1.rc;
                            let truncation = match rc {
                                0 => Truncation::None,
                                4 => Truncation::SizeLimit,
                                11 => Truncation::AdminLimit,
                                _ => {
                                    let _ =
                                        tx.send(AppMsg::Error(format!("LDAP error {rc}"))).await;
                                    let _ = tx
                                        .send(AppMsg::ObjectGroups {
                                            groups: vec![],
                                            truncation: Truncation::None,
                                        })
                                        .await;
                                    return;
                                }
                            };
                            let groups: Vec<String> =
                                r.0.into_iter()
                                    .map(|e| {
                                        let entry = ldap3::SearchEntry::construct(e);
                                        entry
                                            .attrs
                                            .get("cn")
                                            .and_then(|v| v.first())
                                            .cloned()
                                            .unwrap_or_else(|| rdn_value(&entry.dn))
                                    })
                                    .collect();
                            (groups, truncation)
                        }
                    }
                }
            };

            let (groups, truncation) = groups;
            let count = groups.len();
            let log = match truncation {
                Truncation::None => format!("Found {count} groups for '{raw}'"),
                Truncation::SizeLimit => {
                    format!("Found {count} groups for '{raw}' (size limit — may be incomplete)")
                }
                Truncation::AdminLimit => format!(
                    "Found {count} groups for '{raw}' (admin limit exceeded — results incomplete)"
                ),
            };
            let _ = tx.send(AppMsg::Log(log)).await;
            let _ = tx.send(AppMsg::ObjectGroups { groups, truncation }).await;
        });
    }

    // ── Member tree navigation ────────────────────────────────────────────────

    /// Move cursor to the next visible row.
    fn members_next(&mut self) {
        let vis = visible_indices(&self.member_nodes);
        if vis.is_empty() {
            return;
        }
        let cur = self.members_state.selected().unwrap_or(0);
        let next_pos = vis
            .iter()
            .position(|&i| i == cur)
            .map_or(0, |p| (p + 1).min(vis.len() - 1));
        self.members_state.select(Some(vis[next_pos]));
    }

    /// Move cursor to the previous visible row.
    fn members_prev(&mut self) {
        let vis = visible_indices(&self.member_nodes);
        if vis.is_empty() {
            return;
        }
        let cur = self.members_state.selected().unwrap_or(0);
        let prev_pos = vis
            .iter()
            .position(|&i| i == cur)
            .map_or(0, |p| p.saturating_sub(1));
        self.members_state.select(Some(vis[prev_pos]));
    }

    /// Expand the currently selected node.
    fn members_expand(&mut self) {
        if let Some(sel) = self.members_state.selected() {
            if let Some(node) = self.member_nodes.get_mut(sel) {
                if node.has_children() && !node.is_expanded() {
                    node.toggle_expanded();
                }
            }
        }
    }

    /// Collapse the currently selected node (or its parent if already collapsed).
    fn members_collapse(&mut self) {
        if let Some(sel) = self.members_state.selected() {
            if let Some(node) = self.member_nodes.get_mut(sel) {
                if node.is_expanded() {
                    node.toggle_expanded();
                    return;
                }
            }
            // Move to parent (first node with depth < current).
            let depth = self.member_nodes[sel].depth();
            if depth == 0 {
                return;
            }
            let parent = (0..sel)
                .rev()
                .find(|&i| self.member_nodes[i].depth() < depth);
            if let Some(p) = parent {
                self.members_state.select(Some(p));
            }
        }
    }

    /// Toggle expand/collapse on the selected node.
    fn members_toggle(&mut self) {
        if let Some(sel) = self.members_state.selected() {
            if let Some(node) = self.member_nodes.get_mut(sel) {
                if node.has_children() {
                    node.toggle_expanded();
                }
            }
        }
    }

    fn members_click(&mut self, row: u16) {
        let r = self.members_rect;
        if row < r.y + 1 || row >= r.y + r.height {
            return;
        }
        let content_row = (row - r.y - 1) as usize;
        let vis = visible_indices(&self.member_nodes);
        let offset = *self.members_state.offset_mut();
        let idx_in_vis = offset + content_row;
        if let Some(&node_idx) = vis.get(idx_in_vis) {
            self.members_state.select(Some(node_idx));
        }
    }

    // ── Object groups navigation ──────────────────────────────────────────────

    fn object_groups_next(&mut self) {
        if self.object_groups.is_empty() {
            return;
        }
        let next = match self.object_groups_state.selected() {
            Some(i) => (i + 1).min(self.object_groups.len() - 1),
            None => 0,
        };
        self.object_groups_state.select(Some(next));
    }

    fn object_groups_prev(&mut self) {
        if self.object_groups.is_empty() {
            return;
        }
        let prev = match self.object_groups_state.selected() {
            Some(0) | None => 0,
            Some(i) => i - 1,
        };
        self.object_groups_state.select(Some(prev));
    }

    fn object_groups_click(&mut self, row: u16) {
        let r = self.object_groups_rect;
        if row < r.y + 1 || row >= r.y + r.height {
            return;
        }
        let content_row = (row - r.y - 1) as usize;
        let offset = self.object_groups_state.offset();
        let idx = offset + content_row;
        if idx < self.object_groups.len() {
            self.object_groups_state.select(Some(idx));
        }
    }
}

impl Page for GroupsPage {
    fn title(&self) -> &str {
        "Groups"
    }

    fn captures_input(&self) -> bool {
        matches!(self.focus, Focus::GroupInput | Focus::ObjectInput)
    }

    fn render(&mut self, frame: &mut Frame<'_>, area: Rect) {
        // ── Layout ────────────────────────────────────────────────────────────
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0)])
            .split(area);

        let input_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rows[0]);

        let result_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rows[1]);

        self.group_input_rect = input_cols[0];
        self.object_input_rect = input_cols[1];
        self.members_rect = result_cols[0];
        self.object_groups_rect = result_cols[1];

        // ── Group input ───────────────────────────────────────────────────────
        let group_border = if self.focus == Focus::GroupInput {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };
        let group_content = if self.group_input.is_empty() && self.focus != Focus::GroupInput {
            Span::styled(
                "Type a group cn or sAMAccountName",
                Style::default().fg(Color::DarkGray),
            )
        } else {
            Span::raw(self.group_input.clone())
        };
        frame.render_widget(
            Paragraph::new(Line::from(group_content)).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Group")
                    .border_style(group_border),
            ),
            input_cols[0],
        );

        // ── Object input ──────────────────────────────────────────────────────
        let object_border = if self.focus == Focus::ObjectInput {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };
        let object_content = if self.object_input.is_empty() && self.focus != Focus::ObjectInput {
            Span::styled(
                "Type an object's sAMAccountName or DN",
                Style::default().fg(Color::DarkGray),
            )
        } else {
            Span::raw(self.object_input.clone())
        };
        frame.render_widget(
            Paragraph::new(Line::from(object_content)).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Object")
                    .border_style(object_border),
            ),
            input_cols[1],
        );

        // ── Members tree ──────────────────────────────────────────────────────
        let members_title = match self.members_truncation {
            Truncation::AdminLimit => {
                format!("Group Members ({} groups) [ADMIN LIMIT]", self.group_count)
            }
            Truncation::SizeLimit => {
                format!("Group Members ({} groups) [truncated]", self.group_count)
            }
            Truncation::None => format!("Group Members ({} groups)", self.group_count),
        };
        let members_border = match self.members_truncation {
            Truncation::AdminLimit => Style::default().fg(Color::Red),
            Truncation::SizeLimit => Style::default().fg(Color::Yellow),
            _ if self.focus == Focus::Members => Style::default().fg(Color::Yellow),
            _ => Style::default(),
        };

        let vis = visible_indices(&self.member_nodes);
        let selected_node = self.members_state.selected();

        // Map visible node indices → ListItems.
        let member_items: Vec<ListItem> = vis
            .iter()
            .map(|&ni| {
                let node = &self.member_nodes[ni];
                let indent = "  ".repeat(node.depth());
                let (prefix, label_str) = match node {
                    MemberNode::PathSegment {
                        label, expanded, ..
                    } => {
                        let arrow = if *expanded { "▼ " } else { "▶ " };
                        (arrow, label.as_str())
                    }
                    MemberNode::Group {
                        label, expanded, ..
                    } => {
                        let arrow = if *expanded { "▼ " } else { "▶ " };
                        (arrow, label.as_str())
                    }
                    MemberNode::Member { name, .. } => ("  ", name.as_str()),
                };
                let selected = selected_node == Some(ni);
                let style = if selected {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                ListItem::new(Line::from(Span::styled(
                    format!("{indent}{prefix}{label_str}"),
                    style,
                )))
            })
            .collect();

        // Build a synthetic ListState that maps visible-list position → selected.
        let vis_pos = selected_node.and_then(|sel| vis.iter().position(|&i| i == sel));
        let mut vis_state = ListState::default();
        vis_state.select(vis_pos);

        let members_list = List::new(member_items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(members_title)
                .border_style(members_border),
        );
        frame.render_stateful_widget(members_list, result_cols[0], &mut vis_state);

        // Sync the scroll offset back so clicks stay accurate.
        *self.members_state.offset_mut() = *vis_state.offset_mut();

        // ── Object groups list ────────────────────────────────────────────────
        let og_count = self.object_groups.len();
        let og_title = match self.object_groups_truncation {
            Truncation::AdminLimit => {
                format!("Object Groups ({og_count}) [ADMIN LIMIT — incomplete]")
            }
            Truncation::SizeLimit => format!("Object Groups ({og_count}) [truncated]"),
            Truncation::None => format!("Object Groups ({og_count})"),
        };
        let og_border = match self.object_groups_truncation {
            Truncation::AdminLimit => Style::default().fg(Color::Red),
            Truncation::SizeLimit => Style::default().fg(Color::Yellow),
            _ if self.focus == Focus::ObjectGroups => Style::default().fg(Color::Yellow),
            _ => Style::default(),
        };
        let og_items: Vec<ListItem> = self
            .object_groups
            .iter()
            .map(|g| ListItem::new(Span::raw(g.clone())))
            .collect();
        let og_list = List::new(og_items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(og_title)
                    .border_style(og_border),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );
        frame.render_stateful_widget(og_list, result_cols[1], &mut self.object_groups_state);
    }

    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Result<()> {
        match (code, modifiers) {
            (KeyCode::Tab, KeyModifiers::NONE) => {
                self.focus = match self.focus {
                    Focus::GroupInput => Focus::ObjectInput,
                    Focus::ObjectInput => Focus::Members,
                    Focus::Members => Focus::ObjectGroups,
                    Focus::ObjectGroups => Focus::GroupInput,
                };
                return Ok(());
            }
            (KeyCode::BackTab, _) => {
                self.focus = match self.focus {
                    Focus::GroupInput => Focus::ObjectGroups,
                    Focus::ObjectInput => Focus::GroupInput,
                    Focus::Members => Focus::ObjectInput,
                    Focus::ObjectGroups => Focus::Members,
                };
                return Ok(());
            }
            _ => {}
        }

        match self.focus {
            Focus::GroupInput => match (code, modifiers) {
                (KeyCode::Enter, _) => {
                    self.member_nodes.clear();
                    self.members_state = ListState::default();
                    self.members_truncation = Truncation::None;
                    self.group_count = 0;
                    self.fire_group_lookup();
                }
                (KeyCode::Backspace, _) => {
                    self.group_input.pop();
                }
                (KeyCode::Char(ch), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                    self.group_input.push(ch);
                }
                (KeyCode::Esc, _) => self.focus = Focus::Members,
                _ => {}
            },

            Focus::ObjectInput => match (code, modifiers) {
                (KeyCode::Enter, _) => {
                    self.object_groups.clear();
                    self.object_groups_state = ListState::default();
                    self.object_groups_truncation = Truncation::None;
                    self.fire_object_lookup();
                }
                (KeyCode::Backspace, _) => {
                    self.object_input.pop();
                }
                (KeyCode::Char(ch), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                    self.object_input.push(ch);
                }
                (KeyCode::Esc, _) => self.focus = Focus::ObjectGroups,
                _ => {}
            },

            Focus::Members => match (code, modifiers) {
                (KeyCode::Down, _) | (KeyCode::Char('j'), KeyModifiers::NONE) => {
                    self.members_next();
                }
                (KeyCode::Up, _) | (KeyCode::Char('k'), KeyModifiers::NONE) => {
                    self.members_prev();
                }
                (KeyCode::Right, _) | (KeyCode::Enter, _) => {
                    self.members_expand();
                }
                (KeyCode::Left, _) => {
                    self.members_collapse();
                }
                (KeyCode::Char(' '), _) => {
                    self.members_toggle();
                }
                _ => {}
            },

            Focus::ObjectGroups => match (code, modifiers) {
                (KeyCode::Down, _) | (KeyCode::Char('j'), KeyModifiers::NONE) => {
                    self.object_groups_next();
                }
                (KeyCode::Up, _) | (KeyCode::Char('k'), KeyModifiers::NONE) => {
                    self.object_groups_prev();
                }
                _ => {}
            },
        }
        Ok(())
    }

    fn handle_mouse(&mut self, event: MouseEvent) {
        let (col, row) = (event.column, event.row);
        let in_rect =
            |r: Rect| col >= r.x && col < r.x + r.width && row >= r.y && row < r.y + r.height;

        match event.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if in_rect(self.group_input_rect) {
                    self.focus = Focus::GroupInput;
                } else if in_rect(self.object_input_rect) {
                    self.focus = Focus::ObjectInput;
                } else if in_rect(self.members_rect) {
                    self.focus = Focus::Members;
                    self.members_click(row);
                } else if in_rect(self.object_groups_rect) {
                    self.focus = Focus::ObjectGroups;
                    self.object_groups_click(row);
                }
            }
            MouseEventKind::ScrollDown => {
                if in_rect(self.members_rect) {
                    self.members_next();
                } else if in_rect(self.object_groups_rect) {
                    self.object_groups_next();
                }
            }
            MouseEventKind::ScrollUp => {
                if in_rect(self.members_rect) {
                    self.members_prev();
                } else if in_rect(self.object_groups_rect) {
                    self.object_groups_prev();
                }
            }
            _ => {}
        }
    }

    fn apply_msg(&mut self, msg: AppMsg) {
        match msg {
            AppMsg::Connected {
                client,
                flavor,
                root_dn,
                ..
            } => {
                self.ldap = Some(client);
                self.flavor = flavor;
                self.root_dn = root_dn;
            }
            AppMsg::ConfigChanged(cfg) => {
                if cfg.backend != BackendFlavor::Auto {
                    self.flavor = cfg.backend.clone();
                }
                self.attrsort = cfg.attrsort.clone();
            }
            AppMsg::GroupMembers {
                mut entries,
                truncation,
            } => {
                // Sort member name lists within each group according to attrsort.
                for (_, members) in &mut entries {
                    match self.attrsort {
                        crate::config::AttrSort::Asc => members.sort(),
                        crate::config::AttrSort::Desc => {
                            members.sort();
                            members.reverse();
                        }
                        crate::config::AttrSort::None => {}
                    }
                }
                self.group_count = entries.len();
                self.member_nodes = build_member_tree(&self.root_dn, &entries);
                self.members_state = ListState::default();
                self.members_truncation = truncation;
                // Select the first visible node (the root path segment).
                let vis = visible_indices(&self.member_nodes);
                if let Some(&first) = vis.first() {
                    self.members_state.select(Some(first));
                }
            }
            AppMsg::ObjectGroups {
                mut groups,
                truncation,
            } => {
                match self.attrsort {
                    crate::config::AttrSort::Asc => groups.sort(),
                    crate::config::AttrSort::Desc => {
                        groups.sort();
                        groups.reverse();
                    }
                    crate::config::AttrSort::None => {}
                }
                self.object_groups = groups;
                self.object_groups_state = ListState::default();
                self.object_groups_truncation = truncation;
                if !self.object_groups.is_empty() {
                    self.object_groups_state.select(Some(0));
                }
            }
            _ => {}
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract the value from the first RDN of a DN, e.g. `CN=Alice,OU=...` → `Alice`.
/// Extract the value of the first RDN component from a DN, unescaping LDAP
/// backslash sequences.  `CN=Last\, First,OU=...` → `"Last, First"`.
fn rdn_value(dn: &str) -> String {
    // Find the first '=' to separate the attribute type from the value.
    let value_start = match dn.find('=') {
        Some(i) => i + 1,
        None => return dn.to_owned(),
    };
    let rest = &dn[value_start..];

    // Walk `rest` to find the first unescaped ',', building the unescaped value.
    let mut out = String::with_capacity(rest.len());
    let mut chars = rest.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            // Consume the next char as a literal (strip the escape).
            // Two consecutive backslashes → one backslash.
            if let Some(next) = chars.next() {
                out.push(next);
            }
        } else if ch == ',' {
            // First unescaped comma ends this RDN.
            break;
        } else {
            out.push(ch);
        }
    }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn names(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("user{i}")).collect()
    }

    #[test]
    fn tree_collapsed_single_group() {
        let entries = vec![(
            "cn=c_66994,ou=Groups,ou=nis,dc=analog,dc=com".to_owned(),
            names(5),
        )];
        let nodes = build_member_tree("dc=analog,dc=com", &entries);
        // All nodes start collapsed — only the root path segment should be visible.
        let vis = visible_indices(&nodes);
        assert_eq!(vis.len(), 1);
        // Root label matches the base DN.
        match &nodes[vis[0]] {
            MemberNode::PathSegment { label, .. } => {
                assert_eq!(label, "dc=analog,dc=com");
            }
            other => panic!("expected PathSegment, got {other:?}"),
        }
    }

    #[test]
    fn tree_expand_root_shows_next_level() {
        let entries = vec![(
            "cn=c_66994,ou=Groups,ou=nis,dc=analog,dc=com".to_owned(),
            names(3),
        )];
        let mut nodes = build_member_tree("dc=analog,dc=com", &entries);
        // Expand root.
        nodes[0].toggle_expanded();
        let vis = visible_indices(&nodes);
        // Root + first child (nis) should be visible.
        assert_eq!(vis.len(), 2);
    }

    #[test]
    fn tree_full_expand_shows_members() {
        let entries = vec![(
            "cn=g,ou=Groups,ou=nis,dc=analog,dc=com".to_owned(),
            names(2),
        )];
        let mut nodes = build_member_tree("dc=analog,dc=com", &entries);
        // Expand all expandable nodes.
        for node in &mut nodes {
            if node.has_children() {
                node.toggle_expanded();
            }
        }
        let vis = visible_indices(&nodes);
        // dc=analog,dc=com / nis / Groups / g (2 members) / user0 / user1
        assert_eq!(vis.len(), 6);
        let member_labels: Vec<&str> = vis
            .iter()
            .filter_map(|&i| match &nodes[i] {
                MemberNode::Member { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(member_labels, &["user0", "user1"]);
    }

    #[test]
    fn tree_shared_prefix_one_root_node() {
        let entries = vec![
            (
                "cn=g1,ou=Groups,ou=nis,dc=analog,dc=com".to_owned(),
                names(1),
            ),
            (
                "cn=g2,ou=Groups,ou=nis,dc=analog,dc=com".to_owned(),
                names(2),
            ),
        ];
        let nodes = build_member_tree("dc=analog,dc=com", &entries);
        // Only one root path segment for the shared "dc=analog,dc=com".
        let root_count = nodes
            .iter()
            .filter(|n| matches!(n, MemberNode::PathSegment { depth: 0, .. }))
            .count();
        assert_eq!(root_count, 1);
    }

    #[test]
    fn rdn_value_plain() {
        assert_eq!(rdn_value("CN=Alice,OU=Users,DC=corp,DC=com"), "Alice");
    }

    #[test]
    fn rdn_value_escaped_comma() {
        // CN=Last\, First  →  "Last, First"
        assert_eq!(
            rdn_value(r"CN=Last\, First,OU=Users,DC=corp,DC=com"),
            "Last, First"
        );
    }

    #[test]
    fn rdn_value_double_backslash() {
        // CN=Foo\\Bar  →  "Foo\Bar"
        assert_eq!(rdn_value(r"CN=Foo\\Bar,DC=corp,DC=com"), r"Foo\Bar");
    }

    #[test]
    fn rdn_value_no_comma() {
        // DN with no further components
        assert_eq!(rdn_value("CN=Solo"), "Solo");
    }

    #[test]
    fn ranged_key_detection() {
        // Simulate what ldap3 returns for a ranged AD attribute key.
        let mut attrs: std::collections::HashMap<String, Vec<String>> = Default::default();
        attrs.insert(
            "member;range=0-1499".to_owned(),
            vec!["CN=Alice,DC=corp,DC=com".to_owned()],
        );
        let has_ranged = attrs
            .keys()
            .any(|k| k.to_ascii_lowercase().starts_with("member;range="));
        assert!(has_ranged);

        // Plain "member" key must NOT trigger ranged detection.
        let mut plain: std::collections::HashMap<String, Vec<String>> = Default::default();
        plain.insert(
            "member".to_owned(),
            vec!["CN=Bob,DC=corp,DC=com".to_owned()],
        );
        let no_range = plain
            .keys()
            .any(|k| k.to_ascii_lowercase().starts_with("member;range="));
        assert!(!no_range);
    }
}
