//! Explorer page: lazy-loading LDAP tree (left) + attributes table (right).

use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers};
use ldap3::Scope;
use ratatui::Frame;
use ratatui::layout::Rect;
use tokio::sync::mpsc::Sender;

use super::Page;
use crate::app::{AppMsg, SharedLdap};
use crate::config::TimeFmt;
use crate::formats::attributes::{format_bin_value, format_value};
use crate::formats::display::{emoji_for_entry, entry_display_name};
use crate::ldap::search::{SearchParams, search_all};
use crate::tui::widgets::tree::{TreeNode, TreeWidget};

pub struct ExplorerPage {
    tx: Sender<AppMsg>,
    tree: TreeWidget,
    ldap: Option<SharedLdap>,
    root_dn: Option<String>,
    page_size: u32,
    emojis: bool,
    format_attrs: bool,
    timefmt: TimeFmt,
    offset: i32,
    /// Sorted (name, values) pairs for the attributes panel.
    attr_rows: Vec<(String, Vec<String>)>,
    /// DN of the entry currently shown in the attributes panel.
    attr_dn: Option<String>,
}

impl ExplorerPage {
    pub fn new(tx: Sender<AppMsg>) -> Self {
        Self {
            tx,
            tree: TreeWidget::new(),
            ldap: None,
            root_dn: None,
            page_size: 800,
            emojis: true,
            format_attrs: true,
            timefmt: TimeFmt::Eu,
            offset: 0,
            attr_rows: Vec::new(),
            attr_dn: None,
        }
    }

    /// Fire an async task to load the immediate children of `parent_dn`.
    fn load_children(&self, parent_dn: String) {
        let Some(ldap) = self.ldap.clone() else {
            return;
        };
        let tx = self.tx.clone();
        let page_size = self.page_size;

        tokio::spawn(async move {
            let mut guard = ldap.lock().await;
            let params = SearchParams {
                base: parent_dn.clone(),
                scope: Scope::OneLevel,
                filter: "(objectClass=*)".to_owned(),
                attrs: vec![
                    "objectClass".to_owned(),
                    "cn".to_owned(),
                    "ou".to_owned(),
                    "dc".to_owned(),
                    "name".to_owned(),
                    "uid".to_owned(),
                ],
                page_size,
                include_deleted: false,
            };
            match search_all(&mut guard.inner, &params).await {
                Ok(entries) => {
                    let _ = tx.send(AppMsg::ChildEntries { parent_dn, entries }).await;
                }
                Err(e) => {
                    let _ = tx.send(AppMsg::Error(e.to_string())).await;
                }
            }
        });
    }

    /// Fire an async task to fetch all attributes for `dn` (Base scope, all attrs).
    fn fetch_entry(&self, dn: String) {
        let Some(ldap) = self.ldap.clone() else {
            return;
        };
        let tx = self.tx.clone();

        tokio::spawn(async move {
            let mut guard = ldap.lock().await;
            // "*" = all user attributes; "+" = operational attributes
            let result = guard
                .inner
                .search(&dn, Scope::Base, "(objectClass=*)", vec!["*", "+"])
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

    fn on_selection_change(&mut self) {
        if let Some(node) = self.tree.selected_node() {
            let dn = node.id.clone();
            if self.attr_dn.as_deref() != Some(&dn) {
                self.attr_dn = Some(dn.clone());
                self.attr_rows.clear();
                self.fetch_entry(dn);
            }
        }
    }
}

impl Page for ExplorerPage {
    fn title(&self) -> &str {
        "Explorer"
    }

    fn captures_input(&self) -> bool {
        false
    }

    fn render(&mut self, frame: &mut Frame<'_>, area: Rect) {
        use ratatui::layout::{Constraint, Direction, Layout};
        use ratatui::style::{Color, Style};
        use ratatui::text::{Line, Span};
        use ratatui::widgets::{Block, Borders, List, ListItem};

        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(area);

        self.tree.render(frame, chunks[0], "Tree");

        let title = match &self.attr_dn {
            Some(dn) => format!("Attributes — {dn}"),
            None => "Attributes".to_owned(),
        };

        let items: Vec<ListItem> = self
            .attr_rows
            .iter()
            .flat_map(|(name, vals)| {
                vals.iter().map(move |v| {
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("{name}: "), Style::default().fg(Color::Cyan)),
                        Span::raw(v.clone()),
                    ]))
                })
            })
            .collect();

        let list = List::new(items).block(Block::default().borders(Borders::ALL).title(title));
        frame.render_widget(list, chunks[1]);
    }

    fn handle_key(&mut self, code: KeyCode, _modifiers: KeyModifiers) -> Result<()> {
        match code {
            KeyCode::Down | KeyCode::Char('j') => {
                self.tree.select_next();
                self.on_selection_change();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.tree.select_prev();
                self.on_selection_change();
            }
            KeyCode::Right | KeyCode::Enter => {
                if let Some(dn) = self.tree.expand_selected() {
                    self.load_children(dn);
                }
                self.on_selection_change();
            }
            KeyCode::Left => {
                self.tree.collapse_selected();
            }
            KeyCode::Char('r') => {
                if let Some(node) = self.tree.selected_node() {
                    let dn = node.id.clone();
                    self.tree.set_children(&dn, Vec::new());
                    if let Some(n) = self.tree.nodes.iter_mut().find(|n| n.id == dn) {
                        n.children_loaded = false;
                        n.expanded = false;
                    }
                    self.load_children(dn.clone());
                    // Re-fetch attributes too.
                    self.attr_dn = None;
                    self.attr_rows.clear();
                    self.fetch_entry(dn);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn apply_msg(&mut self, msg: AppMsg) {
        match msg {
            AppMsg::Connected {
                root_dn, client, ..
            } => {
                self.ldap = Some(client);
                self.root_dn = Some(root_dn.clone());

                self.tree.nodes.clear();
                self.tree.nodes.push(TreeNode {
                    id: root_dn.clone(),
                    label: root_dn.clone(),
                    depth: 0,
                    expanded: true,
                    has_children: true,
                    children_loaded: false,
                });
                self.tree.state.select(Some(0));
                self.load_children(root_dn.clone());
                // Fetch attributes for the root node immediately.
                self.attr_dn = Some(root_dn.clone());
                self.fetch_entry(root_dn);
            }

            AppMsg::ChildEntries { parent_dn, entries } => {
                let emojis = self.emojis;
                let children: Vec<TreeNode> = entries
                    .iter()
                    .map(|e| {
                        let dn = e.dn.clone();
                        let object_classes: Vec<String> =
                            e.attrs.get("objectClass").cloned().unwrap_or_default();
                        let display = entry_display_name(&dn, &e.attrs);
                        let label = if emojis {
                            format!("{} {display}", emoji_for_entry(&object_classes))
                        } else {
                            display
                        };
                        let has_children = object_classes.iter().any(|c| {
                            matches!(
                                c.to_lowercase().as_str(),
                                "organizationalunit"
                                    | "container"
                                    | "domain"
                                    | "dnsdomain"
                                    | "dnszone"
                                    | "configuration"
                                    | "grouppolicycontainer"
                                    | "domainpolicy"
                                    | "builtindomain"
                                    | "samdomainbase"
                            )
                        });
                        let parent_depth = self
                            .tree
                            .nodes
                            .iter()
                            .find(|n| n.id == parent_dn)
                            .map(|n| n.depth)
                            .unwrap_or(0);
                        TreeNode {
                            id: dn,
                            label,
                            depth: parent_depth + 1,
                            expanded: false,
                            has_children,
                            children_loaded: false,
                        }
                    })
                    .collect();

                self.tree.set_children(&parent_dn, children);
            }

            AppMsg::EntryFetched(entry) => {
                // Only update if this is still the selected entry.
                if self.attr_dn.as_deref() != Some(&entry.dn) {
                    return;
                }

                let fmt = &self.timefmt;
                let offset = self.offset;
                let do_format = self.format_attrs;

                let mut rows: Vec<(String, Vec<String>)> = Vec::new();

                // Text attributes — format if requested.
                let mut attr_names: Vec<&String> = entry.attrs.keys().collect();
                attr_names.sort_by_key(|s| s.to_lowercase());
                for name in attr_names {
                    let vals = &entry.attrs[name];
                    let formatted: Vec<String> = vals
                        .iter()
                        .map(|v| {
                            if do_format {
                                format_value(name, v, fmt, offset)
                            } else {
                                v.clone()
                            }
                        })
                        .collect();
                    rows.push((name.clone(), formatted));
                }

                // Binary attributes — always formatted (SID/GUID need byte decoding).
                let mut bin_names: Vec<&String> = entry.bin_attrs.keys().collect();
                bin_names.sort_by_key(|s| s.to_lowercase());
                for name in bin_names {
                    let vals = &entry.bin_attrs[name];
                    let formatted: Vec<String> =
                        vals.iter().map(|b| format_bin_value(name, b)).collect();
                    rows.push((name.clone(), formatted));
                }

                // Re-sort after merging text + binary.
                rows.sort_by_key(|a| a.0.to_lowercase());
                self.attr_rows = rows;
            }

            _ => {}
        }
    }
}
