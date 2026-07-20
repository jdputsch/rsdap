//! Explorer page: lazy-loading LDAP tree (left) + attributes table (right).

use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers};
use ldap3::Scope;
use ratatui::Frame;
use ratatui::layout::Rect;
use tokio::sync::mpsc::Sender;

use super::Page;
use crate::app::{AppMsg, SharedLdap};
use crate::config::{AttrSort, TimeFmt};
use crate::formats::attributes::{format_bin_value, format_value};
use crate::formats::display::{emoji_for_entry, entry_display_name};
use crate::ldap::search::{SearchParams, search_all};
use crate::tui::widgets::tree::{TreeNode, TreeWidget};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Tree,
    Attrs,
}

pub struct ExplorerPage {
    tx: Sender<AppMsg>,
    tree: TreeWidget,
    ldap: Option<SharedLdap>,
    root_dn: Option<String>,
    // Mirror of the relevant ResolvedConfig fields — updated via ConfigChanged.
    page_size: u32,
    emojis: bool,
    format_attrs: bool,
    expand_attrs: bool,
    attr_limit: usize,
    attrsort: AttrSort,
    timefmt: TimeFmt,
    offset: i32,
    /// All (name, values) pairs for the selected entry, unsorted.
    raw_rows: Vec<(String, Vec<String>)>,
    /// DN of the entry currently shown in the attributes panel.
    attr_dn: Option<String>,
    /// Which panel has keyboard focus.
    focus: Focus,
    /// Scroll offset for the attributes list.
    attr_scroll: usize,
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
            expand_attrs: true,
            attr_limit: 20,
            attrsort: AttrSort::None,
            timefmt: TimeFmt::Eu,
            offset: 0,
            raw_rows: Vec::new(),
            attr_dn: None,
            focus: Focus::Tree,
            attr_scroll: 0,
        }
    }

    /// Apply current config values from a ResolvedConfig snapshot.
    pub fn apply_config(&mut self, cfg: &crate::config::ResolvedConfig) {
        self.page_size = cfg.paging;
        self.emojis = cfg.emojis;
        self.format_attrs = cfg.format;
        self.expand_attrs = cfg.expand;
        self.attr_limit = cfg.limit;
        self.attrsort = cfg.attrsort.clone();
        self.timefmt = cfg.timefmt.clone();
        self.offset = cfg.offset;
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
                self.raw_rows.clear();
                self.attr_scroll = 0;
                self.fetch_entry(dn);
            }
        }
    }

    /// Build the display rows from `raw_rows` applying current sort, expand, and limit settings.
    fn display_rows(&self) -> Vec<(String, String)> {
        let mut rows: Vec<(String, Vec<String>)> = self.raw_rows.clone();

        match self.attrsort {
            AttrSort::None => {}
            AttrSort::Asc => rows.sort_by_key(|(n, _)| n.to_lowercase()),
            AttrSort::Desc => rows.sort_by_key(|(b, _)| std::cmp::Reverse(b.to_lowercase())),
        }

        let mut out = Vec::new();
        for (name, vals) in &rows {
            if self.expand_attrs {
                let shown = vals.len().min(self.attr_limit);
                for v in &vals[..shown] {
                    out.push((name.clone(), v.clone()));
                }
                if vals.len() > self.attr_limit {
                    out.push((
                        name.clone(),
                        format!("… {} more values hidden", vals.len() - self.attr_limit),
                    ));
                }
            } else {
                // Collapsed: join all values with " | "
                out.push((name.clone(), vals.join(" | ")));
            }
        }
        out
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
        use ratatui::style::{Color, Modifier, Style};
        use ratatui::text::{Line, Span};
        use ratatui::widgets::{Block, Borders, List, ListItem};

        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(area);

        // Highlight the focused panel's border.
        let tree_border_style = if self.focus == Focus::Tree {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };
        let attr_border_style = if self.focus == Focus::Attrs {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };

        self.tree
            .render_with_style(frame, chunks[0], "Tree", tree_border_style);

        let title = match &self.attr_dn {
            Some(dn) => format!("Attributes — {dn}"),
            None => "Attributes".to_owned(),
        };

        let display = self.display_rows();
        let visible_height = chunks[1].height.saturating_sub(2) as usize;
        // Clamp scroll to valid range.
        let max_scroll = display.len().saturating_sub(visible_height);
        if self.attr_scroll > max_scroll {
            self.attr_scroll = max_scroll;
        }

        let items: Vec<ListItem> = display
            .iter()
            .skip(self.attr_scroll)
            .take(visible_height)
            .map(|(name, val)| {
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{name}: "), Style::default().fg(Color::Cyan)),
                    Span::raw(val.clone()),
                ]))
            })
            .collect();

        let attr_block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(attr_border_style);

        // Show a scroll indicator in the title if content exceeds the viewport.
        let list = if display.len() > visible_height {
            List::new(items)
                .block(attr_block)
                .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        } else {
            List::new(items).block(attr_block)
        };
        frame.render_widget(list, chunks[1]);
    }

    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Result<()> {
        match (code, modifiers) {
            (KeyCode::Tab, KeyModifiers::NONE) => {
                self.focus = if self.focus == Focus::Tree {
                    Focus::Attrs
                } else {
                    Focus::Tree
                };
            }
            (KeyCode::BackTab, _) => {
                self.focus = if self.focus == Focus::Attrs {
                    Focus::Tree
                } else {
                    Focus::Attrs
                };
            }
            _ => {}
        }

        match self.focus {
            Focus::Tree => match (code, modifiers) {
                (KeyCode::Down, _) | (KeyCode::Char('j'), KeyModifiers::NONE) => {
                    self.tree.select_next();
                    self.on_selection_change();
                }
                (KeyCode::Up, _) | (KeyCode::Char('k'), KeyModifiers::NONE) => {
                    self.tree.select_prev();
                    self.on_selection_change();
                }
                (KeyCode::Right, _) | (KeyCode::Enter, _) => {
                    if let Some(dn) = self.tree.expand_selected() {
                        self.load_children(dn);
                    }
                    self.on_selection_change();
                }
                (KeyCode::Left, _) => {
                    self.tree.collapse_selected();
                }
                (KeyCode::Char('r'), KeyModifiers::NONE) => {
                    if let Some(node) = self.tree.selected_node() {
                        let dn = node.id.clone();
                        self.tree.set_children(&dn, Vec::new());
                        if let Some(n) = self.tree.nodes.iter_mut().find(|n| n.id == dn) {
                            n.children_loaded = false;
                            n.expanded = false;
                        }
                        self.load_children(dn.clone());
                        self.attr_dn = None;
                        self.raw_rows.clear();
                        self.attr_scroll = 0;
                        self.fetch_entry(dn);
                    }
                }
                _ => {}
            },
            Focus::Attrs => match (code, modifiers) {
                (KeyCode::Down, _) | (KeyCode::Char('j'), KeyModifiers::NONE) => {
                    let display_len = self.display_rows().len();
                    if self.attr_scroll + 1 < display_len {
                        self.attr_scroll += 1;
                    }
                }
                (KeyCode::Up, _) | (KeyCode::Char('k'), KeyModifiers::NONE) => {
                    self.attr_scroll = self.attr_scroll.saturating_sub(1);
                }
                _ => {}
            },
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
                self.attr_dn = Some(root_dn.clone());
                self.attr_scroll = 0;
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
                if self.attr_dn.as_deref() != Some(&entry.dn) {
                    return;
                }

                let fmt = &self.timefmt.clone();
                let offset = self.offset;
                let do_format = self.format_attrs;

                let mut rows: Vec<(String, Vec<String>)> = Vec::new();

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

                let mut bin_names: Vec<&String> = entry.bin_attrs.keys().collect();
                bin_names.sort_by_key(|s| s.to_lowercase());
                for name in bin_names {
                    let vals = &entry.bin_attrs[name];
                    let formatted: Vec<String> =
                        vals.iter().map(|b| format_bin_value(name, b)).collect();
                    rows.push((name.clone(), formatted));
                }

                // Store raw (alphabetically pre-sorted); display_rows applies attrsort.
                rows.sort_by_key(|a| a.0.to_lowercase());
                self.raw_rows = rows;
                self.attr_scroll = 0;
            }

            AppMsg::ConfigChanged(cfg) => {
                self.apply_config(&cfg);
                // raw_rows stay valid; display_rows() re-applies the updated settings on next render.
            }

            _ => {}
        }
    }
}
