//! Explorer page: lazy-loading LDAP tree (left) + attributes panel (right).

use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ldap3::Scope;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use tokio::sync::mpsc::Sender;

use super::Page;
use crate::app::{AppMsg, SharedLdap};
use crate::formats::display::entry_display_name;
use crate::ldap::search::{SearchParams, search_all};
use crate::tui::attrs::{AttrConfig, AttrPanel};
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
    attr_cfg: AttrConfig,
    attrs: AttrPanel,
    /// Which panel has keyboard focus.
    focus: Focus,
    /// Bounding rects of the two panels, updated on each render for mouse hit-testing.
    tree_rect: Rect,
    attr_rect: Rect,
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
            attr_cfg: AttrConfig::default(),
            attrs: AttrPanel::default(),
            focus: Focus::Tree,
            tree_rect: Rect::default(),
            attr_rect: Rect::default(),
        }
    }

    /// Apply current config values from a ResolvedConfig snapshot.
    pub fn apply_config(&mut self, cfg: &crate::config::ResolvedConfig) {
        self.page_size = cfg.paging;
        self.emojis = cfg.emojis;
        self.attr_cfg = AttrConfig {
            format_attrs: cfg.format,
            colors: cfg.colors,
            expand_attrs: cfg.expand,
            attr_limit: cfg.limit,
            attrsort: cfg.attrsort.clone(),
            timefmt: cfg.timefmt.clone(),
            offset: cfg.offset,
        };
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
            if self.attrs.selected_dn.as_deref() != Some(&dn) {
                self.attrs.clear();
                self.attrs.selected_dn = Some(dn.clone());
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
        use ratatui::style::Color;

        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(area);

        self.tree_rect = chunks[0];
        self.attr_rect = chunks[1];

        let tree_border_style = if self.focus == Focus::Tree {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };

        self.tree
            .render_with_style(frame, chunks[0], "Tree", tree_border_style, self.emojis);

        let title = match &self.attrs.selected_dn {
            Some(dn) => format!("Attributes — {dn}"),
            None => "Attributes".to_owned(),
        };

        let cfg = self.attr_cfg.clone();
        self.attrs
            .render(frame, chunks[1], &title, self.focus == Focus::Attrs, &cfg);
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
                        self.attrs.clear();
                        self.attrs.selected_dn = Some(dn.clone());
                        self.fetch_entry(dn);
                    }
                }
                _ => {}
            },
            Focus::Attrs => match (code, modifiers) {
                (KeyCode::Down, _) | (KeyCode::Char('j'), KeyModifiers::NONE) => {
                    self.attrs.handle_key(KeyCode::Down);
                }
                (KeyCode::Up, _) | (KeyCode::Char('k'), KeyModifiers::NONE) => {
                    self.attrs.handle_key(KeyCode::Up);
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
                if in_rect(self.tree_rect) {
                    self.focus = Focus::Tree;
                } else if in_rect(self.attr_rect) {
                    self.focus = Focus::Attrs;
                    let cfg = self.attr_cfg.clone();
                    self.attrs.handle_click(col, row, &cfg);
                }
            }
            MouseEventKind::ScrollDown => {
                if in_rect(self.attr_rect) {
                    self.attrs.handle_key(KeyCode::Down);
                } else if in_rect(self.tree_rect) {
                    self.tree.select_next();
                    self.on_selection_change();
                }
            }
            MouseEventKind::ScrollUp => {
                if in_rect(self.attr_rect) {
                    self.attrs.handle_key(KeyCode::Up);
                } else if in_rect(self.tree_rect) {
                    self.tree.select_prev();
                    self.on_selection_change();
                }
            }
            _ => {}
        }
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
                    object_classes: vec!["domain".to_owned()],
                    depth: 0,
                    expanded: true,
                    has_children: true,
                    children_loaded: false,
                });
                self.tree.state.select(Some(0));
                self.load_children(root_dn.clone());
                self.attrs.clear();
                self.attrs.selected_dn = Some(root_dn.clone());
                self.fetch_entry(root_dn);
            }

            AppMsg::ChildEntries { parent_dn, entries } => {
                let children: Vec<TreeNode> = entries
                    .iter()
                    .map(|e| {
                        let dn = e.dn.clone();
                        let object_classes: Vec<String> =
                            e.attrs.get("objectClass").cloned().unwrap_or_default();
                        let label = entry_display_name(&dn, &e.attrs);
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
                            object_classes,
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
                if self.attrs.selected_dn.as_deref() != Some(&entry.dn) {
                    return;
                }
                self.attrs.load(&entry);
            }

            AppMsg::ConfigChanged(cfg) => {
                self.apply_config(&cfg);
            }

            _ => {}
        }
    }
}
