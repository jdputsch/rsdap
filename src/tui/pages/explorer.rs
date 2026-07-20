//! Explorer page: lazy-loading LDAP tree (left) + attributes table (right).

use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers};
use ldap3::Scope;
use ratatui::Frame;
use ratatui::layout::Rect;
use tokio::sync::mpsc::Sender;

use super::Page;
use crate::app::{AppMsg, LdapResult, SharedLdap};
use crate::formats::display::{emoji_for_entry, entry_display_name};
use crate::ldap::search::{SearchParams, search_all};
use crate::tui::widgets::tree::{TreeNode, TreeWidget};

pub struct ExplorerPage {
    tx: Sender<AppMsg>,
    tree: TreeWidget,
    ldap: Option<SharedLdap>,
    root_dn: Option<String>,
    /// Page config values needed for search.
    page_size: u32,
    emojis: bool,
    /// Currently selected entry's attributes for the right panel.
    selected_attrs: Vec<(String, Vec<String>)>,
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
            selected_attrs: Vec::new(),
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

        // Attributes panel
        let items: Vec<ListItem> = self
            .selected_attrs
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

        let list =
            List::new(items).block(Block::default().borders(Borders::ALL).title("Attributes"));
        frame.render_widget(list, chunks[1]);
    }

    fn handle_key(&mut self, code: KeyCode, _modifiers: KeyModifiers) -> Result<()> {
        match code {
            KeyCode::Down | KeyCode::Char('j') => {
                self.tree.select_next();
                self.update_attrs_panel();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.tree.select_prev();
                self.update_attrs_panel();
            }
            KeyCode::Right | KeyCode::Enter => {
                if let Some(dn) = self.tree.expand_selected() {
                    self.load_children(dn);
                }
                self.update_attrs_panel();
            }
            KeyCode::Left => {
                self.tree.collapse_selected();
            }
            KeyCode::Char('r') => {
                // Reload: clear children and re-fetch.
                if let Some(node) = self.tree.selected_node() {
                    let dn = node.id.clone();
                    self.tree.set_children(&dn, Vec::new());
                    // Mark as not loaded so expand_selected triggers a fetch.
                    if let Some(n) = self.tree.nodes.iter_mut().find(|n| n.id == dn) {
                        n.children_loaded = false;
                        n.expanded = false;
                    }
                    self.load_children(dn);
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

                // Seed the tree with the root node and immediately load its children.
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
                self.load_children(root_dn);
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
                        // A node has children if it is a container class.
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
                        // Depth is parent depth + 1; look up parent depth.
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
                self.update_attrs_panel();
            }
            _ => {}
        }
    }
}

impl ExplorerPage {
    fn update_attrs_panel(&mut self) {
        // For now, show the DN and objectClass of the selected node as a placeholder.
        // Phase 4 will fire a full attribute fetch and display all values.
        self.selected_attrs.clear();
        if let Some(node) = self.tree.selected_node() {
            self.selected_attrs
                .push(("dn".to_owned(), vec![node.id.clone()]));
        }
    }
}
