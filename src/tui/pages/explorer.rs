//! Explorer page: lazy-loading LDAP tree (left) + attributes table (right).

use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers, MouseEvent, MouseEventKind};
use ldap3::Scope;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use tokio::sync::mpsc::Sender;

use super::Page;
use crate::app::{AppMsg, SharedLdap};
use crate::config::{AttrSort, TimeFmt};
use crate::formats::attributes::{
    format_bin_value, format_bitset_rows, format_value, is_bitset_attr,
};
use crate::formats::colors::{attr_value_color, bin_attr_value_color};
use crate::formats::display::entry_display_name;
use crate::formats::timestamp::{filetime_parts, generalized_time_parts};
use crate::ldap::search::{SearchParams, search_all};
use crate::tui::widgets::tree::{TreeNode, TreeWidget};

/// Raw value stored from LDAP: either a text string or binary bytes.
#[derive(Clone)]
enum RawVal {
    Text(String),
    Bin(Vec<u8>),
}

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
    colors: bool,
    expand_attrs: bool,
    attr_limit: usize,
    attrsort: AttrSort,
    timefmt: TimeFmt,
    offset: i32,
    /// All (name, values) pairs for the selected entry in server order, truly raw.
    raw_rows: Vec<(String, Vec<RawVal>)>,
    /// DN of the entry currently shown in the attributes panel.
    attr_dn: Option<String>,
    /// Which panel has keyboard focus.
    focus: Focus,
    /// Scroll offset for the attributes list.
    attr_scroll: usize,
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
            format_attrs: true,
            colors: true,
            expand_attrs: true,
            attr_limit: 20,
            attrsort: AttrSort::None,
            timefmt: TimeFmt::Eu,
            offset: 0,
            raw_rows: Vec::new(),
            attr_dn: None,
            focus: Focus::Tree,
            attr_scroll: 0,
            tree_rect: Rect::default(),
            attr_rect: Rect::default(),
        }
    }

    /// Apply current config values from a ResolvedConfig snapshot.
    pub fn apply_config(&mut self, cfg: &crate::config::ResolvedConfig) {
        self.page_size = cfg.paging;
        self.emojis = cfg.emojis;
        self.format_attrs = cfg.format;
        self.colors = cfg.colors;
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

    /// Format one raw value into display string(s).
    ///
    /// Normally returns one string; bitset attrs return one string per active bit.
    fn format_raw_val(&self, name: &str, rv: &RawVal) -> Vec<String> {
        match rv {
            RawVal::Bin(bytes) => {
                if self.format_attrs {
                    vec![format_bin_value(name, bytes)]
                } else {
                    vec![bytes.iter().map(|b| format!("{b:02x}")).collect()]
                }
            }
            RawVal::Text(s) => {
                if self.format_attrs && is_bitset_attr(name) {
                    let bits = format_bitset_rows(name, s);
                    if bits.is_empty() {
                        vec![s.clone()]
                    } else {
                        bits
                    }
                } else if self.format_attrs {
                    vec![format_value(name, s, &self.timefmt, self.offset)]
                } else {
                    vec![s.clone()]
                }
            }
        }
    }

    /// Build a styled Line for one attribute value.
    ///
    /// When Colors is ON, timestamp attrs get a colored distance suffix; other attrs
    /// get a per-attribute color applied to the whole value span.
    fn styled_line(&self, name: &str, rv: &RawVal) -> Line<'static> {
        let name_span = Span::styled(format!("{name}: "), Style::default().fg(Color::Cyan));

        // Timestamp attrs: split into date + colored distance suffix.
        if self.format_attrs {
            if let RawVal::Text(s) = rv {
                if let Some((date_str, dist_str, level)) =
                    try_timestamp_parts(name, s, &self.timefmt, self.offset)
                {
                    let dist_color = if self.colors {
                        match level {
                            0 => Color::Green,
                            1 => Color::Yellow,
                            _ => Color::Red,
                        }
                    } else {
                        Color::Reset
                    };
                    let dist_span = if self.colors {
                        Span::styled(format!("({dist_str})"), Style::default().fg(dist_color))
                    } else {
                        Span::raw(format!("({dist_str})"))
                    };
                    return Line::from(vec![
                        name_span,
                        Span::raw(date_str),
                        Span::raw(" "),
                        dist_span,
                    ]);
                }
            }
        }

        // All other attrs: compute value string then apply optional color.
        let vals = self.format_raw_val(name, rv);
        let val_str = vals.join(" | ");

        if self.colors {
            let color = match rv {
                RawVal::Bin(_) => bin_attr_value_color(name),
                RawVal::Text(s) => {
                    // Use the raw value for color lookup so duration/threshold rules
                    // see the original number, not the formatted string.
                    attr_value_color(name, s)
                }
            };
            if let Some(c) = color {
                return Line::from(vec![
                    name_span,
                    Span::styled(val_str, Style::default().fg(c)),
                ]);
            }
        }

        Line::from(vec![name_span, Span::raw(val_str)])
    }

    /// Build the display lines, applying sort, expand, and limit.
    fn display_lines(&self) -> Vec<Line<'static>> {
        let mut rows: Vec<(String, Vec<RawVal>)> = self.raw_rows.clone();

        match self.attrsort {
            AttrSort::None => {}
            AttrSort::Asc => rows.sort_by_key(|(n, _)| n.to_lowercase()),
            AttrSort::Desc => rows.sort_by_key(|(b, _)| std::cmp::Reverse(b.to_lowercase())),
        }

        let mut out = Vec::new();
        for (name, vals) in &rows {
            // Bitset attributes expand per-bit when FormatAttrs is ON, regardless of ExpandAttrs.
            if self.format_attrs && is_bitset_attr(name) {
                for rv in vals {
                    if let RawVal::Text(s) = rv {
                        let bits = format_bitset_rows(name, s);
                        if bits.is_empty() {
                            out.push(self.styled_line(name, rv));
                        } else {
                            for bit_name in bits {
                                let line = Line::from(vec![
                                    Span::styled(
                                        format!("{name}: "),
                                        Style::default().fg(Color::Cyan),
                                    ),
                                    Span::raw(bit_name),
                                ]);
                                out.push(line);
                            }
                        }
                    } else {
                        out.push(self.styled_line(name, rv));
                    }
                }
                continue;
            }

            if self.expand_attrs {
                let shown = vals.len().min(self.attr_limit);
                for rv in &vals[..shown] {
                    out.push(self.styled_line(name, rv));
                }
                if vals.len() > self.attr_limit {
                    let hidden = vals.len() - self.attr_limit;
                    out.push(Line::from(vec![
                        Span::styled(format!("{name}: "), Style::default().fg(Color::Cyan)),
                        Span::styled(
                            format!("… {hidden} more values hidden"),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]));
                }
            } else {
                // Collapsed: join all values with " | "
                let joined: Vec<String> = vals
                    .iter()
                    .flat_map(|rv| self.format_raw_val(name, rv))
                    .collect();
                out.push(Line::from(vec![
                    Span::styled(format!("{name}: "), Style::default().fg(Color::Cyan)),
                    Span::raw(joined.join(" | ")),
                ]));
            }
        }
        out
    }

    /// Number of display rows (for scroll limit calculation, avoids cloning Lines).
    fn display_len(&self) -> usize {
        self.display_lines().len()
    }
}

/// Try to extract (date_str, distance_str, color_level) for a known timestamp attribute.
fn try_timestamp_parts(
    attr_name: &str,
    raw: &str,
    fmt: &TimeFmt,
    offset: i32,
) -> Option<(String, String, u8)> {
    match attr_name.to_lowercase().as_str() {
        "lastlogon"
        | "lastlogontimestamp"
        | "lastlogoff"
        | "badpasswordtime"
        | "pwdlastset"
        | "accountexpires"
        | "lockouttime"
        | "creationtime"
        | "msds-lastsuccessfulinteractivelogontime"
        | "msds-lastfailedinteractivelogontime" => {
            let ft = raw.parse::<i64>().ok()?;
            filetime_parts(ft, fmt, offset)
        }
        "whencreated" | "whenchanged" | "dscorepropagationdata" => {
            generalized_time_parts(raw, fmt, offset)
        }
        _ => None,
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
        use ratatui::style::Modifier;
        use ratatui::widgets::{Block, Borders, List, ListItem};

        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(area);

        self.tree_rect = chunks[0];
        self.attr_rect = chunks[1];

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
            .render_with_style(frame, chunks[0], "Tree", tree_border_style, self.emojis);

        let title = match &self.attr_dn {
            Some(dn) => format!("Attributes — {dn}"),
            None => "Attributes".to_owned(),
        };

        let lines = self.display_lines();
        let visible_height = chunks[1].height.saturating_sub(2) as usize;
        // Clamp scroll to valid range.
        let max_scroll = lines.len().saturating_sub(visible_height);
        if self.attr_scroll > max_scroll {
            self.attr_scroll = max_scroll;
        }

        let items: Vec<ListItem> = lines
            .into_iter()
            .skip(self.attr_scroll)
            .take(visible_height)
            .map(ListItem::new)
            .collect();

        let attr_block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(attr_border_style);

        let list = if self.display_len() > visible_height {
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
                    let display_len = self.display_len();
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

    fn handle_mouse(&mut self, event: MouseEvent) {
        let (col, row) = (event.column, event.row);
        let in_rect =
            |r: Rect| col >= r.x && col < r.x + r.width && row >= r.y && row < r.y + r.height;

        match event.kind {
            MouseEventKind::ScrollDown => {
                if in_rect(self.attr_rect) {
                    let display_len = self.display_len();
                    if self.attr_scroll + 1 < display_len {
                        self.attr_scroll += 1;
                    }
                } else if in_rect(self.tree_rect) {
                    self.tree.select_next();
                    self.on_selection_change();
                }
            }
            MouseEventKind::ScrollUp => {
                if in_rect(self.attr_rect) {
                    self.attr_scroll = self.attr_scroll.saturating_sub(1);
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
                self.attr_dn = Some(root_dn.clone());
                self.attr_scroll = 0;
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
                if self.attr_dn.as_deref() != Some(&entry.dn) {
                    return;
                }

                // Store truly raw data — format at render time so toggles take effect immediately.
                let mut rows: Vec<(String, Vec<RawVal>)> = Vec::new();

                for (name, vals) in &entry.attrs {
                    rows.push((
                        name.clone(),
                        vals.iter().map(|v| RawVal::Text(v.clone())).collect(),
                    ));
                }
                for (name, vals) in &entry.bin_attrs {
                    rows.push((
                        name.clone(),
                        vals.iter().map(|b| RawVal::Bin(b.clone())).collect(),
                    ));
                }

                self.raw_rows = rows;
                self.attr_scroll = 0;
            }

            AppMsg::ConfigChanged(cfg) => {
                self.apply_config(&cfg);
                // raw_rows stay valid; display_lines() re-applies settings on next render.
            }

            _ => {}
        }
    }
}
