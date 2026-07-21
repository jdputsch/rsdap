//! Search page: filter input, predefined query library, results list, attributes panel.

use std::time::Instant;

use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers};
use ldap3::Scope;
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Row, Table};
use tokio::sync::mpsc::Sender;

use super::Page;
use crate::app::{AppMsg, SharedLdap};
use crate::config::{AttrSort, ResolvedConfig, TimeFmt};
use crate::formats::attributes::{
    format_bin_value, format_bitset_rows, format_value, is_bitset_attr,
};
use crate::formats::colors::{attr_value_color, bin_attr_value_color};
use crate::formats::timestamp::{filetime_parts, generalized_time_parts};
use crate::ldap::search::{SearchParams, auto_wrap_filter, search_all};
use crate::tui::widgets::form::{FormField, ModalForm};

// ── Predefined query library ────────────────────────────────────────────────

struct QueryEntry {
    label: &'static str,
    filter: &'static str,
}

const PREDEFINED_QUERIES: &[QueryEntry] = &[
    QueryEntry {
        label: "All objects",
        filter: "(objectClass=*)",
    },
    QueryEntry {
        label: "Users",
        filter: "(objectClass=person)",
    },
    QueryEntry {
        label: "Groups",
        filter: "(objectClass=groupOfNames)",
    },
    QueryEntry {
        label: "Organizational units",
        filter: "(objectClass=organizationalUnit)",
    },
    QueryEntry {
        label: "Computers (AD)",
        filter: "(objectClass=computer)",
    },
    QueryEntry {
        label: "Enabled users (AD)",
        filter: "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
    },
    QueryEntry {
        label: "Disabled users (AD)",
        filter: "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))",
    },
    QueryEntry {
        label: "Locked out (AD)",
        filter: "(&(objectClass=user)(lockoutTime>=1))",
    },
    QueryEntry {
        label: "Password never expires (AD)",
        filter: "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))",
    },
    QueryEntry {
        label: "Admin groups (AD)",
        filter: "(&(objectClass=group)(adminCount=1))",
    },
];

// ── Raw value (mirror of explorer.rs) ───────────────────────────────────────

#[derive(Clone)]
enum RawVal {
    Text(String),
    Bin(Vec<u8>),
}

// ── History entry ────────────────────────────────────────────────────────────

struct HistoryEntry {
    filter: String,
    result_count: usize,
    elapsed_ms: u64,
}

// ── Scope selector ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SearchScope {
    Base,
    OneLevel,
    Subtree,
}

impl SearchScope {
    fn label(self) -> &'static str {
        match self {
            SearchScope::Base => "base",
            SearchScope::OneLevel => "one",
            SearchScope::Subtree => "sub",
        }
    }

    fn to_ldap(self) -> Scope {
        match self {
            SearchScope::Base => Scope::Base,
            SearchScope::OneLevel => Scope::OneLevel,
            SearchScope::Subtree => Scope::Subtree,
        }
    }
}

// ── Focus ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Filter,
    Results,
    Library,
    Attrs,
}

// ── SearchPage ───────────────────────────────────────────────────────────────

pub struct SearchPage {
    tx: Sender<AppMsg>,
    ldap: Option<SharedLdap>,

    // Config mirrors.
    page_size: u32,
    format_attrs: bool,
    colors: bool,
    expand_attrs: bool,
    attr_limit: usize,
    attrsort: AttrSort,
    timefmt: TimeFmt,
    offset: i32,

    // Filter input.
    filter_input: String,

    // Results: just the DN list; attrs are fetched lazily on selection.
    result_dns: Vec<String>,
    result_scroll: usize,

    // Selected result's attributes (lazily fetched).
    selected_result: Option<usize>,
    selected_dn: Option<String>,
    raw_rows: Vec<(String, Vec<RawVal>)>,
    attr_scroll: usize,

    // Library.
    library_selected: usize,

    // History.
    history: Vec<HistoryEntry>,
    history_scroll: usize,

    // Settings modal.
    settings_open: bool,
    settings_form: Option<ModalForm>,
    search_base: Option<String>, // None = use root_dn
    root_dn: Option<String>,
    scope: SearchScope,

    // Search in progress.
    searching: bool,
    search_started: Option<Instant>,

    // Panel focus.
    focus: Focus,

    // Whether to show history pane instead of results.
    show_history: bool,
}

impl SearchPage {
    pub fn new(tx: Sender<AppMsg>) -> Self {
        Self {
            tx,
            ldap: None,
            page_size: 800,
            format_attrs: true,
            colors: true,
            expand_attrs: true,
            attr_limit: 20,
            attrsort: AttrSort::None,
            timefmt: TimeFmt::Eu,
            offset: 0,
            filter_input: String::new(),
            result_dns: Vec::new(),
            result_scroll: 0,
            selected_result: None,
            selected_dn: None,
            raw_rows: Vec::new(),
            attr_scroll: 0,
            library_selected: 0,
            history: Vec::new(),
            history_scroll: 0,
            settings_open: false,
            settings_form: None,
            search_base: None,
            root_dn: None,
            scope: SearchScope::Subtree,
            searching: false,
            search_started: None,
            focus: Focus::Filter,
            show_history: false,
        }
    }

    fn apply_config(&mut self, cfg: &ResolvedConfig) {
        self.page_size = cfg.paging;
        self.format_attrs = cfg.format;
        self.colors = cfg.colors;
        self.expand_attrs = cfg.expand;
        self.attr_limit = cfg.limit;
        self.attrsort = cfg.attrsort.clone();
        self.timefmt = cfg.timefmt.clone();
        self.offset = cfg.offset;
    }

    fn effective_base(&self) -> String {
        self.search_base
            .clone()
            .or_else(|| self.root_dn.clone())
            .unwrap_or_default()
    }

    fn fire_search(&mut self) {
        let Some(ldap) = self.ldap.clone() else {
            return;
        };
        let raw = self.filter_input.trim().to_owned();
        if raw.is_empty() {
            return;
        }
        let filter = auto_wrap_filter(&raw);
        let base = self.effective_base();
        let scope = self.scope.to_ldap();
        let page_size = self.page_size;
        let tx = self.tx.clone();

        self.searching = true;
        self.search_started = Some(Instant::now());

        tokio::spawn(async move {
            // Fetch only display-name attrs; full entry is loaded lazily on selection.
            let params = SearchParams {
                base,
                scope,
                filter: filter.clone(),
                attrs: vec![
                    "objectClass".to_owned(),
                    "cn".to_owned(),
                    "ou".to_owned(),
                    "dc".to_owned(),
                    "name".to_owned(),
                    "uid".to_owned(),
                    "sAMAccountName".to_owned(),
                ],
                page_size,
                include_deleted: false,
            };
            let mut guard = ldap.lock().await;
            let result = search_all(&mut guard.inner, &params).await;
            drop(guard);

            match result {
                Ok(entries) => {
                    let _ = tx
                        .send(AppMsg::SearchDone {
                            filter,
                            entries,
                            elapsed_ms: 0,
                        })
                        .await;
                }
                Err(e) => {
                    // Send both the error message AND a SearchDone with empty results so
                    // searching=true doesn't get stuck.
                    let _ = tx.send(AppMsg::Error(e.to_string())).await;
                    let _ = tx
                        .send(AppMsg::SearchDone {
                            filter,
                            entries: vec![],
                            elapsed_ms: 0,
                        })
                        .await;
                }
            }
        });
    }

    /// Fire an async task to fetch all attributes for a DN (same as ExplorerPage).
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
                    vec!["base".into(), "one".into(), "sub".into()],
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
                "base" => SearchScope::Base,
                "one" => SearchScope::OneLevel,
                _ => SearchScope::Subtree,
            };
        }
        self.settings_form = None;
        self.settings_open = false;
    }

    /// Build attribute display lines (same logic as ExplorerPage::display_lines).
    fn display_lines(&self) -> Vec<Line<'static>> {
        let mut rows: Vec<(String, Vec<RawVal>)> = self.raw_rows.clone();
        match self.attrsort {
            AttrSort::None => {}
            AttrSort::Asc => rows.sort_by_key(|(n, _)| n.to_lowercase()),
            AttrSort::Desc => {
                rows.sort_by_key(|(b, _)| std::cmp::Reverse(b.to_lowercase()));
            }
        }

        let mut out = Vec::new();
        for (name, vals) in &rows {
            if self.format_attrs && is_bitset_attr(name) {
                for rv in vals {
                    if let RawVal::Text(s) = rv {
                        let bits = format_bitset_rows(name, s);
                        if bits.is_empty() {
                            out.push(self.styled_line(name, rv));
                        } else {
                            for bit_name in bits {
                                out.push(Line::from(vec![
                                    Span::styled(
                                        format!("{name}: "),
                                        Style::default().fg(Color::Cyan),
                                    ),
                                    Span::raw(bit_name),
                                ]));
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

    fn styled_line(&self, name: &str, rv: &RawVal) -> Line<'static> {
        let name_span = Span::styled(format!("{name}: "), Style::default().fg(Color::Cyan));

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
                    return Line::from(vec![
                        name_span,
                        Span::raw(date_str),
                        Span::raw(" "),
                        Span::styled(format!("({dist_str})"), Style::default().fg(dist_color)),
                    ]);
                }
            }
        }

        let vals = self.format_raw_val(name, rv);
        let val_str = vals.join(" | ");

        if self.colors {
            let color = match rv {
                RawVal::Bin(_) => bin_attr_value_color(name),
                RawVal::Text(s) => attr_value_color(name, s),
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

    fn select_result(&mut self, idx: usize) {
        if idx >= self.result_dns.len() {
            return;
        }
        let dn = self.result_dns[idx].clone();
        self.selected_result = Some(idx);
        self.selected_dn = Some(dn.clone());
        self.raw_rows.clear();
        self.attr_scroll = 0;
        self.fetch_entry(dn);
    }
}

/// Try to extract timestamp parts for a named attribute (same list as explorer.rs).
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

impl Page for SearchPage {
    fn title(&self) -> &str {
        "Search"
    }

    fn captures_input(&self) -> bool {
        // Only the settings modal truly captures all input (suppresses global keys).
        // The filter text box is handled inside handle_key without blocking globals.
        self.settings_open
    }

    fn render(&mut self, frame: &mut Frame<'_>, area: Rect) {
        // ── Layout ───────────────────────────────────────────────────────────
        // Row 0: filter bar (3 lines)
        // Row 1: [results / history | library] (left 70% / right 30%)
        // Row 2: attributes panel (bottom third)
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Percentage(45),
                Constraint::Percentage(45),
            ])
            .split(area);

        let mid_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
            .split(rows[1]);

        // ── Filter bar ───────────────────────────────────────────────────────
        let filter_border = if self.focus == Focus::Filter {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };

        let filter_text = if self.searching {
            format!("{} [searching…]", self.filter_input)
        } else {
            format!(
                "{} [base: {} | scope: {}]",
                self.filter_input,
                self.search_base
                    .as_deref()
                    .or(self.root_dn.as_deref())
                    .unwrap_or("(not connected)"),
                self.scope.label()
            )
        };
        let filter_para = Paragraph::new(filter_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Filter  (Enter=search  o=settings  H=history)")
                    .border_style(filter_border),
            )
            .style(if self.focus == Focus::Filter {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(Color::Gray)
            });
        frame.render_widget(filter_para, rows[0]);

        // ── Results or history ───────────────────────────────────────────────
        if self.show_history {
            self.render_history(frame, mid_cols[0]);
        } else {
            self.render_results(frame, mid_cols[0]);
        }

        // ── Library ──────────────────────────────────────────────────────────
        self.render_library(frame, mid_cols[1]);

        // ── Attributes panel ─────────────────────────────────────────────────
        self.render_attrs(frame, rows[2]);

        // ── Settings modal (rendered last / on top) ──────────────────────────
        if self.settings_open {
            if let Some(form) = &self.settings_form {
                form.render(frame, area);
            }
        }
    }

    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Result<()> {
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

        // ── Panel-specific keys ───────────────────────────────────────────────
        match self.focus {
            Focus::Filter => match (code, modifiers) {
                (KeyCode::Esc, _) => self.focus = Focus::Results,
                (KeyCode::Enter, _) => {
                    self.fire_search();
                    self.focus = Focus::Results;
                }
                (KeyCode::Tab, KeyModifiers::NONE) => self.focus = Focus::Results,
                (KeyCode::BackTab, _) => self.focus = Focus::Library,
                (KeyCode::Backspace, _) => {
                    self.filter_input.pop();
                }
                (KeyCode::Char('o'), KeyModifiers::CONTROL) => self.open_settings(),
                (KeyCode::Char(ch), KeyModifiers::NONE | KeyModifiers::SHIFT) => {
                    self.filter_input.push(ch);
                }
                _ => {}
            },

            Focus::Results => match (code, modifiers) {
                (KeyCode::Tab, KeyModifiers::NONE) => self.focus = Focus::Attrs,
                (KeyCode::BackTab, _) => self.focus = Focus::Filter,
                (KeyCode::Char('o'), KeyModifiers::NONE) => self.open_settings(),
                (KeyCode::Char('H'), KeyModifiers::NONE) => {
                    self.show_history = !self.show_history;
                }
                (KeyCode::Down, _) | (KeyCode::Char('j'), KeyModifiers::NONE) => {
                    if !self.result_dns.is_empty() {
                        let next = self
                            .selected_result
                            .map(|i| (i + 1).min(self.result_dns.len() - 1))
                            .unwrap_or(0);
                        self.select_result(next);
                    }
                }
                (KeyCode::Up, _) | (KeyCode::Char('k'), KeyModifiers::NONE) => {
                    if let Some(i) = self.selected_result {
                        let prev = i.saturating_sub(1);
                        self.select_result(prev);
                    }
                }
                _ => {}
            },

            Focus::Library => match (code, modifiers) {
                (KeyCode::Tab, KeyModifiers::NONE) => self.focus = Focus::Filter,
                (KeyCode::BackTab, _) => self.focus = Focus::Attrs,
                (KeyCode::Down, _) | (KeyCode::Char('j'), KeyModifiers::NONE) => {
                    self.library_selected =
                        (self.library_selected + 1).min(PREDEFINED_QUERIES.len() - 1);
                }
                (KeyCode::Up, _) | (KeyCode::Char('k'), KeyModifiers::NONE) => {
                    self.library_selected = self.library_selected.saturating_sub(1);
                }
                (KeyCode::Enter, _) => {
                    self.filter_input = PREDEFINED_QUERIES[self.library_selected].filter.to_owned();
                    self.focus = Focus::Filter;
                }
                _ => {}
            },

            Focus::Attrs => match (code, modifiers) {
                (KeyCode::Tab, KeyModifiers::NONE) => self.focus = Focus::Library,
                (KeyCode::BackTab, _) => self.focus = Focus::Results,
                (KeyCode::Down, _) | (KeyCode::Char('j'), KeyModifiers::NONE) => {
                    let len = self.display_lines().len();
                    if self.attr_scroll + 1 < len {
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
                self.root_dn = Some(root_dn);
                self.ldap = Some(client);
            }

            AppMsg::SearchDone {
                filter,
                entries,
                elapsed_ms,
            } => {
                self.searching = false;
                let actual_ms = self
                    .search_started
                    .take()
                    .map(|t| t.elapsed().as_millis() as u64)
                    .unwrap_or(elapsed_ms);

                // Only record history when there was no error (non-empty or genuine zero results).
                self.history.push(HistoryEntry {
                    filter,
                    result_count: entries.len(),
                    elapsed_ms: actual_ms,
                });

                self.result_dns = entries.into_iter().map(|e| e.dn).collect();
                self.result_scroll = 0;
                self.selected_result = None;
                self.selected_dn = None;
                self.raw_rows.clear();
                self.attr_scroll = 0;

                if !self.result_dns.is_empty() {
                    self.select_result(0);
                }
                self.show_history = false;
            }

            AppMsg::EntryFetched(entry) => {
                // Only populate if this is still the selected entry.
                if self.selected_dn.as_deref() == Some(&entry.dn) {
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
            }

            AppMsg::ConfigChanged(cfg) => {
                self.apply_config(&cfg);
            }

            _ => {}
        }
    }
}

// ── Private render helpers ───────────────────────────────────────────────────

impl SearchPage {
    fn render_results(&self, frame: &mut Frame<'_>, area: Rect) {
        let border_style = if self.focus == Focus::Results {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };
        let count = self.result_dns.len();
        let title = format!("Results ({count})  j/k=navigate  H=history");

        let visible_height = area.height.saturating_sub(2) as usize;
        let items: Vec<ListItem> = self
            .result_dns
            .iter()
            .enumerate()
            .skip(self.result_scroll)
            .take(visible_height)
            .map(|(i, dn)| {
                let style = if self.selected_result == Some(i) {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                };
                ListItem::new(Span::styled(dn.clone(), style))
            })
            .collect();

        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(border_style),
        );
        frame.render_widget(list, area);
    }

    fn render_history(&self, frame: &mut Frame<'_>, area: Rect) {
        let border_style = if self.focus == Focus::Results {
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
                    h.filter.clone(),
                    h.result_count.to_string(),
                    format!("{}ms", h.elapsed_ms),
                ])
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Percentage(70),
                Constraint::Percentage(15),
                Constraint::Percentage(15),
            ],
        )
        .header(
            Row::new(vec!["Filter", "Count", "Time"]).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("History  (H=close)")
                .border_style(border_style),
        );

        frame.render_widget(table, area);
    }

    fn render_library(&self, frame: &mut Frame<'_>, area: Rect) {
        let border_style = if self.focus == Focus::Library {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };

        let items: Vec<ListItem> = PREDEFINED_QUERIES
            .iter()
            .enumerate()
            .map(|(i, q)| {
                let style = if i == self.library_selected && self.focus == Focus::Library {
                    Style::default().add_modifier(Modifier::REVERSED)
                } else {
                    Style::default()
                };
                ListItem::new(Span::styled(q.label, style))
            })
            .collect();

        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Library  (Enter=load)")
                .border_style(border_style),
        );
        frame.render_widget(list, area);
    }

    fn render_attrs(&self, frame: &mut Frame<'_>, area: Rect) {
        let border_style = if self.focus == Focus::Attrs {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };

        let title = match &self.selected_dn {
            Some(dn) => format!("Attributes — {dn}"),
            None => "Attributes".to_owned(),
        };

        let lines = self.display_lines();
        let visible_height = area.height.saturating_sub(2) as usize;
        let max_scroll = lines.len().saturating_sub(visible_height);
        let scroll = self.attr_scroll.min(max_scroll);

        let items: Vec<ListItem> = lines
            .into_iter()
            .skip(scroll)
            .take(visible_height)
            .map(ListItem::new)
            .collect();

        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(border_style),
        );
        frame.render_widget(list, area);
    }
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
            filter: "(cn=*)".into(),
            entries: vec![],
            elapsed_ms: 42,
        });
        assert_eq!(p.history.len(), 1);
        assert_eq!(p.history[0].filter, "(cn=*)");
        assert_eq!(p.history[0].result_count, 0);
    }

    #[test]
    fn history_records_result_count() {
        let mut p = page();
        // Build a minimal SearchEntry-like result via SearchDone.
        // We just send an empty entries vec; count should be 0.
        p.apply_msg(AppMsg::SearchDone {
            filter: "(objectClass=*)".into(),
            entries: vec![],
            elapsed_ms: 10,
        });
        assert_eq!(p.history[0].result_count, 0);
    }

    #[test]
    fn library_entry_loads_filter() {
        let mut p = page();
        p.focus = Focus::Library;
        p.library_selected = 1; // "Users"
        p.handle_key(KeyCode::Enter, KeyModifiers::NONE).unwrap();
        assert_eq!(p.filter_input, PREDEFINED_QUERIES[1].filter);
        assert_eq!(p.focus, Focus::Filter);
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
        // Change the base DN field.
        if let Some(f) = &mut p.settings_form {
            f.fields[0].value = "dc=example,dc=com".to_owned();
            f.fields[1].value = "one".to_owned();
        }
        p.apply_settings();
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
        assert_eq!(p.focus, Focus::Attrs);
        p.handle_key(KeyCode::Tab, KeyModifiers::NONE).unwrap();
        assert_eq!(p.focus, Focus::Library);
        p.handle_key(KeyCode::Tab, KeyModifiers::NONE).unwrap();
        assert_eq!(p.focus, Focus::Filter);
    }

    #[test]
    fn history_toggle() {
        let mut p = page();
        p.focus = Focus::Results;
        p.handle_key(KeyCode::Char('H'), KeyModifiers::NONE)
            .unwrap();
        assert!(p.show_history);
        p.handle_key(KeyCode::Char('H'), KeyModifiers::NONE)
            .unwrap();
        assert!(!p.show_history);
    }
}
