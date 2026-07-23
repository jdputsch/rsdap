//! Shared attribute panel: rendering, navigation, and display logic reused by
//! every page that shows LDAP entry attributes (Explorer, Search, …).

use std::cmp::Reverse;

use crossterm::event::KeyCode;
use ldap3::SearchEntry;
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem};

use crate::config::{AttrSort, TimeFmt};
use crate::formats::attributes::{
    format_bin_value, format_bitset_rows, format_value, is_bitset_attr,
};
use crate::formats::colors::{attr_value_color, bin_attr_value_color};
use crate::formats::timestamp::{filetime_parts, generalized_time_parts};

/// Raw value stored from LDAP: either a text string or binary bytes.
#[derive(Clone)]
pub enum RawVal {
    Text(String),
    Bin(Vec<u8>),
}

/// Display + navigation settings that control how attrs are rendered.
#[derive(Clone, Debug)]
pub struct AttrConfig {
    pub format_attrs: bool,
    pub colors: bool,
    pub expand_attrs: bool,
    pub attr_limit: usize,
    pub attrsort: AttrSort,
    pub timefmt: TimeFmt,
    pub offset: i32,
}

impl Default for AttrConfig {
    fn default() -> Self {
        Self {
            format_attrs: true,
            colors: true,
            expand_attrs: true,
            attr_limit: 20,
            attrsort: AttrSort::None,
            timefmt: TimeFmt::Eu,
            offset: 0,
        }
    }
}

/// Self-contained attribute panel state: raw data, selection, and scroll.
#[derive(Default)]
pub struct AttrPanel {
    /// (name, values) in server order; sorted on render.
    pub raw_rows: Vec<(String, Vec<RawVal>)>,
    /// DN whose attributes are shown.
    pub selected_dn: Option<String>,
    /// Index into the sorted attr list; `None` = no selection.
    pub attr_selected: Option<usize>,
    /// Display-row scroll offset; auto-adjusted by `render`.
    pub attr_scroll: usize,
    /// Inner content rect (excluding border) — updated each frame for mouse hit-testing.
    pub content_rect: Rect,
}

impl AttrPanel {
    /// Populate from a fetched LDAP entry. Resets selection and scroll.
    pub fn load(&mut self, entry: &SearchEntry) {
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
        self.selected_dn = Some(entry.dn.clone());
        self.attr_selected = None;
        self.attr_scroll = 0;
    }

    /// Clear all data (e.g. when a new search begins).
    pub fn clear(&mut self) {
        self.raw_rows.clear();
        self.selected_dn = None;
        self.attr_selected = None;
        self.attr_scroll = 0;
    }

    /// Handle Up/Down key navigation (by attribute, not display row).
    pub fn handle_key(&mut self, code: KeyCode) {
        let count = self.raw_rows.len();
        if count == 0 {
            return;
        }
        match code {
            KeyCode::Down | KeyCode::Char('j') => {
                let next = match self.attr_selected {
                    None => 0,
                    Some(i) => (i + 1).min(count - 1),
                };
                self.attr_selected = Some(next);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                let prev = match self.attr_selected {
                    None => 0,
                    Some(0) => 0,
                    Some(i) => i - 1,
                };
                self.attr_selected = Some(prev);
            }
            _ => {}
        }
    }

    /// Handle a mouse click at terminal coordinates `(col, row)`.
    /// Selects the attribute under the cursor if inside `content_rect`.
    pub fn handle_click(&mut self, col: u16, row: u16, cfg: &AttrConfig) {
        let r = self.content_rect;
        if col < r.x || col >= r.x + r.width || row < r.y || row >= r.y + r.height {
            return;
        }
        let clicked_row = row.saturating_sub(r.y) as usize;
        let display_idx = self.attr_scroll + clicked_row;
        let (_, line_attr) = self.build_lines_indexed(cfg);
        if let Some(&attr_idx) = line_attr.get(display_idx) {
            self.attr_selected = Some(attr_idx);
        }
    }

    /// Handle mouse scroll up/down inside the panel.
    pub fn scroll_down(&mut self, cfg: &AttrConfig) {
        self.handle_key_raw(KeyCode::Down, cfg);
    }

    pub fn scroll_up(&mut self, cfg: &AttrConfig) {
        self.handle_key_raw(KeyCode::Up, cfg);
    }

    fn handle_key_raw(&mut self, code: KeyCode, _cfg: &AttrConfig) {
        self.handle_key(code);
    }

    /// Render the panel into `area`. Updates `content_rect` for subsequent mouse hits.
    /// `focused` controls the border highlight colour.
    pub fn render(
        &mut self,
        frame: &mut Frame<'_>,
        area: Rect,
        title: &str,
        focused: bool,
        cfg: &AttrConfig,
    ) {
        let border_style = if focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };

        let (lines, line_attr) = self.build_lines_indexed(cfg);
        let visible_height = area.height.saturating_sub(2) as usize;
        let total = lines.len();

        // Auto-scroll: keep the first display row of the selected attr visible.
        if let Some(sel) = self.attr_selected {
            if let Some(first_row) = line_attr.iter().position(|&a| a == sel) {
                if first_row < self.attr_scroll {
                    self.attr_scroll = first_row;
                } else if first_row >= self.attr_scroll + visible_height {
                    self.attr_scroll = first_row.saturating_sub(visible_height - 1);
                }
            }
        }
        let max_scroll = total.saturating_sub(visible_height);
        self.attr_scroll = self.attr_scroll.min(max_scroll);

        // Store the inner content rect (border excluded) for click hit-testing.
        self.content_rect = Rect {
            x: area.x + 1,
            y: area.y + 1,
            width: area.width.saturating_sub(2),
            height: area.height.saturating_sub(2),
        };

        let items: Vec<ListItem> = lines
            .into_iter()
            .skip(self.attr_scroll)
            .take(visible_height)
            .map(ListItem::new)
            .collect();

        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(title.to_owned())
                .border_style(border_style),
        );

        frame.render_widget(list, area);
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn sorted_attrs(&self, cfg: &AttrConfig) -> Vec<(String, Vec<RawVal>)> {
        let mut rows = self.raw_rows.clone();
        match cfg.attrsort {
            AttrSort::None => {}
            AttrSort::Asc => rows.sort_by_key(|(n, _)| n.to_lowercase()),
            AttrSort::Desc => rows.sort_by_key(|(b, _)| Reverse(b.to_lowercase())),
        }
        rows
    }

    /// Returns `(display_lines, per_line_attr_index)`.
    pub fn build_lines_indexed(&self, cfg: &AttrConfig) -> (Vec<Line<'static>>, Vec<usize>) {
        let rows = self.sorted_attrs(cfg);
        let mut lines: Vec<Line<'static>> = Vec::new();
        let mut line_attr: Vec<usize> = Vec::new();

        for (attr_idx, (name, vals)) in rows.iter().enumerate() {
            let highlight = self.attr_selected == Some(attr_idx);
            let name_style = if highlight {
                Style::default().fg(Color::Black).bg(Color::Yellow)
            } else {
                Style::default().fg(Color::Cyan)
            };

            macro_rules! push {
                ($line:expr) => {{
                    lines.push($line);
                    line_attr.push(attr_idx);
                }};
            }

            if cfg.format_attrs && is_bitset_attr(name) {
                for rv in vals {
                    if let RawVal::Text(s) = rv {
                        let bits = format_bitset_rows(name, s);
                        if bits.is_empty() {
                            push!(styled_line_hl(name, rv, name_style, cfg));
                        } else {
                            for bit_name in bits {
                                push!(Line::from(vec![
                                    Span::styled(format!("{name}: "), name_style),
                                    Span::raw(bit_name),
                                ]));
                            }
                        }
                    } else {
                        push!(styled_line_hl(name, rv, name_style, cfg));
                    }
                }
                continue;
            }

            if cfg.expand_attrs {
                let shown = vals.len().min(cfg.attr_limit);
                let indent = " ".repeat(name.len() + 2);
                for (vi, rv) in vals[..shown].iter().enumerate() {
                    let line = if vi == 0 {
                        styled_line_hl(name, rv, name_style, cfg)
                    } else {
                        continuation_line(name, rv, &indent, name_style, cfg)
                    };
                    push!(line);
                }
                if vals.len() > cfg.attr_limit {
                    let hidden = vals.len() - cfg.attr_limit;
                    push!(Line::from(vec![
                        Span::styled(indent, name_style),
                        Span::styled(
                            format!("… {hidden} more values hidden"),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]));
                }
            } else {
                let joined: Vec<String> = vals
                    .iter()
                    .flat_map(|rv| format_raw_val(name, rv, cfg))
                    .collect();
                push!(Line::from(vec![
                    Span::styled(format!("{name}: "), name_style),
                    Span::raw(joined.join(" | ")),
                ]));
            }
        }
        (lines, line_attr)
    }
}

// ── Module-level helpers (free functions, not methods) ────────────────────────

pub fn format_raw_val(name: &str, rv: &RawVal, cfg: &AttrConfig) -> Vec<String> {
    match rv {
        RawVal::Bin(bytes) => {
            if cfg.format_attrs {
                vec![format_bin_value(name, bytes)]
            } else {
                vec![bytes.iter().map(|b| format!("{b:02x}")).collect()]
            }
        }
        RawVal::Text(s) => {
            if cfg.format_attrs && is_bitset_attr(name) {
                let bits = format_bitset_rows(name, s);
                if bits.is_empty() {
                    vec![s.clone()]
                } else {
                    bits
                }
            } else if cfg.format_attrs {
                vec![format_value(name, s, &cfg.timefmt, cfg.offset)]
            } else {
                vec![s.clone()]
            }
        }
    }
}

/// Build a styled line for a single (name, value) pair using the given name style.
pub fn styled_line_hl(
    name: &str,
    rv: &RawVal,
    name_style: Style,
    cfg: &AttrConfig,
) -> Line<'static> {
    let name_span = Span::styled(format!("{name}: "), name_style);

    if cfg.format_attrs {
        if let RawVal::Text(s) = rv {
            if let Some((date_str, dist_str, level)) =
                try_timestamp_parts(name, s, &cfg.timefmt, cfg.offset)
            {
                let dist_color = if cfg.colors {
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

    let vals = format_raw_val(name, rv, cfg);
    let val_str = vals.join(" | ");

    if cfg.colors {
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

/// Build a continuation line (2nd+ value for the same attr) indented to align under the first.
fn continuation_line(
    name: &str,
    rv: &RawVal,
    indent: &str,
    name_style: Style,
    cfg: &AttrConfig,
) -> Line<'static> {
    let val_strs = format_raw_val(name, rv, cfg);
    let val_str = val_strs.join(" | ");
    if cfg.colors {
        let color = match rv {
            RawVal::Bin(_) => bin_attr_value_color(name),
            RawVal::Text(s) => attr_value_color(name, s),
        };
        if let Some(c) = color {
            return Line::from(vec![
                Span::styled(indent.to_owned(), name_style),
                Span::styled(val_str, Style::default().fg(c)),
            ]);
        }
    }
    Line::from(vec![
        Span::styled(indent.to_owned(), name_style),
        Span::raw(val_str),
    ])
}

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
