//! Ratatui layout: split the terminal into the four fixed zones.

use ratatui::layout::{Constraint, Direction, Layout, Rect};

/// The four areas that make up the application frame.
pub struct AppAreas {
    pub tab_bar: Rect,
    pub log_panel: Rect,
    pub status_bar: Rect,
    pub content: Rect,
}

/// Build the application layout from the full terminal area.
///
/// When `show_header` is false the status_bar area has zero height and is
/// merged into the content area effectively.
pub fn build_layout(area: Rect, show_header: bool) -> AppAreas {
    let status_height = if show_header { 1 } else { 0 };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),             // tab bar
            Constraint::Length(status_height), // status/header bar
            Constraint::Min(0),                // content
            Constraint::Length(5),             // log panel (3 entries + 2 border lines)
        ])
        .split(area);

    AppAreas {
        tab_bar: chunks[0],
        status_bar: chunks[1],
        content: chunks[2],
        log_panel: chunks[3],
    }
}
