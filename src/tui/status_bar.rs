//! Status/header bar: connection state and toggle flag indicators.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::config::ResolvedConfig;

/// An action triggered by clicking a status-bar button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusAction {
    ToggleFormat,
    ToggleColors,
    ToggleExpand,
    ToggleEmoji,
    ToggleDeleted,
    CycleSort,
}

fn bool_span(label: &str, on: bool) -> Span<'static> {
    let (text, color) = if on {
        ("ON", Color::Green)
    } else {
        ("OFF", Color::Red)
    };
    Span::styled(
        format!("[{label}: {text}]"),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    )
}

fn cycle_span(label: &str, value: &str) -> Span<'static> {
    let color = if value == "OFF" {
        Color::Red
    } else {
        Color::Green
    };
    Span::styled(
        format!("[{label}: {value}]"),
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    )
}

/// Render the status bar and return click hit-zones: `(rect, action)` per clickable button.
///
/// "Connected" and "TLS" are read-only indicators and have no associated action.
pub fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    config: &ResolvedConfig,
    connected: bool,
) -> Vec<(Rect, StatusAction)> {
    // Each button is (span, optional_action).  We build all spans first,
    // then compute hit zones in a second pass using cumulative widths.
    let buttons: &[(Span<'static>, Option<StatusAction>)] = &[
        (bool_span("Connected", connected), None),
        (bool_span("TLS", config.ldaps), None),
        (
            bool_span("Format (f)", config.format),
            Some(StatusAction::ToggleFormat),
        ),
        (
            bool_span("Colors (c)", config.colors),
            Some(StatusAction::ToggleColors),
        ),
        (
            bool_span("Expand (a)", config.expand),
            Some(StatusAction::ToggleExpand),
        ),
        (
            bool_span("Emoji (e)", config.emojis),
            Some(StatusAction::ToggleEmoji),
        ),
        (
            bool_span("Deleted (d)", config.deleted),
            Some(StatusAction::ToggleDeleted),
        ),
        (
            cycle_span("Sort (s)", config.attrsort.label()),
            Some(StatusAction::CycleSort),
        ),
    ];

    let mut hit_zones: Vec<(Rect, StatusAction)> = Vec::new();
    let mut x = area.x;
    let mut spans: Vec<Span> = Vec::new();

    for (sp, action) in buttons {
        let w = sp.content.len() as u16;
        if let Some(act) = action {
            hit_zones.push((
                Rect {
                    x,
                    y: area.y,
                    width: w,
                    height: 1,
                },
                *act,
            ));
        }
        x += w + 1; // +1 for the trailing separator space
        spans.push(sp.clone());
        spans.push(Span::raw(" "));
    }

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
    hit_zones
}
