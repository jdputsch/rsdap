//! Status/header bar: connection state and toggle flag indicators.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::config::ResolvedConfig;

pub fn render(frame: &mut Frame<'_>, area: Rect, config: &ResolvedConfig, connected: bool) {
    let indicator = |label: &'static str, on: bool| {
        let style = if on {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        vec![Span::styled(format!("[{label}]"), style), Span::raw(" ")]
    };

    let cycle = |label: &str, value: &str| {
        let style = Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD);
        vec![
            Span::styled(format!("[{label}: {value}]"), style),
            Span::raw(" "),
        ]
    };

    let mut spans = Vec::new();
    spans.extend(indicator("Connected", connected));
    spans.extend(indicator("TLS", config.ldaps));
    spans.extend(indicator("Format (f)", config.format));
    spans.extend(indicator("Colors (c)", config.colors));
    spans.extend(indicator("Expand (a)", config.expand));
    spans.extend(indicator("Emoji (e)", config.emojis));
    spans.extend(indicator("Deleted (d)", config.deleted));
    spans.extend(cycle("Sort (s)", config.attrsort.label()));

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}
