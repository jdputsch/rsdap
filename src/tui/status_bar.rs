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

    let mut spans = Vec::new();
    spans.extend(indicator("Connected", connected));
    spans.extend(indicator("TLS", config.ldaps));
    spans.extend(indicator("Format", config.format));
    spans.extend(indicator("Colors", config.colors));
    spans.extend(indicator("Expand", config.expand));
    spans.extend(indicator("Emoji", config.emojis));
    spans.extend(indicator("Deleted", config.deleted));

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}
