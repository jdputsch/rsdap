//! Tab bar rendering: numbered page tabs with the active page highlighted.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::pages::Page;

pub fn render(frame: &mut Frame<'_>, area: Rect, pages: &[Box<dyn Page>], active: usize) {
    let spans: Vec<Span> = pages
        .iter()
        .enumerate()
        .flat_map(|(i, page)| {
            let label = format!(" {} {} ", i + 1, page.title());
            let style = if i == active {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            [Span::styled(label, style), Span::raw(" ")]
        })
        .collect();

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}
