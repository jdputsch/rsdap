//! Tab bar rendering: numbered page tabs with the active page highlighted.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::pages::Page;

pub fn render(
    frame: &mut Frame<'_>,
    area: Rect,
    pages: &[Box<dyn Page>],
    active: usize,
    visible: &[usize],
) {
    let spans: Vec<Span> = visible
        .iter()
        .enumerate()
        .flat_map(|(tab_pos, &page_idx)| {
            let label = format!(" {} {} ", tab_pos + 1, pages[page_idx].title());
            let style = if page_idx == active {
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
