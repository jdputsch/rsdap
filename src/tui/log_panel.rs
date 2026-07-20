//! Log panel: last 3 lines of timestamped status messages.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Paragraph};

// TODO: wire up a shared log ring buffer once the app struct carries one.
pub fn render(frame: &mut Frame<'_>, area: Rect) {
    let placeholder = Paragraph::new("Ready.")
        .block(Block::default().borders(Borders::ALL).title("Log"))
        .style(Style::default().fg(Color::Gray));
    frame.render_widget(placeholder, area);
}
