//! Log panel: ring buffer of timestamped status messages, showing the last N lines.

use std::collections::VecDeque;

use chrono::{DateTime, Local};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

const MAX_ENTRIES: usize = 64;

pub struct LogPanel {
    entries: VecDeque<(DateTime<Local>, String)>,
}

impl LogPanel {
    pub fn new() -> Self {
        Self {
            entries: VecDeque::with_capacity(MAX_ENTRIES),
        }
    }

    pub fn push(&mut self, msg: impl Into<String>) {
        if self.entries.len() == MAX_ENTRIES {
            self.entries.pop_front();
        }
        self.entries.push_back((Local::now(), msg.into()));
    }

    pub fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        let visible = (area.height.saturating_sub(2)) as usize;
        let lines: Vec<Line> = self
            .entries
            .iter()
            .rev()
            .take(visible.max(1))
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .map(|(ts, msg)| {
                let timestamp = ts.format("%Y-%m-%d %H:%M:%S").to_string();
                Line::from(vec![
                    Span::styled(
                        format!("[{timestamp}] "),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::raw(msg.clone()),
                ])
            })
            .collect();

        let text = if lines.is_empty() {
            vec![Line::from(Span::styled(
                "Ready.",
                Style::default().fg(Color::DarkGray),
            ))]
        } else {
            lines
        };

        frame.render_widget(
            Paragraph::new(text).block(Block::default().borders(Borders::ALL).title("Log")),
            area,
        );
    }
}

impl Default for LogPanel {
    fn default() -> Self {
        Self::new()
    }
}
