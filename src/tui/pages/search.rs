//! Search page: filter input, predefined query library, and results tree.

use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use tokio::sync::mpsc::Sender;

use super::Page;
use crate::app::AppMsg;

pub struct SearchPage {
    tx: Sender<AppMsg>,
    query: String,
    modal_open: bool,
}

impl SearchPage {
    pub fn new(tx: Sender<AppMsg>) -> Self {
        Self {
            tx,
            query: String::new(),
            modal_open: false,
        }
    }
}

impl Page for SearchPage {
    fn title(&self) -> &str {
        "Search"
    }
    fn captures_input(&self) -> bool {
        self.modal_open
    }

    fn render(&mut self, frame: &mut Frame<'_>, area: Rect) {
        use ratatui::layout::{Constraint, Direction, Layout};
        use ratatui::widgets::{Block, Borders};

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0)])
            .split(area);

        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
            .split(rows[1]);

        frame.render_widget(
            Block::default().borders(Borders::ALL).title("Filter"),
            rows[0],
        );
        frame.render_widget(
            Block::default().borders(Borders::ALL).title("Results"),
            cols[0],
        );
        frame.render_widget(
            Block::default().borders(Borders::ALL).title("Library"),
            cols[1],
        );
    }

    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Result<()> {
        // TODO: capture filter input, execute search on Enter
        Ok(())
    }

    fn apply_msg(&mut self, msg: AppMsg) {
        // TODO: populate results tree from LdapResult
    }
}
