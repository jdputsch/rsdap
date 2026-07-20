//! Groups page: member lookup and group-membership lookup.

use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use tokio::sync::mpsc::Sender;

use super::Page;
use crate::app::AppMsg;

pub struct GroupsPage {
    tx: Sender<AppMsg>,
    modal_open: bool,
}

impl GroupsPage {
    pub fn new(tx: Sender<AppMsg>) -> Self {
        Self {
            tx,
            modal_open: false,
        }
    }
}

impl Page for GroupsPage {
    fn title(&self) -> &str {
        "Groups"
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
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(rows[1]);

        frame.render_widget(
            Block::default()
                .borders(Borders::ALL)
                .title("Group / Object"),
            rows[0],
        );
        frame.render_widget(
            Block::default().borders(Borders::ALL).title("Members"),
            cols[0],
        );
        frame.render_widget(
            Block::default().borders(Borders::ALL).title("Member Of"),
            cols[1],
        );
    }

    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Result<()> {
        Ok(())
    }

    fn apply_msg(&mut self, msg: AppMsg) {}
}
