//! Explorer page: lazy-loading LDAP tree (left) + attributes table (right).

use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use tokio::sync::mpsc::Sender;

use super::Page;
use crate::app::{AppMsg, LdapResult};

pub struct ExplorerPage {
    tx: Sender<AppMsg>,
    modal_open: bool,
}

impl ExplorerPage {
    pub fn new(tx: Sender<AppMsg>) -> Self {
        Self {
            tx,
            modal_open: false,
        }
    }
}

impl Page for ExplorerPage {
    fn title(&self) -> &str {
        "Explorer"
    }
    fn captures_input(&self) -> bool {
        self.modal_open
    }

    fn render(&mut self, frame: &mut Frame<'_>, area: Rect) {
        use ratatui::layout::{Constraint, Direction, Layout};
        use ratatui::widgets::{Block, Borders};

        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(area);

        frame.render_widget(
            Block::default().borders(Borders::ALL).title("Tree"),
            chunks[0],
        );
        frame.render_widget(
            Block::default().borders(Borders::ALL).title("Attributes"),
            chunks[1],
        );
    }

    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Result<()> {
        // TODO: implement tree navigation, attribute editing, modal forms
        Ok(())
    }

    fn apply_msg(&mut self, msg: AppMsg) {
        // TODO: handle LdapResult::Entries to populate the tree/attributes panel
    }
}
