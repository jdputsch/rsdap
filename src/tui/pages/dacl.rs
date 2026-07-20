//! DACL page (MS AD only): security descriptor inspection and editing.

use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use tokio::sync::mpsc::Sender;

use super::Page;
use crate::app::AppMsg;

pub struct DaclPage {
    tx: Sender<AppMsg>,
    modal_open: bool,
}

impl DaclPage {
    pub fn new(tx: Sender<AppMsg>) -> Self {
        Self {
            tx,
            modal_open: false,
        }
    }
}

impl Page for DaclPage {
    fn title(&self) -> &str {
        "DACLs"
    }
    fn captures_input(&self) -> bool {
        self.modal_open
    }

    fn render(&mut self, frame: &mut Frame<'_>, area: Rect) {
        use ratatui::layout::{Constraint, Direction, Layout};
        use ratatui::widgets::{Block, Borders};

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Min(0),
            ])
            .split(area);

        frame.render_widget(
            Block::default()
                .borders(Borders::ALL)
                .title("Object / Owner"),
            rows[0],
        );
        frame.render_widget(
            Block::default()
                .borders(Borders::ALL)
                .title("Control Flags / ACE Mask"),
            rows[1],
        );
        frame.render_widget(
            Block::default().borders(Borders::ALL).title("DACL Entries"),
            rows[2],
        );
    }

    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Result<()> {
        Ok(())
    }

    fn apply_msg(&mut self, msg: AppMsg) {}
}
