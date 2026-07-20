//! Help page: scrollable table of all keybindings.

use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Cell, Row, Table};

use super::Page;
use crate::app::AppMsg;

static KEYBINDINGS: &[(&str, &str, &str)] = &[
    // (binding, context, action)
    ("q", "Global", "Quit"),
    ("f", "Global", "Toggle attribute formatting"),
    ("e", "Global", "Toggle emojis"),
    ("c", "Global", "Toggle colors"),
    ("a", "Global", "Toggle attribute expansion"),
    ("d", "Global", "Toggle deleted objects (MS AD)"),
    ("s", "Global", "Cycle attribute sort: none → asc → desc"),
    ("h", "Global", "Toggle header visibility"),
    ("l", "Global", "Open connection configuration form"),
    ("Ctrl+R", "Global", "Reconnect to server"),
    ("Ctrl+U", "Global", "Upgrade to TLS (StartTLS)"),
    ("Ctrl+J", "Global", "Next page"),
    ("→", "Tree", "Expand node"),
    ("←", "Tree", "Collapse node / navigate to parent"),
    ("r", "Tree", "Reload node"),
    ("Ctrl+N", "Tree", "Create new child object"),
    ("Ctrl+S", "Tree", "Export subtree to JSON"),
    ("Ctrl+P", "Tree", "Change password"),
    ("Ctrl+A", "Tree", "Edit userAccountControl"),
    ("Ctrl+L", "Tree", "Move / rename object"),
    ("Ctrl+G", "Tree", "Add member to group"),
    ("Ctrl+D", "Tree", "Inspect DACL"),
    ("Ctrl+F", "Tree", "Open cache finder"),
    ("Ctrl+B", "Tree", "Open explorer settings"),
    ("Delete", "Tree", "Delete selected object"),
    ("Ctrl+E", "Attributes", "Edit selected attribute value"),
    ("Ctrl+N", "Attributes", "Create new attribute"),
    ("Delete", "Attributes", "Delete attribute or value"),
    ("Enter", "Attributes", "Expand hidden entries"),
    ("r", "Attributes", "Reload attributes"),
    ("Ctrl+S", "Attributes", "Export to JSON"),
];

pub struct HelpPage;

impl HelpPage {
    pub fn new() -> Self {
        Self
    }
}

impl Page for HelpPage {
    fn title(&self) -> &str {
        "Help"
    }
    fn captures_input(&self) -> bool {
        false
    }

    fn render(&mut self, frame: &mut Frame<'_>, area: Rect) {
        let header = Row::new(vec!["Keybinding", "Context", "Action"])
            .style(Style::default().fg(Color::Yellow));

        let rows: Vec<Row> = KEYBINDINGS
            .iter()
            .map(|(key, ctx, action)| {
                Row::new(vec![
                    Cell::from(*key),
                    Cell::from(*ctx),
                    Cell::from(*action),
                ])
            })
            .collect();

        let widths = [
            ratatui::layout::Constraint::Length(12),
            ratatui::layout::Constraint::Length(14),
            ratatui::layout::Constraint::Min(20),
        ];

        let table = Table::new(rows, widths)
            .header(header)
            .block(Block::default().borders(Borders::ALL).title("Keybindings"));

        frame.render_widget(table, area);
    }

    fn handle_key(&mut self, _code: KeyCode, _modifiers: KeyModifiers) -> Result<()> {
        Ok(())
    }

    fn apply_msg(&mut self, _msg: AppMsg) {}
}
