//! Modal form widget: renders over the current page, captures all keyboard input.
//!
//! Supports text, password (masked), dropdown/select, checkbox, and read-only fields.
//! Escape dismisses; Tab cycles focus between fields.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

#[derive(Debug, Clone)]
pub enum FieldKind {
    Text,
    Password,
    Select { options: Vec<String> },
    Checkbox,
    ReadOnly,
}

#[derive(Debug, Clone)]
pub struct FormField {
    pub label: String,
    pub kind: FieldKind,
    pub value: String,
}

pub struct ModalForm {
    pub title: String,
    pub fields: Vec<FormField>,
    pub focused: usize,
    pub submitted: bool,
    pub cancelled: bool,
}

impl ModalForm {
    pub fn new(title: impl Into<String>, fields: Vec<FormField>) -> Self {
        Self {
            title: title.into(),
            fields,
            focused: 0,
            submitted: false,
            cancelled: false,
        }
    }

    pub fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        // Clear the area underneath before rendering the modal
        frame.render_widget(Clear, area);

        let block = Block::default()
            .borders(Borders::ALL)
            .title(self.title.as_str())
            .style(Style::default().fg(Color::White).bg(Color::DarkGray));

        frame.render_widget(block, area);

        // TODO: render each field inside the block with focus highlight
    }

    pub fn handle_char(&mut self, ch: char) {
        if let Some(field) = self.fields.get_mut(self.focused) {
            match &field.kind {
                FieldKind::Text | FieldKind::Password => field.value.push(ch),
                FieldKind::Select { options } => {
                    // TODO: arrow key navigation
                }
                FieldKind::Checkbox => {
                    if ch == ' ' {
                        field.value = if field.value == "true" {
                            "false".to_owned()
                        } else {
                            "true".to_owned()
                        };
                    }
                }
                FieldKind::ReadOnly => {}
            }
        }
    }

    pub fn next_field(&mut self) {
        self.focused = (self.focused + 1) % self.fields.len();
    }

    pub fn prev_field(&mut self) {
        self.focused = self.focused.checked_sub(1).unwrap_or(self.fields.len() - 1);
    }
}
