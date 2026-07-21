//! Modal form widget: renders over the current page, captures all keyboard input.
//!
//! Supports text, password (masked), dropdown/select, and read-only fields.
//! Escape dismisses; Tab/Shift+Tab cycles focus; Enter submits.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph};

#[derive(Debug, Clone)]
pub enum FieldKind {
    Text,
    Password,
    Select { options: Vec<String> },
    ReadOnly,
}

#[derive(Debug, Clone)]
pub struct FormField {
    pub label: String,
    pub kind: FieldKind,
    pub value: String,
}

impl FormField {
    pub fn text(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            kind: FieldKind::Text,
            value: value.into(),
        }
    }

    pub fn password(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            kind: FieldKind::Password,
            value: String::new(),
        }
    }

    pub fn select(
        label: impl Into<String>,
        options: Vec<String>,
        current: impl Into<String>,
    ) -> Self {
        Self {
            label: label.into(),
            kind: FieldKind::Select { options },
            value: current.into(),
        }
    }

    pub fn readonly(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            kind: FieldKind::ReadOnly,
            value: value.into(),
        }
    }
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

    /// Render the form centered in `area`.  Each field occupies one line.
    pub fn render(&self, frame: &mut Frame<'_>, area: Rect) {
        let field_count = self.fields.len() as u16;
        // Height: 2 border + 1 per field + 1 blank + 1 hint line
        let height = (field_count + 4).min(area.height);
        let width = (area.width * 3 / 4).max(40).min(area.width);
        let modal_area = centered_rect(width, height, area);

        frame.render_widget(Clear, modal_area);

        let block = Block::default()
            .borders(Borders::ALL)
            .title(self.title.as_str())
            .style(Style::default().fg(Color::White).bg(Color::DarkGray));

        let inner = block.inner(modal_area);
        frame.render_widget(block, modal_area);

        // Field rows + hint row at the bottom.
        let mut constraints: Vec<Constraint> =
            self.fields.iter().map(|_| Constraint::Length(1)).collect();
        constraints.push(Constraint::Min(0)); // spacer
        constraints.push(Constraint::Length(1)); // hint

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(inner);

        for (i, field) in self.fields.iter().enumerate() {
            let is_focused = i == self.focused;
            let label_style = if is_focused {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            let value_style = if is_focused {
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::REVERSED)
            } else {
                Style::default().fg(Color::White)
            };

            let display_value = match &field.kind {
                FieldKind::Password => "*".repeat(field.value.len()),
                _ => field.value.clone(),
            };

            let line = Line::from(vec![
                Span::styled(format!("{:<16} ", field.label), label_style),
                Span::styled(display_value, value_style),
            ]);
            frame.render_widget(Paragraph::new(line), rows[i]);
        }

        // Hint line.
        let hint_idx = self.fields.len() + 1;
        if hint_idx < rows.len() {
            let hint = Line::from(vec![
                Span::styled("Tab", Style::default().fg(Color::Yellow)),
                Span::raw(" next field  "),
                Span::styled("Enter", Style::default().fg(Color::Yellow)),
                Span::raw(" submit  "),
                Span::styled("Esc", Style::default().fg(Color::Yellow)),
                Span::raw(" cancel"),
            ]);
            frame.render_widget(Paragraph::new(hint), rows[hint_idx]);
        }
    }

    /// Render a dropdown overlay for a Select field when it is focused.
    pub fn render_dropdown(&self, frame: &mut Frame<'_>, area: Rect) {
        let field = &self.fields[self.focused];
        let FieldKind::Select { options } = &field.kind else {
            return;
        };
        let selected_idx = options.iter().position(|o| o == &field.value);
        let height = (options.len() as u16 + 2).min(area.height / 2);
        let width = (area.width * 3 / 4).max(40).min(area.width);
        let drop_area = centered_rect(width, height, area);

        frame.render_widget(Clear, drop_area);

        let items: Vec<ListItem> = options
            .iter()
            .map(|o| {
                let style = if Some(o) == selected_idx.map(|i| &options[i]) {
                    Style::default().fg(Color::Black).bg(Color::White)
                } else {
                    Style::default().fg(Color::White)
                };
                ListItem::new(Span::styled(o.as_str(), style))
            })
            .collect();

        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(field.label.as_str())
                .style(Style::default().bg(Color::DarkGray)),
        );
        frame.render_widget(list, drop_area);
    }

    /// Handle a regular character key.
    pub fn handle_char(&mut self, ch: char) {
        if let Some(field) = self.fields.get_mut(self.focused) {
            match &field.kind {
                FieldKind::Text | FieldKind::Password => field.value.push(ch),
                FieldKind::Select { options } => {
                    // Cycle options with any keypress.
                    let opts = options.clone();
                    let current = opts.iter().position(|o| o == &field.value).unwrap_or(0);
                    let next = (current + 1) % opts.len();
                    field.value = opts[next].clone();
                }
                FieldKind::ReadOnly => {}
            }
        }
    }

    /// Handle Backspace.
    pub fn handle_backspace(&mut self) {
        if let Some(field) = self.fields.get_mut(self.focused) {
            match field.kind {
                FieldKind::Text | FieldKind::Password => {
                    field.value.pop();
                }
                _ => {}
            }
        }
    }

    /// Advance focus to the next editable field (wraps).
    pub fn next_field(&mut self) {
        if self.fields.is_empty() {
            return;
        }
        self.focused = (self.focused + 1) % self.fields.len();
    }

    /// Move focus to the previous editable field (wraps).
    pub fn prev_field(&mut self) {
        if self.fields.is_empty() {
            return;
        }
        self.focused = self.focused.checked_sub(1).unwrap_or(self.fields.len() - 1);
    }

    /// Cycle the current Select field backward.
    pub fn prev_option(&mut self) {
        if let Some(field) = self.fields.get_mut(self.focused) {
            if let FieldKind::Select { options } = &field.kind {
                let opts = options.clone();
                if opts.is_empty() {
                    return;
                }
                let current = opts.iter().position(|o| o == &field.value).unwrap_or(0);
                let prev = if current == 0 {
                    opts.len() - 1
                } else {
                    current - 1
                };
                field.value = opts[prev].clone();
            }
        }
    }

    /// Cycle the current Select field forward.
    pub fn next_option(&mut self) {
        self.handle_char(' '); // reuse cycle logic
    }
}

/// Compute a centered rect of given `width` and `height` within `area`.
fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect {
        x,
        y,
        width: width.min(area.width),
        height: height.min(area.height),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_form() -> ModalForm {
        ModalForm::new(
            "Test",
            vec![
                FormField::text("Server", "ldap.example.com"),
                FormField::text("Port", "389"),
                FormField::password("Password"),
            ],
        )
    }

    #[test]
    fn tab_cycles_forward() {
        let mut f = make_form();
        assert_eq!(f.focused, 0);
        f.next_field();
        assert_eq!(f.focused, 1);
        f.next_field();
        assert_eq!(f.focused, 2);
        f.next_field();
        assert_eq!(f.focused, 0); // wraps
    }

    #[test]
    fn shift_tab_cycles_backward() {
        let mut f = make_form();
        f.prev_field();
        assert_eq!(f.focused, 2); // wraps to last
        f.prev_field();
        assert_eq!(f.focused, 1);
    }

    #[test]
    fn typing_appends_to_text_field() {
        let mut f = make_form();
        f.focused = 0;
        f.handle_char('X');
        assert_eq!(f.fields[0].value, "ldap.example.comX");
    }

    #[test]
    fn backspace_removes_last_char() {
        let mut f = make_form();
        f.focused = 0;
        f.handle_backspace();
        assert_eq!(f.fields[0].value, "ldap.example.co");
    }

    #[test]
    fn password_field_accepts_chars() {
        let mut f = make_form();
        f.focused = 2;
        f.handle_char('s');
        f.handle_char('3');
        f.handle_char('c');
        assert_eq!(f.fields[2].value, "s3c");
    }

    #[test]
    fn select_cycles_options() {
        let mut f = ModalForm::new(
            "T",
            vec![FormField::select(
                "Scope",
                vec!["base".into(), "one".into(), "sub".into()],
                "base",
            )],
        );
        f.next_option();
        assert_eq!(f.fields[0].value, "one");
        f.next_option();
        assert_eq!(f.fields[0].value, "sub");
        f.next_option();
        assert_eq!(f.fields[0].value, "base"); // wraps
    }

    #[test]
    fn readonly_field_ignores_input() {
        let mut f = ModalForm::new(
            "T",
            vec![FormField::readonly("DN", "cn=admin,dc=example,dc=com")],
        );
        f.handle_char('x');
        f.handle_backspace();
        assert_eq!(f.fields[0].value, "cn=admin,dc=example,dc=com");
    }
}
