//! Lazy-loading expand/collapse tree widget for the Explorer and ADIDNS pages.
//!
//! ratatui has no built-in tree widget, so this is a custom implementation.
//! Nodes are stored as a flat vec; visibility is computed on each render pass.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};

#[derive(Debug, Clone)]
pub struct TreeNode {
    pub id: String,
    pub label: String,
    pub depth: usize,
    pub expanded: bool,
    pub has_children: bool,
    pub children_loaded: bool,
}

pub struct TreeWidget {
    pub nodes: Vec<TreeNode>,
    pub state: ListState,
}

impl TreeWidget {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            state: ListState::default(),
        }
    }

    pub fn render(&mut self, frame: &mut Frame<'_>, area: Rect, title: &str) {
        // Collect into a temp vec first to release the immutable borrow on `self.nodes`
        // before the mutable borrow on `self.state`.
        let items: Vec<ListItem> = {
            let mut depth_expanded = [true; 64];
            self.nodes
                .iter()
                .filter(|node| {
                    let parent_visible = depth_expanded[..node.depth].iter().all(|&e| e);
                    if node.depth < depth_expanded.len() {
                        depth_expanded[node.depth] = node.expanded;
                    }
                    parent_visible
                })
                .map(|node| {
                    let indent = "  ".repeat(node.depth);
                    let expand_marker = if node.has_children {
                        if node.expanded { "▼ " } else { "▶ " }
                    } else {
                        "  "
                    };
                    let line = Line::from(vec![
                        Span::raw(indent),
                        Span::raw(expand_marker),
                        Span::raw(node.label.clone()),
                    ]);
                    ListItem::new(line)
                })
                .collect()
        };

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::White)
                    .add_modifier(Modifier::BOLD),
            );

        frame.render_stateful_widget(list, area, &mut self.state);
    }

    pub fn selected_node(&self) -> Option<&TreeNode> {
        self.state.selected().and_then(|i| self.nodes.get(i))
    }
}

impl Default for TreeWidget {
    fn default() -> Self {
        Self::new()
    }
}
