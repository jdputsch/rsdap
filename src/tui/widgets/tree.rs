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

    /// Indices of nodes that are currently visible (parents all expanded).
    fn visible_indices(&self) -> Vec<usize> {
        // Track whether each depth level is currently expanded.
        // Use a Vec to avoid the fixed-size panic at depth ≥ 64.
        let mut depth_expanded: Vec<bool> = Vec::new();
        let mut visible = Vec::new();

        for (i, node) in self.nodes.iter().enumerate() {
            // Grow the tracking vec if this node is deeper than anything seen so far.
            if node.depth >= depth_expanded.len() {
                depth_expanded.resize(node.depth + 1, true);
            }

            let parent_visible = depth_expanded[..node.depth].iter().all(|&e| e);
            depth_expanded[node.depth] = node.expanded;

            if parent_visible {
                visible.push(i);
            }
        }
        visible
    }

    pub fn render(&mut self, frame: &mut Frame<'_>, area: Rect, title: &str) {
        self.render_with_style(frame, area, title, Style::default());
    }

    pub fn render_with_style(
        &mut self,
        frame: &mut Frame<'_>,
        area: Rect,
        title: &str,
        border_style: Style,
    ) {
        let visible = self.visible_indices();

        let items: Vec<ListItem> = visible
            .iter()
            .map(|&i| {
                let node = &self.nodes[i];
                let indent = "  ".repeat(node.depth);
                let marker = if node.has_children {
                    if node.expanded { "▼ " } else { "▶ " }
                } else {
                    "  "
                };
                let line = Line::from(vec![
                    Span::raw(indent),
                    Span::raw(marker),
                    Span::raw(node.label.clone()),
                ]);
                ListItem::new(line)
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title)
                    .border_style(border_style),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::White)
                    .add_modifier(Modifier::BOLD),
            );

        frame.render_stateful_widget(list, area, &mut self.state);
    }

    /// The currently selected node, if any.
    pub fn selected_node(&self) -> Option<&TreeNode> {
        let visible = self.visible_indices();
        self.state
            .selected()
            .and_then(|sel| visible.get(sel))
            .and_then(|&i| self.nodes.get(i))
    }

    /// Move selection down by one visible row.
    pub fn select_next(&mut self) {
        let count = self.visible_indices().len();
        if count == 0 {
            return;
        }
        let next = match self.state.selected() {
            Some(i) => (i + 1).min(count - 1),
            None => 0,
        };
        self.state.select(Some(next));
    }

    /// Move selection up by one visible row.
    pub fn select_prev(&mut self) {
        let count = self.visible_indices().len();
        if count == 0 {
            return;
        }
        let prev = match self.state.selected() {
            Some(0) | None => 0,
            Some(i) => i - 1,
        };
        self.state.select(Some(prev));
    }

    /// Expand the selected node. Returns its `id` if children need loading.
    pub fn expand_selected(&mut self) -> Option<String> {
        let visible = self.visible_indices();
        let node_idx = self
            .state
            .selected()
            .and_then(|sel| visible.get(sel).copied())?;
        let node = &mut self.nodes[node_idx];
        if !node.has_children {
            return None;
        }
        node.expanded = true;
        if !node.children_loaded {
            Some(node.id.clone())
        } else {
            None
        }
    }

    /// Collapse the selected node.
    pub fn collapse_selected(&mut self) {
        let visible = self.visible_indices();
        if let Some(node_idx) = self
            .state
            .selected()
            .and_then(|sel| visible.get(sel).copied())
        {
            self.nodes[node_idx].expanded = false;
        }
    }

    /// Insert child nodes after their parent in the flat vec, removing any stale children first.
    pub fn set_children(&mut self, parent_id: &str, children: Vec<TreeNode>) {
        let Some(parent_idx) = self.nodes.iter().position(|n| n.id == parent_id) else {
            return;
        };

        let parent_depth = self.nodes[parent_idx].depth;

        // Remove existing direct children (all nodes with depth == parent_depth + 1
        // that appear before the next sibling/uncle at depth <= parent_depth).
        let start = parent_idx + 1;
        let end = self.nodes[start..]
            .iter()
            .position(|n| n.depth <= parent_depth)
            .map(|rel| start + rel)
            .unwrap_or(self.nodes.len());

        self.nodes.drain(start..end);
        for (i, child) in children.into_iter().enumerate() {
            self.nodes.insert(start + i, child);
        }

        self.nodes[parent_idx].children_loaded = true;
    }
}

impl Default for TreeWidget {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, depth: usize, expanded: bool, has_children: bool) -> TreeNode {
        TreeNode {
            id: id.to_string(),
            label: id.to_string(),
            depth,
            expanded,
            has_children,
            children_loaded: false,
        }
    }

    #[test]
    fn flat_tree_all_visible() {
        let mut w = TreeWidget::new();
        w.nodes = vec![node("a", 0, false, false), node("b", 0, false, false)];
        let vis = w.visible_indices();
        assert_eq!(vis, vec![0, 1]);
    }

    #[test]
    fn collapsed_parent_hides_children() {
        let mut w = TreeWidget::new();
        w.nodes = vec![
            node("root", 0, false, true), // collapsed
            node("child1", 1, false, false),
            node("child2", 1, false, false),
        ];
        let vis = w.visible_indices();
        assert_eq!(
            vis,
            vec![0],
            "children of a collapsed parent should be hidden"
        );
    }

    #[test]
    fn expanded_parent_shows_children() {
        let mut w = TreeWidget::new();
        w.nodes = vec![
            node("root", 0, true, true), // expanded
            node("child1", 1, false, false),
            node("child2", 1, false, false),
        ];
        let vis = w.visible_indices();
        assert_eq!(vis, vec![0, 1, 2]);
    }

    #[test]
    fn nested_collapse_hides_grandchildren() {
        let mut w = TreeWidget::new();
        w.nodes = vec![
            node("root", 0, true, true),    // expanded
            node("child", 1, false, true),  // collapsed
            node("grand", 2, false, false), // hidden because parent collapsed
        ];
        let vis = w.visible_indices();
        assert_eq!(vis, vec![0, 1]);
    }

    #[test]
    fn set_children_inserts_and_replaces() {
        let mut w = TreeWidget::new();
        w.nodes = vec![node("root", 0, true, true)];
        w.set_children(
            "root",
            vec![node("a", 1, false, false), node("b", 1, false, false)],
        );
        assert_eq!(w.nodes.len(), 3);
        assert_eq!(w.nodes[1].id, "a");
        assert_eq!(w.nodes[2].id, "b");

        // Replace with one child.
        w.set_children("root", vec![node("c", 1, false, false)]);
        assert_eq!(w.nodes.len(), 2);
        assert_eq!(w.nodes[1].id, "c");
    }

    #[test]
    fn deep_tree_does_not_panic() {
        // Regression: depth ≥ 64 must not panic.
        let mut w = TreeWidget::new();
        let mut nodes = Vec::new();
        for depth in 0..128 {
            nodes.push(node(&format!("n{depth}"), depth, true, true));
        }
        w.nodes = nodes;
        // Should not panic.
        let vis = w.visible_indices();
        assert_eq!(vis.len(), 128);
    }
}
