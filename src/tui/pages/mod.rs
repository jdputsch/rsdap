//! Page trait and page module re-exports.

use anyhow::Result;
use crossterm::event::{KeyCode, KeyModifiers, MouseEvent};
use ratatui::Frame;
use ratatui::layout::Rect;

use crate::app::AppMsg;

pub mod dacl;
pub mod dns;
pub mod explorer;
pub mod gpo;
pub mod groups;
pub mod help;
pub mod search;

pub use dacl::DaclPage;
pub use dns::DnsPage;
pub use explorer::ExplorerPage;
pub use gpo::GpoPage;
pub use groups::GroupsPage;
pub use help::HelpPage;
pub use search::SearchPage;

/// Identifies the kind of page for routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageKind {
    Explorer,
    Search,
    Groups,
    Dacl,
    Gpo,
    Dns,
    Help,
}

/// Trait implemented by every TUI page.
pub trait Page {
    /// Short label shown in the tab bar.
    fn title(&self) -> &str;

    /// Whether this page is currently capturing all keyboard input (e.g. a modal is open).
    fn captures_input(&self) -> bool;

    /// Render the page into the given area.
    fn render(&mut self, frame: &mut Frame<'_>, area: Rect);

    /// Handle a key event forwarded from the app event loop.
    fn handle_key(&mut self, code: KeyCode, modifiers: KeyModifiers) -> Result<()>;

    /// Handle a mouse event forwarded from the app event loop. Default: no-op.
    fn handle_mouse(&mut self, _event: MouseEvent) {}

    /// Apply an async result message from the LDAP task pool.
    fn apply_msg(&mut self, msg: AppMsg);
}
