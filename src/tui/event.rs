//! Crossterm event polling helpers.

use std::time::Duration;

use anyhow::Result;
use crossterm::event::{Event, KeyCode, KeyModifiers};

/// Poll for a terminal event with a given timeout. Returns `None` on timeout.
pub fn poll_event(timeout: Duration) -> Result<Option<Event>> {
    if crossterm::event::poll(timeout)? {
        Ok(Some(crossterm::event::read()?))
    } else {
        Ok(None)
    }
}

/// Returns `true` if the event is the quit keybinding (`q` with no modifiers).
pub fn is_quit(event: &Event) -> bool {
    matches!(
        event,
        Event::Key(key) if key.code == KeyCode::Char('q') && key.modifiers == KeyModifiers::NONE
    )
}
