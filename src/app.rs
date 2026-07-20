//! Application state and top-level event/message dispatch loop.

use std::time::Duration;

use anyhow::Result;
use crossterm::event::Event;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio::sync::mpsc;

use crate::config::ResolvedConfig;
use crate::ldap::LdapClient;
use crate::tui::pages::{Page, PageKind};

/// Messages sent from async tasks back to the UI thread.
#[derive(Debug)]
pub enum AppMsg {
    LdapResult(LdapResult),
    Error(String),
    Connected,
    Disconnected,
}

/// Result of an LDAP operation, carrying data back to a page.
#[derive(Debug)]
pub enum LdapResult {
    Entries(Vec<ldap3::SearchEntry>),
    Entry(ldap3::SearchEntry),
    Done,
}

pub struct App {
    pub config: ResolvedConfig,
    pub active_page: usize,
    pub pages: Vec<Box<dyn Page>>,
    pub show_header: bool,
    pub ldap: Option<LdapClient>,
    pub msg_tx: mpsc::Sender<AppMsg>,
    msg_rx: mpsc::Receiver<AppMsg>,
}

impl App {
    pub fn new(config: ResolvedConfig) -> Self {
        let (msg_tx, msg_rx) = mpsc::channel(256);
        let pages = build_pages(&config, msg_tx.clone());
        App {
            config,
            active_page: 0,
            pages,
            show_header: true,
            ldap: None,
            msg_tx,
            msg_rx,
        }
    }

    pub fn render(&mut self, frame: &mut ratatui::Frame<'_>) {
        use crate::tui::layout::build_layout;
        let areas = build_layout(frame.area(), self.show_header);
        crate::tui::header::render(frame, areas.tab_bar, &self.pages, self.active_page);
        crate::tui::log_panel::render(frame, areas.log_panel);
        if self.show_header {
            crate::tui::status_bar::render(frame, areas.status_bar, &self.config);
        }
        self.pages[self.active_page].render(frame, areas.content);
    }

    pub fn handle_event(&mut self, event: Event) -> Result<bool> {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        if let Event::Key(KeyEvent {
            code, modifiers, ..
        }) = event
        {
            if !self.pages[self.active_page].captures_input() {
                match (code, modifiers) {
                    (KeyCode::Char('q'), KeyModifiers::NONE) => return Ok(true),
                    (KeyCode::Char('h'), KeyModifiers::NONE) => {
                        self.show_header = !self.show_header
                    }
                    (KeyCode::Char('j'), KeyModifiers::CONTROL) => self.next_page(),
                    _ => {}
                }
            }
            self.pages[self.active_page].handle_key(code, modifiers)?;
        }
        Ok(false)
    }

    pub fn apply(&mut self, msg: AppMsg) {
        self.pages[self.active_page].apply_msg(msg);
    }

    fn next_page(&mut self) {
        self.active_page = (self.active_page + 1) % self.pages.len();
    }
}

fn build_pages(config: &ResolvedConfig, tx: mpsc::Sender<AppMsg>) -> Vec<Box<dyn Page>> {
    use crate::tui::pages::*;
    let mut pages: Vec<Box<dyn Page>> = vec![
        Box::new(ExplorerPage::new(tx.clone())),
        Box::new(SearchPage::new(tx.clone())),
        Box::new(GroupsPage::new(tx.clone())),
    ];
    if config.backend == crate::ldap::BackendFlavor::MsAd {
        pages.push(Box::new(DaclPage::new(tx.clone())));
        pages.push(Box::new(GpoPage::new(tx.clone())));
        pages.push(Box::new(DnsPage::new(tx.clone())));
    }
    pages.push(Box::new(HelpPage::new()));
    pages
}

pub async fn run(config: ResolvedConfig) -> Result<()> {
    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(config);

    loop {
        terminal.draw(|f| app.render(f))?;

        if crossterm::event::poll(Duration::from_millis(50))? {
            let event = crossterm::event::read()?;
            if app.handle_event(event)? {
                break;
            }
        }

        while let Ok(msg) = app.msg_rx.try_recv() {
            app.apply(msg);
        }
    }

    crossterm::terminal::disable_raw_mode()?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::terminal::LeaveAlternateScreen
    )?;
    Ok(())
}
