//! Application state and top-level event/message dispatch loop.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::Event;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::mpsc;

use crate::cache::EntryCache;
use crate::config::ResolvedConfig;
use crate::ldap::{BackendFlavor, LdapClient};
use crate::tui::log_panel::LogPanel;
use crate::tui::pages::{Page, PageKind};

/// Shared, async-safe handle to the LDAP connection.
pub type SharedLdap = Arc<AsyncMutex<LdapClient>>;

/// Reason a search result set may be incomplete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Truncation {
    /// All results were returned.
    #[default]
    None,
    /// Server-imposed size limit (rc=4); normal for large result sets.
    SizeLimit,
    /// Administrative limit exceeded (rc=11); server cut off the scan early.
    AdminLimit,
}

/// Messages sent from async tasks back to the UI thread.
pub enum AppMsg {
    LdapResult(LdapResult),
    Error(String),
    /// Connection succeeded; carries the live client and detected flavor.
    Connected {
        root_dn: String,
        tls: bool,
        flavor: BackendFlavor,
        client: SharedLdap,
    },
    Disconnected,
    /// Children of a DN loaded from the server.
    ChildEntries {
        parent_dn: String,
        entries: Vec<ldap3::SearchEntry>,
    },
    /// Full entry fetched for the attributes panel.
    EntryFetched(ldap3::SearchEntry),
    /// Search completed; carries result entries and elapsed milliseconds.
    /// `truncation` indicates whether the server returned a partial result set.
    /// `generation` matches the `search_generation` counter at the time the search was fired;
    /// stale responses (from a superseded search) are discarded by the handler.
    SearchDone {
        generation: u64,
        filter: String,
        entries: Vec<ldap3::SearchEntry>,
        elapsed_ms: u64,
        truncation: Truncation,
    },
    /// A toggle key was pressed; pages should re-render with updated config.
    ConfigChanged(Box<ResolvedConfig>),
    /// Push a message to the application log panel.
    Log(String),
}

// Manual Debug for AppMsg because LdapClient doesn't derive Debug.
impl std::fmt::Debug for AppMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppMsg::LdapResult(r) => write!(f, "LdapResult({r:?})"),
            AppMsg::Error(e) => write!(f, "Error({e:?})"),
            AppMsg::Connected {
                root_dn,
                tls,
                flavor,
                ..
            } => {
                write!(
                    f,
                    "Connected {{ root_dn: {root_dn:?}, tls: {tls:?}, flavor: {flavor:?} }}"
                )
            }
            AppMsg::Disconnected => write!(f, "Disconnected"),
            AppMsg::ChildEntries { parent_dn, entries } => write!(
                f,
                "ChildEntries {{ parent_dn: {parent_dn:?}, count: {} }}",
                entries.len()
            ),
            AppMsg::EntryFetched(e) => write!(f, "EntryFetched({})", e.dn),
            AppMsg::SearchDone {
                filter,
                entries,
                generation,
                truncation,
                ..
            } => write!(
                f,
                "SearchDone(gen={generation}, {filter:?}, {} entries, {truncation:?})",
                entries.len()
            ),
            AppMsg::ConfigChanged(_) => write!(f, "ConfigChanged"),
            AppMsg::Log(msg) => write!(f, "Log({msg:?})"),
        }
    }
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
    pub ldap: Option<SharedLdap>,
    pub cache: EntryCache,
    pub connected: bool,
    pub log: LogPanel,
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
            cache: EntryCache::new(),
            connected: false,
            log: LogPanel::new(),
            msg_tx,
            msg_rx,
        }
    }

    pub fn render(&mut self, frame: &mut ratatui::Frame<'_>) {
        use crate::tui::layout::build_layout;
        let areas = build_layout(frame.area(), self.show_header);
        let visible = self.visible_pages();
        crate::tui::header::render(
            frame,
            areas.tab_bar,
            &self.pages,
            self.active_page,
            &visible,
        );
        if self.show_header {
            crate::tui::status_bar::render(frame, areas.status_bar, &self.config, self.connected);
        }
        self.pages[self.active_page].render(frame, areas.content);
        self.log.render(frame, areas.log_panel);
    }

    pub fn handle_event(&mut self, event: Event) -> Result<bool> {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent};
        if let Event::Mouse(mouse) = event {
            self.pages[self.active_page].handle_mouse(mouse);
            return Ok(false);
        }
        if let Event::Key(KeyEvent {
            code, modifiers, ..
        }) = event
        {
            if !self.pages[self.active_page].captures_input() {
                match (code, modifiers) {
                    (KeyCode::Char('q'), KeyModifiers::NONE) => return Ok(true),
                    (KeyCode::Char('h'), KeyModifiers::NONE) => {
                        self.show_header = !self.show_header;
                    }
                    (KeyCode::Char('j'), KeyModifiers::CONTROL) => self.next_page(),
                    (KeyCode::Char('f'), KeyModifiers::NONE) => {
                        self.config.format = !self.config.format;
                        self.broadcast_config();
                    }
                    (KeyCode::Char('e'), KeyModifiers::NONE) => {
                        self.config.emojis = !self.config.emojis;
                        self.broadcast_config();
                    }
                    (KeyCode::Char('c'), KeyModifiers::NONE) => {
                        self.config.colors = !self.config.colors;
                        self.broadcast_config();
                    }
                    (KeyCode::Char('a'), KeyModifiers::NONE) => {
                        self.config.expand = !self.config.expand;
                        self.broadcast_config();
                    }
                    (KeyCode::Char('d'), KeyModifiers::NONE) => {
                        self.config.deleted = !self.config.deleted;
                        self.broadcast_config();
                    }
                    (KeyCode::Char('s'), KeyModifiers::NONE) => {
                        self.config.attrsort = self.config.attrsort.next();
                        self.broadcast_config();
                    }
                    _ => {}
                }
            }
            self.pages[self.active_page].handle_key(code, modifiers)?;
        }
        Ok(false)
    }

    pub fn apply(&mut self, msg: AppMsg) {
        match msg {
            AppMsg::Connected {
                root_dn,
                tls,
                flavor,
                client,
            } => {
                self.connected = true;
                self.ldap = Some(client.clone());
                // Propagate the detected flavor into the app config so that all
                // subsequent ConfigChanged broadcasts carry the correct flavor.
                self.config.backend = flavor.clone();
                let tls_tag = if tls { " [TLS]" } else { "" };
                self.log.push(format!("Connected to {root_dn}{tls_tag}"));
                // Broadcast to ALL pages so every page gets the ldap handle, root_dn,
                // and the now-resolved flavor.
                for page in &mut self.pages {
                    page.apply_msg(AppMsg::Connected {
                        root_dn: root_dn.clone(),
                        tls,
                        flavor: flavor.clone(),
                        client: client.clone(),
                    });
                }
                // Broadcast updated config (with resolved flavor) to all pages.
                self.broadcast_config();
                // Ensure the active page is visible for the detected flavor.
                self.ensure_active_page_visible();
            }
            AppMsg::Disconnected => {
                self.connected = false;
                self.ldap = None;
                self.log.push("Disconnected.");
            }
            AppMsg::Error(e) => {
                self.log.push(format!("Error: {e}"));
            }
            AppMsg::EntryFetched(ref entry) => {
                // Populate cache with text attributes.
                if self.config.cache {
                    self.cache.add(entry.dn.clone(), entry.attrs.clone());
                }
                self.pages[self.active_page].apply_msg(msg);
            }
            // ConfigChanged must reach every page so toggling on one page
            // takes effect when the user switches to another.
            AppMsg::ConfigChanged(_) => {
                for page in &mut self.pages {
                    page.apply_msg(AppMsg::ConfigChanged(Box::new(self.config.clone())));
                }
            }
            AppMsg::Log(msg) => {
                self.log.push(msg);
            }
            AppMsg::ChildEntries { .. } | AppMsg::LdapResult(_) | AppMsg::SearchDone { .. } => {
                self.pages[self.active_page].apply_msg(msg);
            }
        }
    }

    fn next_page(&mut self) {
        let visible = self.visible_pages();
        if visible.is_empty() {
            return;
        }
        let pos = visible
            .iter()
            .position(|&i| i == self.active_page)
            .unwrap_or(0);
        self.active_page = visible[(pos + 1) % visible.len()];
    }

    /// Returns the indices of pages that should be shown for the current flavor.
    fn visible_pages(&self) -> Vec<usize> {
        self.pages
            .iter()
            .enumerate()
            .filter(|(_, p)| match p.required_flavor() {
                None => true,
                Some(f) => f == self.config.backend,
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// If the active page is not visible for the current flavor, snap to the first visible page.
    fn ensure_active_page_visible(&mut self) {
        let visible = self.visible_pages();
        if !visible.contains(&self.active_page) {
            self.active_page = visible.first().copied().unwrap_or(0);
        }
    }

    fn broadcast_config(&mut self) {
        let cfg = Box::new(self.config.clone());
        for page in &mut self.pages {
            page.apply_msg(AppMsg::ConfigChanged(cfg.clone()));
        }
    }
}

fn build_pages(_config: &ResolvedConfig, tx: mpsc::Sender<AppMsg>) -> Vec<Box<dyn Page>> {
    use crate::tui::pages::*;
    // All pages are always created. AD-specific pages (DACLs, GPOs, ADIDNS) filter
    // themselves via `required_flavor()` and are hidden until AD is detected.
    vec![
        Box::new(ExplorerPage::new(tx.clone())),
        Box::new(SearchPage::new(tx.clone())),
        Box::new(GroupsPage::new(tx.clone())),
        Box::new(DaclPage::new(tx.clone())),
        Box::new(GpoPage::new(tx.clone())),
        Box::new(DnsPage::new(tx.clone())),
        Box::new(HelpPage::new()),
    ]
}

pub async fn run(config: ResolvedConfig) -> Result<()> {
    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(config.clone());
    app.log
        .push(format!("Connecting to {}:{}…", config.server, config.port));

    let tx = app.msg_tx.clone();
    tokio::spawn(async move {
        match LdapClient::connect(&config).await {
            Ok(client) => {
                let root_dn = client.root_dn.clone();
                let tls = client.tls;
                let flavor = client.flavor.clone();
                let client = Arc::new(AsyncMutex::new(client));
                let _ = tx
                    .send(AppMsg::Connected {
                        root_dn,
                        tls,
                        flavor,
                        client,
                    })
                    .await;
            }
            Err(e) => {
                let _ = tx.send(AppMsg::Error(e.to_string())).await;
            }
        }
    });

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
        crossterm::event::DisableMouseCapture,
        crossterm::terminal::LeaveAlternateScreen
    )?;
    Ok(())
}
