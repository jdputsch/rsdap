# rsdap — Project Context & Coding Guidelines

## Overview

`rsdap` is a TUI LDAP client written in Rust. It is a clean-room reimplementation of
[godap](https://github.com/Macmod/godap), targeting Microsoft Active Directory and generic
LDAP directories. Features include multi-pane browsing, DACL/security descriptor inspection,
AD-integrated DNS management, GPO analysis, and multiple authentication methods (simple,
NTLM, Kerberos, certificate).

See `docs/SPEC-rust-rewrite.md` for the full feature specification.

---

## Essential Commands

```sh
cargo build                    # debug build
cargo build --release          # release build
cargo run -- <args>            # run the binary
cargo check                    # fast type-check without codegen
cargo test                     # run all tests
cargo clippy -- -D warnings    # lint (all warnings are errors in CI)
cargo fmt                      # format in place
cargo fmt --check              # check formatting (CI mode)
```

---

## Architecture

The codebase is organized around eight capability modules:

| Module | Responsibility |
|--------|---------------|
| `config` | CLI flag parsing (`clap`), YAML config loading, connection parameter resolution |
| `tui` | Event loop, page rendering, keybinding dispatch, widgets, color theming |
| `ldap` | Connection lifecycle, authentication, search with paging, CRUD, schema lookup |
| `net` | SSH local port forwarding (`russh`), SOCKS5 proxy (`tokio-socks`) |
| `security` | MS-DTYP security descriptor binary parsing, SID conversion, well-known SID table |
| `dns` | AD-Integrated DNS zone/node/record parsing (MS-DNSP), CRUD |
| `formats` | AD attribute value formatting (timestamps, bitmasks, SIDs, GUIDs) |
| `export` | JSON file writing |

Top-level coordination lives in `app.rs` (the `App` struct and message-dispatch loop).

### Async Architecture

- All network I/O (LDAP queries, SSH, SOCKS) runs on a `tokio` async runtime.
- The TUI render/input loop runs on the main thread.
- `tokio::sync::mpsc` channels carry results from async tasks back to the TUI thread.
- The event loop polls the channel with `try_recv()` each frame (≤50 ms timeout).

```rust
loop {
    terminal.draw(|f| app.render(f))?;
    if crossterm::event::poll(Duration::from_millis(50))? {
        app.handle_event(crossterm::event::read()?)?;
    }
    while let Ok(msg) = result_rx.try_recv() {
        app.apply(msg);
    }
}
```

### Shared State

The entry cache is `Arc<Mutex<HashMap<String, LdapEntry>>>` — written from async tasks,
read from the render thread.

---

## Rust Conventions

### Edition & MSRV

- Edition: **2024** (set in `Cargo.toml`).
- MSRV: **1.85** (first stable edition-2024 release).

### Error Handling

- Use `thiserror` for library-style (module-level) error types.
- Use `anyhow` for application-level error propagation in `main.rs` and `app.rs`.
- Never use `unwrap()` or `expect()` in non-test code unless the invariant is
  *provably* upheld and a comment explains why.
- Return `Result` from all fallible functions; propagate with `?`.

```rust
// Good — thiserror for a module's public error type
#[derive(Debug, thiserror::Error)]
pub enum LdapError {
    #[error("connection failed: {0}")]
    Connection(#[from] ldap3::LdapError),
    #[error("authentication failed")]
    AuthFailed,
}

// Good — anyhow for the top-level application
fn run() -> anyhow::Result<()> { ... }
```

### Naming & Style

- Follow standard Rust naming: `snake_case` functions/vars, `CamelCase` types,
  `SCREAMING_SNAKE_CASE` constants, `snake_case` modules.
- Module files use `mod.rs` only when the module has child files. Prefer flat
  `module_name.rs` for leaf modules.
- Keep functions short; extract helpers rather than nesting deeply.
- `use` imports at the top of the file, grouped: std → external crates → internal.
  `rustfmt.toml` enforces `group_imports = "StdExternalCrate"`.

### Async

- Annotate async entry points with `#[tokio::main]`.
- Prefer `tokio::spawn` for fire-and-forget background tasks.
- Use `tokio::sync::mpsc` for task-to-UI communication.
- Avoid `std::thread::sleep` in async contexts — use `tokio::time::sleep`.
- Mark blocking calls with `tokio::task::spawn_blocking` when mixing sync libs.

### Lifetimes & Ownership

- Prefer owned types in structs (`String`, `Vec<T>`) over borrowed (`&str`, `&[T]`)
  unless profiling shows allocation overhead.
- Use `Arc<T>` for shared ownership across async tasks; `Rc<T>` only in
  single-threaded contexts.
- Avoid `clone()` in hot paths; pass by reference or restructure ownership.

### Comments

- Write comments only when the *why* is non-obvious: a hidden constraint, a
  protocol quirk, a workaround for an upstream bug.
- Do not comment what the code does — well-named identifiers do that.
- Doc comments (`///`) on public items are encouraged for the module API surface.

### Panics

- `panic!`, `todo!()`, and `unimplemented!()` are acceptable in scaffolded stubs.
- Before shipping a feature, replace all `todo!()` bodies with real implementations.
- `unreachable!()` is acceptable for branches that are provably impossible.

### Clippy

- All clippy warnings are errors in CI (`-D warnings`).
- MSRV is set in `.clippy.toml`; do not use APIs newer than 1.85 without a version gate.
- Suppress specific lints only with a `#[allow(reason = "...")]` annotation.

---

## Dependencies

Add dependencies only when they provide substantial value over the standard library.
Prefer the crates listed in the spec (section 16):

| Feature | Crate |
|---------|-------|
| TUI | `ratatui`, `crossterm` |
| Async | `tokio` |
| LDAP | `ldap3` |
| CLI | `clap` (derive feature) |
| Config | `serde`, `serde_yaml`, `serde_json` |
| Errors | `anyhow`, `thiserror` |
| Tracing | `tracing`, `tracing-subscriber` |
| Regex | `regex` |
| SSH | `russh` |
| SOCKS5 | `tokio-socks` |
| Passwords | `rpassword` |
| Time | `chrono` |

When adding a new crate: check its maintenance status, audit `Cargo.lock` for
transitive deps, and prefer crates already in the dependency tree.

---

## Testing

- Unit tests live in a `#[cfg(test)]` module at the bottom of each source file.
- Integration tests go in `tests/`.
- Async tests use `#[tokio::test]`.
- Do not mock the LDAP server in integration tests — use a real LDAP instance
  (e.g., via Docker) or skip with `#[ignore]` and a comment.
- Target ≥ 80% line coverage for parsing/formatting logic in `security`, `dns`,
  and `formats`.

---

## TUI Conventions

- Each page implements the `Page` trait (`tui/pages/mod.rs`).
- Pages own their own focus state; the `App` only tracks which page is active.
- Modal forms render as an overlay drawn last in the frame; `Escape` dismisses them.
- Global keybindings are suppressed when a text input widget has focus.
- Use `ratatui::layout::Layout` for all layout; avoid hardcoded pixel offsets.
