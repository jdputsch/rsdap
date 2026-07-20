# rsdap Phased Implementation Plan

## Context

The scaffold compiles and tests pass, but the app panics immediately at startup (`config::resolve` is a `todo!()`). The goal is a working LDAP browser: connect to a directory, navigate the tree, view entry attributes, and search — before tackling AD-specific features (DACL, GPO, ADIDNS, NTLM/Kerberos auth, security descriptors).

Phases are ordered so each one produces a **runnable, manually testable result** before moving on. AD-specific work is deferred to later phases.

---

## Testing Approach (all phases)

- **Unit tests** live in `#[cfg(test)]` modules at the bottom of each source file.
- **Integration tests** live in `tests/`. Async integration tests use `#[tokio::test]`.
- Tests that require a live LDAP server are marked `#[ignore]` with a comment explaining how to run them (e.g. `cargo test -- --ignored` against a local OpenLDAP Docker container).
- `just ci` runs `cargo test --all-targets`, which includes all non-ignored tests.
- Each phase adds a `just test-integration` recipe (or documents the `--ignored` invocation) once integration tests exist.
- The `#![allow(dead_code, unused_variables, unused_imports)]` crate-level attribute in `main.rs` is removed module by module as implementations are completed.

---

## Phase 1 — App Launches (no LDAP)

**Goal:** `cargo run -- someserver` opens the TUI without panicking. All pages render their placeholder layouts. `q` quits cleanly.

**Files to implement:**
- `src/config/mod.rs` — `resolve(args, file) -> ResolvedConfig`
  - Map CLI flags → `ResolvedConfig` fields with built-in defaults
  - Merge named connection from file config when `--connection` or positional arg matches
  - Apply `global:` config values as defaults beneath CLI flags
  - Resolve `AuthMethod` from credential flags (§2.6 mutual-exclusion validation)
  - Prompt for password interactively (`rpassword`) when `--username` given but no credential
  - Parse `BackendFlavor`, `TimeFmt`, `AttrSort` from string flags
  - Build `SshConfig` from `--ssh-*` flags when `--ssh-host` is set
  - Handle `init-config` and `version` subcommands (print and exit before TUI opens)
- `src/config/file.rs` — config file discovery uses `etcetera` (XDG strategy on Unix)
  - Linux/macOS: `$XDG_CONFIG_HOME/rsdap/config.yaml` (falls back to `~/.config/rsdap/config.yaml`)
  - Windows: `%APPDATA%\rsdap\config.yaml`

**Tests:**
- Unit: `resolve` with various flag combinations → correct `AuthMethod` variant
- Unit: mutual-exclusion validation returns errors for conflicting credential flags
- Unit: CLI flag overrides file config value; file config overrides built-in default
- Unit: `init-config` output is valid YAML that round-trips through `file::load`

**Manual verification:** `cargo run -- 127.0.0.1` opens the TUI; tab bar shows Explorer/Search/Groups/Help; `q` exits; `just ci` passes.

---

## Phase 2 — LDAP Connection & Simple Bind

**Goal:** The app connects to a real LDAP server (anonymous or username+password), discovers the root DN, and shows connection state in the log panel.

**Files to implement:**
- `src/ldap/connection.rs` — `LdapClient::connect`, `discover_root_dn`, `start_tls`
  - Plain TCP and LDAPS via `ldap3::LdapConnAsync`
  - Configurable timeout
  - Root DN discovery from RootDSE `namingContexts` (§5.5)
  - Auto backend detection when `BackendFlavor::Auto` (§5.2)
- `src/ldap/auth.rs` — `bind` dispatcher + `simple_bind` (anonymous + password only; NTLM/Kerberos Phase 9)
- `src/app.rs` — spawn tokio task on startup; send `AppMsg::Connected` / `AppMsg::Error`; update log panel
- `src/tui/log_panel.rs` — wire `VecDeque<(Instant, String)>` ring buffer on `App`; render last 3 entries

**Tests:**
- Unit: `discover_root_dn` selects the correct naming context (mock RootDSE response with multiple contexts)
- Unit: `auto` backend detection from RootDSE `objectClass` values
- Integration (`#[ignore]`): connect anonymously to local OpenLDAP; assert `root_dn` is non-empty
- Integration (`#[ignore]`): simple bind with valid credentials succeeds; invalid credentials returns `AuthFailed`

**Manual verification:** `cargo run -- ldap://localhost -u cn=admin,dc=example,dc=com -p secret` connects; log panel shows "Connected"; `[TLS]` indicator lights up for LDAPS.

---

## Phase 3 — Explorer Page: Tree Navigation

**Goal:** The Explorer page loads the root DN's immediate children and supports expand/collapse/navigate keyboard interaction.

**Files to implement:**
- `src/ldap/search.rs` — `search_all` with paged results (`ldap3` `PagedResults` control)
- `src/tui/pages/explorer.rs` — tree panel wired to real data:
  - On connection: fire `SingleLevel` search from root DN; populate tree
  - `→` / Enter: expand — fire child search, add nodes
  - `←`: collapse; `↑`/`↓`: navigate selection
  - `r`: reload selected node from server
  - Display name via `formats::display::entry_display_name`
  - Emoji prefix via `formats::display::emoji_for_entry` when `config.emojis`
- `src/tui/widgets/tree.rs` — add `select_next`, `select_prev`, `expand`, `collapse` methods
- `src/cache.rs` — add `explorer_cache: EntryCache` to `App`; `ExplorerPage` holds an `Arc<EntryCache>`

**Tests:**
- Unit: `entry_display_name` priority order (cn → ou → dc → name → uid → fallback)
- Unit: `emoji_for_entry` returns correct emoji for known object classes and fallback for unknown
- Unit: `TreeWidget` visible-node filtering with mixed expanded/collapsed nodes
- Integration (`#[ignore]`): expand root DN node; assert children returned match a direct `ldap3` search

**Manual verification:** Tree shows root DN children; expand a container; children load; `r` reloads from server; emojis appear.

---

## Phase 4 — Explorer Page: Attributes Panel

**Goal:** Selecting a tree node loads and displays the entry's attributes in the right panel with formatting and toggle support.

**Files to implement:**
- `src/tui/pages/explorer.rs` — attributes panel:
  - Two-column table: attribute name | value(s)
  - Expand mode: one row per value; collapsed: all values in one cell
  - Hidden-entries row when value count > `config.limit`
  - Attribute sort (none/asc/desc)
  - `Tab`/`Shift+Tab` cycles focus between tree and attributes panels
- `src/formats/attributes.rs` — `format_value` dispatcher (timestamps, SID, GUID, UAC bitmask)
- `src/formats/timestamp.rs` — `format_filetime` and `format_generalized_time`
- Global toggle keys (`f`, `e`, `c`, `a`, `s`) wired in `src/app.rs`

**Tests:**
- Unit: `format_filetime` for known timestamps (epoch, a known AD timestamp)
- Unit: `format_generalized_time` parses `YYYYMMDDHHmmss.0Z` correctly
- Unit: `guid_to_string` for a known 16-byte sequence
- Unit: `sid_to_string` for `S-1-5-18` (SYSTEM)
- Unit: `uac_flags` decodes a known bitmask to the expected flag list
- Unit: `ms_duration_format` for never / 1 day / 90 days (2 already pass; add more)

**Manual verification:** Selecting a user entry shows all attributes; toggling `f` switches raw↔formatted values; `a` collapses multi-value attrs; `s` cycles sort order.

---

## Phase 5 — Search Page

**Goal:** The Search page accepts a filter, executes a search, and displays results with the same attribute panel behavior as Explorer.

**Files to implement:**
- `src/tui/pages/search.rs` — full implementation:
  - Text input captures keystrokes; Enter fires search
  - `auto_wrap_filter` applied to bare terms
  - Results displayed via `TreeWidget`
  - Side panel: static predefined query library (basic LDAP queries; AD-specific deferred to Phase 9)
  - Search history table (timestamp, duration, result count, query)
  - Settings modal (base DN, scope, attribute list) using `tui/widgets/form.rs`
- `src/tui/widgets/form.rs` — implement field rendering and keyboard handling

**Tests:**
- Unit: search history entry is created with correct fields after a search completes
- Unit: bare-term filter wrapping (already tested; verify via search page logic path)
- Unit: form field cycling (Tab advances focus; Shift+Tab reverses)
- Integration (`#[ignore]`): search `(objectClass=*)` returns at least one result

**Manual verification:** Typing `(cn=*)` and pressing Enter returns entries; history row appears; selecting a result shows attributes.

---

## Phase 6 — Groups Page

**Goal:** The Groups page resolves group members and the groups an object belongs to, and supports adding/removing membership.

**Files to implement:**
- `src/tui/pages/groups.rs` — full implementation:
  - Group name input → Enter → members table
  - Object name input → Enter → groups table
  - MaxDepth input (0 = immediate, -1 = all nested via recursive search)
  - `Delete` removes member; `Ctrl+G` adds member
- `src/ldap/mutation.rs` — `add_attribute_value` and `delete_attribute_value`

**Tests:**
- Unit: `delete_attribute_value` builds the correct `ldap3::Mod` operation
- Unit: `add_attribute_value` builds the correct `ldap3::Mod` operation
- Integration (`#[ignore]`): add a member to a group; verify with a follow-up search; remove them; verify again

**Manual verification:** Enter a group DN → members appear; Delete removes one; enter a user DN → their groups appear.

---

## Phase 7 — Write Operations & Export

**Goal:** Complete Explorer write operations (create, delete, rename, attribute edit) and JSON export.

**Files to implement:**
- `src/ldap/mutation.rs` — `create_object`, `delete_object`, `move_object`, `modify_attribute`, `reset_password`
- `src/tui/pages/explorer.rs` — wire `Ctrl+N`, `Delete`, `Ctrl+L`, `Ctrl+E`, `Ctrl+N` (attrs), `Delete` (attrs), `Ctrl+S`
- `src/tui/widgets/form.rs` — complete all field types (password masked input, dropdown, checkbox)
- `src/export/json.rs` — already implemented; wire `Ctrl+S` calls through to it

**Tests:**
- Unit: `create_object` produces correct `ldap3` add request for each `ObjectClass` variant
- Unit: `move_object` builds correct ModifyDN request
- Unit: `reset_password` correctly UTF-16LE-encodes a password with surrounding quotes
- Unit: `export` writes a file with correct `{Data, Format}` structure and valid JSON
- Integration (`#[ignore]`): create an OU, rename it, add an attribute, delete the OU; assert clean state after

**Manual verification:** Create an OU; rename it; add/edit/delete an attribute; `Ctrl+S` produces a valid JSON file in `data/`.

---

## Phase 8 — Connection Form & Reconnect

**Goal:** `l` opens the connection configuration form at runtime; `Ctrl+R` reconnects; `Ctrl+U` issues StartTLS.

**Files to implement:**
- Connection config modal (`src/tui/connection_form.rs` or inline in `app.rs`)
- `LdapClient::start_tls` (stubbed in `connection.rs`)
- `AppMsg::Disconnected` handling — prompt to reconnect
- `src/net/socks.rs` — implement when SOCKS proxy field is exercised
- `src/net/ssh.rs` — implement SSH tunnel when SSH section is exercised

**Tests:**
- Unit: connection form pre-populates fields from `ResolvedConfig`
- Unit: "Update" action produces a new `ResolvedConfig` matching form values
- Integration (`#[ignore]`): StartTLS upgrade on a plain connection

**Manual verification:** Open form with `l`; change server; press Update; app reconnects to new host.

---

## Phase 9 — AD-Specific Features (deferred)

Implemented once the core browser is solid. Each item is its own sub-phase:

- NTLM and Kerberos authentication (`ldap/auth.rs`)
- Security descriptor parser (`security/`) + DACL page
- GPO page
- ADIDNS page (`dns/`)
- AD predefined query library for Search page
- Schema GUID loading (`--schema` flag)
- Deleted object handling (`--deleted` flag)
- `Ctrl+F` cache finder overlay

---

## Key Reuse Across Phases

| Existing implementation | Used in phase |
|---|---|
| `config/cli.rs` — complete clap struct | 1 |
| `config/file.rs` — YAML loader | 1 |
| `config/types.rs` — all runtime types | 1+ |
| `ldap/search.rs::auto_wrap_filter` | 3, 5 |
| `cache.rs` — full `EntryCache` | 3+ |
| `formats/display.rs` — `entry_display_name`, `emoji_for_entry` | 3 |
| `tui/layout.rs` — `build_layout` | 1 (already wired) |
| `tui/widgets/tree.rs` — skeleton | 3 (extend) |
| `export/json.rs` — full implementation | 7 |
