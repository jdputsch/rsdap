# Godap Rust Rewrite Specification

## Overview

**Godap** is a full-featured TUI (Terminal User Interface) application for browsing, searching, and modifying LDAP directories, with specialized support for Microsoft Active Directory. It supports multiple authentication methods, SSH tunneling, SOCKS proxy connections, DACL/security descriptor inspection and editing, AD-integrated DNS management, and GPO analysis.

This specification defines the requirements for a clean-room reimplementation in Rust, targeting:
- **ratatui** + **crossterm** for the TUI layer
- **tokio** for async I/O
- Rust standard library wherever possible
- Appropriate Rust LDAP, SSH, and crypto crates

---

## 1. Architecture

### 1.1 High-Level Components

```
┌──────────────────────────────────────────────────┐
│  CLI / Config Loader                             │
├──────────────────────────────────────────────────┤
│  TUI Application (ratatui + crossterm)           │
│  ┌─────────────────────────────────────────────┐ │
│  │ Pages: Explorer│Search│Groups│DACLs│GPOs│DNS│ │
│  │ Header: Status indicators / toggle flags     │ │
│  │ Log Panel: timestamped status messages       │ │
│  │ Page Switcher: numbered tab bar              │ │
│  └─────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────┤
│  LDAP Connection Layer                           │
├──────────────────────────────────────────────────┤
│  Network Layer                                   │
│  ┌─────────────┐ ┌───────────┐ ┌─────────────┐ │
│  │ TCP/TLS     │ │ SSH Tunnel│ │ SOCKS Proxy │ │
│  └─────────────┘ └───────────┘ └─────────────┘ │
├──────────────────────────────────────────────────┤
│  Utilities                                       │
└──────────────────────────────────────────────────┘
```

### 1.2 Top-Level Module Areas

The Rust implementation should be organized around the following capability domains. Internal file structure within each module is left to the implementer.

| Module | Responsibility |
|--------|---------------|
| `config` | YAML config file loading, CLI flag parsing, connection parameter resolution |
| `tui` | TUI event loop, page rendering, keybinding dispatch, widgets (tree, table, forms, overlays), color theming |
| `ldap` | LDAP connection lifecycle (plain, TLS, StartTLS), authentication (simple, NTLM, Kerberos, certificate), search with paging, object CRUD, schema GUID resolution, backend flavor detection |
| `net` | SSH local port forwarding, SOCKS5 proxy dialing |
| `security` | Security descriptor (MS-DTYP) binary parsing and encoding, SID string conversion, well-known SID table |
| `dns` | AD-Integrated DNS zone/node/record parsing per MS-DNSP, CRUD operations |
| `formats` | AD attribute value formatting (timestamps, bitmasks, SIDs, GUIDs), object class display names |
| `export` | JSON export file writing |

---

## 2. Command-Line Interface

### 2.1 Usage

```
rsdap [OPTIONS] [server_address | connection_name]
rsdap init-config [--output FILE]
rsdap version
```

### 2.2 Connection Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--port` | `-P` | 0 (auto: 389/636) | LDAP server port |
| `--username` | `-u` | | LDAP username |
| `--password` | `-p` | | LDAP password |
| `--passfile` | | | Path to password file (or `-` for stdin) |
| `--domain` | `-d` | | NTLM/Kerberos domain |
| `--hash` | `-H` | | NTLM hash |
| `--hashfile` | | | Path to NTLM hash file (or `-` for stdin) |
| `--kerberos` | `-k` | false | Use Kerberos (KRB5CCNAME env) |
| `--spn` | `-t` | | Target SPN for Kerberos |
| `--kdc` | | | KDC address (if different from server) |
| `--crt` | | | Client certificate path |
| `--key` | | | Client private key path |
| `--pfx` | | | PKCS#12 file path |
| `--ldaps` | `-S` | false | Use LDAPS |
| `--insecure` | `-I` | false | Skip TLS verification |
| `--socks` | `-x` | | SOCKS5 proxy address |
| `--timeout` | `-T` | 10 | Connection timeout (seconds) |
| `--backend` | `-b` | `msad` | Backend flavor: `msad`, `basic`, `auto` |

### 2.3 TUI Behavior Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--rootDN` | `-r` | (auto-detected) | Initial root DN |
| `--filter` | `-f` | `(objectClass=*)` | Initial search filter |
| `--emojis` | `-E` | true | Prefix objects with emojis |
| `--colors` | `-C` | true | Colorize objects |
| `--format` | `-F` | true | Format attributes human-readably |
| `--expand` | `-A` | true | Expand multi-value attributes |
| `--limit` | `-L` | 20 | Max attribute values shown when expanded |
| `--cache` | `-M` | true | Cache entries in memory |
| `--deleted` | `-D` | false | Include deleted objects (MS AD) |
| `--schema` | `-s` | false | Load schema GUIDs at startup |
| `--paging` | `-G` | 800 | LDAP paging size |
| `--timefmt` | | `EU` | Timestamp format: `EU`, `US`, `ISO8601`, or Go-style layout |
| `--offset` | | 0 | Hours offset for timestamps |
| `--attrsort` | | `none` | Attribute sort: `none`, `asc`, `desc` |
| `--exportdir` | | `data` | Export directory |
| `--debug-log` | | | Debug log file path |

### 2.4 SSH Tunnel Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--ssh-host` | | SSH server (setting enables tunnel) |
| `--ssh-port` | 22 | SSH port |
| `--ssh-user` | `$USER` | SSH username |
| `--ssh-auth` | (inferred) | Deprecated; auth inferred from other flags |
| `--ssh-password` | | SSH password |
| `--ssh-passfile` | | SSH password file (or `-` for stdin) |
| `--ssh-agent` | false | Use SSH agent |
| `--ssh-key` | | SSH private key path |
| `--ssh-key-passphrase` | | Passphrase for SSH key |
| `--ssh-ignore-host-key` | false | Skip SSH host key verification |

### 2.5 Config/Connection Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--config` | `-c` | Config file path (overrides discovery) |
| `--connection` | | Named connection from config |

### 2.6 Authentication Validation

Exactly one credential set must be provided (or none for anonymous bind):
- `{--username}` (prompts for password)
- `{--username, --password}`
- `{--username, --passfile}`
- `{--username, --hash}`
- `{--username, --hashfile}`
- `{--kerberos}`
- `{--crt, --key}`
- `{--pfx}`

### 2.7 Environment Variables

| Variable | Purpose |
|----------|---------|
| `RSDAP_PASSWD` | LDAP password (fallback when no `--password`/`--passfile`) |
| `RSDAP_SSH_PASSWORD` | SSH password (fallback) |
| `KRB5CCNAME` | Kerberos credential cache path |

### 2.8 Password Prompting

When `--username` is set but no password/hash/kerberos/cert method is provided, prompt interactively on the terminal for the LDAP password (masked input).

---

## 3. Configuration File

### 3.1 File Location (precedence order)

1. `--config` flag (explicit)
2. `./rsdap.yaml` (current directory)
3. Platform config directory via `etcetera` (XDG strategy on Unix, native on Windows):
   - Linux: `$XDG_CONFIG_HOME/rsdap/config.yaml` (default `~/.config/rsdap/config.yaml`)
   - macOS: `$XDG_CONFIG_HOME/rsdap/config.yaml` (default `~/.config/rsdap/config.yaml`)
   - Windows: `%APPDATA%\rsdap\config.yaml`

`etcetera` is used (with the XDG strategy unconditionally on Unix) rather than the Apple
strategy, because `rsdap` is a CLI/TUI tool whose users manage dotfiles via `~/.config`
and expect `$XDG_CONFIG_HOME` to be respected, even on macOS.

### 3.2 Structure (YAML)

```yaml
default_connection: <name>

global:
  emojis: true
  colors: true
  format: true
  expand: true
  limit: 20
  cache: true
  attrsort: none
  timefmt: ""
  offset: 0
  exportdir: data
  debug_log: ""

connections:
  - name: <string>
    server: <string>
    port: <int>
    ldaps: <bool>
    insecure: <bool>
    socks: <string>
    timeout: <int>
    backend: <string>  # msad | basic | auto
    username: <string>
    password: <string>
    passfile: <string>
    domain: <string>
    hash: <string>
    hashfile: <string>
    kerberos: <bool>
    spn: <string>
    kdc: <string>
    crt: <string>
    key: <string>
    pfx: <string>
    root_dn: <string>
    filter: <string>
    paging: <uint>
    schema: <bool>
    deleted: <bool>
    ssh:
      host: <string>
      port: <int>
      user: <string>
      password: <string>
      passfile: <string>
      agent: <bool>
      key: <string>
      key_passphrase: <string>
      ignore_host_key: <bool>
```

### 3.3 Precedence

CLI flags > config file values > built-in defaults.

The positional argument is first checked as a named connection; if no match, treated as a server address.

### 3.4 `init-config` Subcommand

Prints a fully-documented sample config to stdout (or writes to `--output` path).

---

## 4. Network Layer

### 4.1 LDAP Connection

- Support plain TCP (port 389) and LDAPS (port 636)
- Support StartTLS upgrade on plain connections
- Support configurable TLS certificate verification (skip with `--insecure`)
- Support client certificate authentication (PEM or PKCS#12)
- Connection timeout configurable in seconds
- Paged search results with configurable page size

### 4.2 SSH Tunnel

- Local port forwarding: listen on random `127.0.0.1:PORT`, forward through SSH to remote LDAP
- Auth methods: password, private key (with optional passphrase), SSH agent
- Host key verification via `~/.ssh/known_hosts` (or skip with flag)
- On unknown host key: surface a clear error with remediation instructions
- Tunnel lifecycle: close old tunnel before creating new one on reconnect
- Setting `--ssh-host` implicitly enables the tunnel

### 4.3 SOCKS5 Proxy

- Dial through a SOCKS5 proxy for the LDAP connection
- Works independently of / in addition to SSH tunneling
- Proxy address format: `socks5://host:port`

---

## 5. LDAP Operations

### 5.1 Connection & Authentication

| Method | Description |
|--------|-------------|
| Simple Bind | Username + password |
| Unauthenticated Bind | Username only, empty password |
| NTLM Bind | Domain + username + NT hash |
| Kerberos (GSSAPI/SPNEGO) | CCache file + KDC + SPN |
| External Bind | Client certificate (after StartTLS or LDAPS) |

### 5.2 Backend Flavor Detection

- **msad**: Microsoft Active Directory (default)
- **basic**: Generic LDAP (OpenLDAP, etc.)
- **auto**: Queries RootDSE `objectClass` — if contains `OpenLDAProotDSE`, use basic; otherwise msad

The flavor controls:
- Available pages (DACL, GPO, ADIDNS are MS AD only)
- Predefined query library content
- Group membership query strategy
- Object naming conventions (sAMAccountName vs cn/uid)

### 5.3 Search Operations

- Scopes: BaseObject, SingleLevel, WholeSubtree
- Paged results with configurable page size
- Support for MS AD "show deleted" control
- Optional attribute list restriction per query
- If search input lacks parentheses, auto-wrap: `(|(samAccountName=X)(cn=X)(ou=X)(name=X))`

### 5.4 Mutation Operations

| Operation | Details |
|-----------|---------|
| Create object | Types: OU, Container, User, Group, Computer. Supports `entryTTL` for dynamic objects. |
| Delete object | Simple delete by DN |
| Move/Rename | ModifyDN with new RDN and new parent |
| Modify attribute | Replace all values of an attribute |
| Add attribute | Add new attribute or append value |
| Delete attribute | Delete entire attribute or specific values |
| Reset password | Unicode-encoded `unicodePwd` replacement with policy hints control |
| Modify UAC | Replace `userAccountControl` bitmask |
| Modify DACL | Replace `nTSecurityDescriptor` with Microsoft SD Flags control |
| Group membership | Add/remove `member` attribute values |

### 5.5 Root DN Discovery

Query RootDSE for `namingContexts`, select the first that doesn't start with `CN=Schema`, `CN=Configuration`, `DC=DomainDnsZones`, or `DC=ForestDnsZones`.

---

## 6. TUI Layout & Navigation

### 6.1 Overall Layout

```
┌─────────────────────────────────────────────────┐
│ [1 Explorer  2 Search  3 Groups  ...]  Tab Bar  │ 1 row
├─────────────────────────────────────────────────┤
│ [timestamp] Last status message         Log     │ 3 rows
├─────────────────────────────────────────────────┤
│ TLS│Bind│Format│Colors│Expand│Sort│Emoji│Deleted│ 3 rows (header, toggleable)
├─────────────────────────────────────────────────┤
│                                                 │
│              Active Page Content                 │ remaining
│                                                 │
└─────────────────────────────────────────────────┘
```

### 6.2 Page Navigation

- `Ctrl+J` or clicking tab numbers: cycle to next page
- Pages available depend on flavor:
  - **MS AD**: Explorer, Search, Groups, DACLs, GPOs, ADIDNS, Help
  - **Basic LDAP**: Explorer, Search, Groups, Help

### 6.3 Global Keybindings

| Key | Action |
|-----|--------|
| `q` | Quit |
| `f` | Toggle attribute formatting |
| `e` | Toggle emojis |
| `c` | Toggle colors |
| `a` | Toggle attribute expansion |
| `d` | Toggle deleted objects (MS AD only) |
| `s` | Cycle attribute sort: none → asc → desc |
| `h` | Toggle header visibility |
| `l` | Open connection configuration form |
| `Ctrl+R` | Reconnect to server |
| `Ctrl+U` | Upgrade to TLS (StartTLS) |
| `Ctrl+J` | Next page |

Global keys are suppressed when a TextArea or InputField has focus.

### 6.4 Focus Management

- `Tab`/`Shift+Tab` within each page cycles focus between panels
- Each page defines its own focus rotation order
- Modal forms capture all input until dismissed

---

## 7. Pages

### 7.1 Explorer Page

**Layout**: Left panel (tree view) | Right panel (attributes table)

**Tree Panel**:
- Lazy-loading: children fetched on expand
- Nodes display: emoji prefix + name (derived from cn/ou/dc/name/uid)
- Color coding: red=recycled, gray=deleted, yellow=disabled (UAC bit 2)
- Sorted alphabetically by name

**Key bindings (Tree Panel)**:
| Key | Action |
|-----|--------|
| Right Arrow | Expand node (fetch children if needed) |
| Left Arrow | Collapse node (or navigate to parent) |
| `r` | Reload current node's attributes and children |
| `Ctrl+N` | Create new child object |
| `Ctrl+S` | Export loaded subtree to JSON |
| `Ctrl+P` | Change password of selected object |
| `Ctrl+A` | Edit userAccountControl interactively |
| `Ctrl+L` | Move/rename object |
| `Ctrl+G` | Add member to group (or add to group) |
| `Ctrl+D` | Inspect DACL (switches to DACL page) |
| `Ctrl+F` | Open cache finder (regex search) |
| `Ctrl+B` | Open explorer settings (base DN, filter, attributes) |
| Delete | Delete selected object |

**Attributes Panel**:
| Key | Action |
|-----|--------|
| `Ctrl+E` | Edit selected attribute value |
| `Ctrl+N` | Create new attribute |
| Delete (col 0) | Delete entire attribute |
| Delete (col 1) | Delete specific attribute value |
| Enter | Expand hidden entries (when `[N entries hidden]`) |
| `r` | Reload attributes from server |
| `Ctrl+S` | Export to JSON |

**Attributes Display Rules**:
- Two columns: attribute name | value(s)
- When `expand=true`: multi-value attributes show one value per row (name only on first row)
- When `expand=false`: all values concatenated in one cell
- Hidden entries: when attribute values exceed `limit`, show first N then `[M entries hidden]` row
- Sorting: none/asc/desc by attribute name
- Formatting: timestamps, UAC flags, SIDs, GUIDs converted to human-readable
- Color coding per attribute type (timestamps colored by age, boolean by value)
- Attribute anchor: when navigating the tree, remember which attribute was selected

### 7.2 Search Page

**Layout**:
- Top: Search filter input | Side panel tabs (Library / Attrs / History)
- Bottom: Search results tree | Side panel content

**Search behavior**:
- Enter in query field executes search
- Simple text (no parentheses) auto-wrapped: `(|(samAccountName=X)(cn=X)(ou=X)(name=X))`
- Results displayed as a tree (DN components become hierarchy)
- Configurable: base DN, scope (WholeSubtree/SingleLevel/BaseObject), attributes list
- Search history: table tracking timestamp, duration, results count, query, base DN, scope
- Predefined query library (categorized by topic)

**Predefined Queries (MS AD)**:
- Security: AdminSDHolder, Kerberoastable, AS-REP roastable, unconstrained delegation, etc.
- Group Members: Domain Admins, Enterprise Admins, etc.
- Users: Enabled, disabled, locked, password never expires, etc.
- Computers: Domain controllers, servers, workstations
- Enum: Trusts, GPOs, OUs, subnets, etc.

**Predefined Queries (Basic LDAP)**:
- Users: posixAccount, inetOrgPerson, etc.
- Groups: groupOfNames, posixGroup, etc.
- Enum: OUs, domains, etc.

**Key bindings (Search Tree)**:
- Same as Explorer tree (Ctrl+N, Ctrl+P, Ctrl+A, Ctrl+L, Ctrl+G, Ctrl+D, Ctrl+S, Delete, r)

### 7.3 Groups Page

**Layout**:
- Top: [MaxDepth input] Group name input | Object name input
- Bottom: Members table | Object Groups table

**Behavior**:
- Type group name/DN → Enter → shows members
- Type object name/DN → Enter → shows groups containing object
- MaxDepth: 0=immediate only, -1=all nested (uses `LDAP_MATCHING_RULE_IN_CHAIN` for MS AD)
- Click member row → auto-fills object input
- Click group row → auto-fills group input

**MS AD** members display: sAMAccountName, category emoji, DN
**Basic LDAP** members display: member DN values

**Key bindings**:
| Key | Action |
|-----|--------|
| Tab | Rotate focus |
| Delete | Remove member from group |
| `Ctrl+S` | Export members/groups to JSON |
| `Ctrl+G` | Add member to group |
| `Ctrl+D` | Inspect DACL of selected |

### 7.4 DACL Page (MS AD only)

**Layout**:
- Row 1: Object input | Owner display
- Row 2: Control flags | ACE mask (decimal) | ACE mask (binary)
- Main: DACL entries table

**DACL Table Columns**: Type (Allow/Deny), Principal, Access, Inherited, Scope, No Propagate

**ACE Types Parsed** (per MS-DTYP):
- `ACCESS_ALLOWED_ACE_TYPE` (0x00) — allow access
- `ACCESS_DENIED_ACE_TYPE` (0x01) — deny access
- `ACCESS_ALLOWED_OBJECT_ACE_TYPE` (0x05) — allow with optional object type and inherited object type GUIDs
- `ACCESS_DENIED_OBJECT_ACE_TYPE` (0x06) — deny with optional object type and inherited object type GUIDs
- Unrecognized ACE types: display raw bytes as fallback

**ACE Mask Resolution**: Converts permission bits to human-readable right names. Color coding distinguishes high-impact rights (e.g., full control, write DACL, write owner) from lower-impact rights (e.g., read-only), with the specific color scheme being an implementation choice.

**Principal Resolution**: SID → sAMAccountName lookup (cached during session). Well-known SIDs mapped from built-in table.

**Scope Resolution**: ACE flags parsed to determine inheritance scope (e.g., "This object only", "All child objects", specific object types via inherited object type GUID).

**Key bindings**:
| Key | Action |
|-----|--------|
| Tab | Rotate focus (input ↔ table) |
| `Ctrl+O` | Change DACL owner |
| `Ctrl+K` | Edit control flags |
| `Ctrl+N` | Create new ACE |
| `Ctrl+E` | Edit selected ACE |
| `Ctrl+S` | Export SD to JSON |
| Delete | Delete selected ACE |

**Schema GUID Resolution** (when `--schema` enabled):
- Load extended rights from `CN=Extended-Rights,CN=Configuration,...`
- Load class/attribute schema GUIDs from schema naming context
- Map GUIDs in object ACEs to human-readable names

### 7.5 GPO Page (MS AD only)

**Layout**:
- Top: Target input (DN or cn, or blank for all)
- Bottom left: GPO list table (Name, Created, Changed, GUID)
- Bottom right: GPO path + Links table (Target, Enforced, Enabled)

**Behavior**:
1. Query all objects with `gpLink` attribute
2. Parse gpLink values: `[LDAP://CN={GUID},...;flags]`
3. If target specified: walk DN hierarchy to find applicable GPOs
4. Display GPOs with their filesystem paths and link targets
5. Clicking a link target fills the target input for navigation

**Key bindings**: Tab (rotate), Ctrl+S (export)

### 7.6 ADIDNS Page (MS AD only)

**Layout**:
- Top: Zone search input | Node filter (regex) | Zone filter (regex)
- Bottom left: Zones & Nodes tree
- Bottom right: Zone Properties table OR Node Records tree

**Behavior**:
- Enter in zone search: query DomainDnsZones and ForestDnsZones containers
- Zones displayed with emoji: 🌐 (domain) / 🌲 (forest)
- Nodes displayed with emoji: 📃
- Zone properties: parsed `dNSProperty` attribute values
- Node records: parsed `dnsRecord` attribute values with type, TTL, timestamp, fields
- Filters applied as regex on zone/node names (live filtering)

**DNS Record Types Supported**: A, AAAA, NS, CNAME, SOA, PTR, MX, SRV, TXT, and others per MS-DNSP spec

**Key bindings (DNS Tree)**:
| Key | Action |
|-----|--------|
| Right/Left | Expand/collapse |
| `r` | Reload zone nodes or node records |
| `Ctrl+N` | Create new zone (at root) or node (at zone) |
| `Ctrl+E` | Edit node records |
| `Ctrl+S` | Export to JSON |
| Delete | Delete zone or node |

**Key bindings (Records Tree)**:
| Key | Action |
|-----|--------|
| `Ctrl+E` | Edit parent node's records |
| Delete | Delete selected record |

### 7.7 Help Page

Displays a scrollable table of all keybindings with columns: Keybinding, Context, Action.

---

## 8. Entry Cache

### 8.1 Structure

Thread-safe map: `DN → LDAP Entry (all attributes)`

Separate caches for:
- Explorer page
- Search page

### 8.2 Operations

- `add(dn, entry)`: Store/update entry
- `get(dn) → Option<Entry>`: Retrieve
- `delete(dn)`: Remove single entry
- `clear()`: Remove all entries
- `length() → usize`: Count
- `find_with_regexp(pattern) → Vec<Match>`: Search across all cached DNs, attribute names, and attribute values

### 8.3 Behavior

- When `cache=true`: entries kept in memory, only re-fetched on explicit reload (`r`)
- When `cache=false`: entries evicted when tree nodes are collapsed

---

## 9. Cache Finder (Ctrl+F)

A modal overlay that regex-searches across all cached entries.

**Match categories**:
- DN match: the entry's distinguished name matches the pattern
- Attribute name match: an attribute name matches the pattern
- Attribute value match: an attribute value matches the pattern (records which value index matched)

**Display**: Table with columns: Match Category, Object DN, Attribute Name, Attribute Value, Value Index. Matched text highlighted in green.

---

## 10. Export System

### 10.1 Format

JSON files with structure:
```json
{
  "Data": { ... },
  "Format": "<format_type>"
}
```

### 10.2 File Naming

`<unix_timestamp_ms>_<suffix>.json` in the configured export directory.

### 10.3 Export Types

| Suffix | Format | Source |
|--------|--------|--------|
| `objects` | `tree_objects` | Explorer/Search tree subtree |
| `results` | `tree_objects` | Search results |
| `members` | `group_members` | Group members |
| `groups` | `object_groups` | Object's groups |
| `sd` | `security_descriptor` | DACL + parsed ACEs |
| `gpos` | `gpos` | GPOs + links |
| `dns` | `adidns` | DNS zones + nodes + records |

---

## 11. Security Descriptor Parser

### 11.1 Binary Format (MS-DTYP)

Parse the `nTSecurityDescriptor` attribute (hex-encoded binary) into:
- Header (revision, control flags)
- Owner SID
- Group SID
- DACL (list of ACEs)
- SACL (optional)

### 11.2 ACE Types (per MS-DTYP)

- **ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE (0x00, 0x01)**: ACE header + access mask + SID
- **ACCESS_ALLOWED_OBJECT_ACE / ACCESS_DENIED_OBJECT_ACE (0x05, 0x06)**: ACE header + access mask + object type flags + optional ObjectType GUID + optional InheritedObjectType GUID + SID

### 11.3 Control Flags

Bitmask values: SE_DACL_PRESENT, SE_DACL_DEFAULTED, SE_DACL_AUTO_INHERITED, SE_DACL_PROTECTED, SE_SACL_PRESENT, etc.

### 11.4 ACE Mask Interpretation

Map permission bits to names:
- Generic: READ, WRITE, EXECUTE, ALL
- Standard: DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER, SYNCHRONIZE
- DS-specific: READ_PROP, WRITE_PROP, CREATE_CHILD, DELETE_CHILD, LIST_CHILDREN, SELF, LIST_OBJECT, CONTROL_ACCESS
- When ObjectType GUID present: resolve to specific property/right name

### 11.5 Well-Known SIDs

Maintain a built-in map of well-known SIDs (S-1-5-18 → SYSTEM, S-1-5-32-544 → Administrators, etc.) plus AD-specific GUIDs for rights and property sets.

---

## 12. AD-Integrated DNS

### 12.1 Zone Discovery

- Query `CN=MicrosoftDNS,DC=DomainDnsZones,<rootDN>` for domain zones
- Query `CN=MicrosoftDNS,DC=ForestDnsZones,<rootDN>` for forest zones
- Zone objects: `objectClass=dnsZone`

### 12.2 Zone Properties

Parse `dNSProperty` attribute (binary) per MS-DNSP spec:
- Property ID → name mapping (e.g., ZONE_TYPE, ALLOW_UPDATE, AGING_STATE, etc.)
- Property values formatted based on type (timestamps, enums, durations)

### 12.3 Node Records

Parse `dnsRecord` attribute (binary) per MS-DNSP:
- Record header: type, data length, flags, serial, TTL, timestamp
- Record data: type-specific fields (IP for A/AAAA, name for CNAME/NS/PTR, priority+weight+port+target for SRV, etc.)

### 12.4 CRUD Operations

- Create zone: Add `dnsZone` object with `dNSProperty` attributes
- Create node: Add `dnsNode` object with `dnsRecord` attributes
- Update node: Replace `dnsRecord` attribute values
- Delete zone/node: Standard LDAP delete
- Delete individual record: Remove from `dnsRecord` multi-value

---

## 13. Attribute Formatting

### 13.1 Timestamp Formats

| Format Code | Pattern |
|-------------|---------|
| `EU` (default) | `DD/MM/YYYY HH:MM:SS` |
| `US` | `MM/DD/YYYY HH:MM:SS` |
| `ISO8601` | `YYYY-MM-DD HH:MM:SS` |
| Custom | Any strftime-compatible pattern |

### 13.2 AD-Specific Attribute Formatting

- **Windows FILETIME** (e.g., `lastLogonTimestamp`, `pwdLastSet`): Convert 100ns-since-1601 to datetime
- **Generalized Time** (e.g., `whenCreated`): Parse `YYYYMMDDHHmmss.0Z`
- **MS Duration** (e.g., `maxPwdAge`): Negative 100ns intervals → human duration
- **SID** (`objectSid`): Binary → `S-1-5-21-...` string format
- **GUID** (`objectGUID`): Binary → `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`
- **userAccountControl**: Bitmask → list of flag names (ACCOUNTDISABLE, DONT_EXPIRE_PASSWORD, etc.)
- **systemFlags**, **trustAttributes**, **pwdProperties**, **searchFlags**: Similar bitmask decoding

### 13.3 Color Coding

Time-based attributes colored by age:
- ≤7 days: green
- ≤90 days: yellow
- >90 days: red

Boolean-like values: TRUE/Enabled=green, FALSE/Disabled=yellow/red

---

## 14. Object Naming & Display

### 14.1 Name Resolution Priority

For each LDAP entry, the display name is derived from:
1. `cn` attribute
2. `ou` attribute
3. `dc` attribute
4. `name` attribute
5. `uid` attribute
6. Fallback: `<NoName:first_RDN_value>`

For domain entries (all components are DC=): show dotted domain form (e.g., `corp.example.com`)

### 14.2 Emoji Prefixes

Map `objectClass` values to emoji:
- user → 👤, computer → 💻, group → 👥, organizationalUnit → 📂
- container → 📁, domain → 🌐, groupPolicyContainer → ⚙️
- Many more (see full emoji map in source)

Fallback based on DN prefix: OU= → 📂, DC= → 🌐, else → 📁

### 14.3 Deleted Object Handling

Strip `DEL:<GUID>` suffix from names. Color: recycled=red, deleted=gray.

---

## 15. Connection Configuration Form

A full-screen modal form allowing runtime modification of:
- Server address, port, LDAPS, certificate verification, SOCKS proxy
- Domain name
- Authentication type (dropdown): Password, Password(file), NTLM, NTLM(file), Kerberos, Certificate(PEM), Certificate(PKCS#12)
- Credentials for selected auth type
- SSH tunnel settings (expandable section)

On "Update": applies new settings and triggers reconnection.

---

## 16. Recommended Rust Crates

| Feature | Recommended Crate(s) |
|---------|---------------------|
| TUI rendering | `ratatui` + `crossterm` |
| LDAP client | `ldap3` |
| SSH client / local port forwarding | `russh` or `ssh2` |
| SOCKS5 proxy dialing | `tokio-socks` or `fast-socks5` |
| YAML config parsing | `serde` + `serde_yaml` |
| Platform config/data directories | `etcetera` (XDG strategy on Unix, native on Windows) |
| CLI argument parsing | `clap` |
| Terminal raw mode / masked password input | `crossterm` |
| PKCS#12 / PFX certificate decoding | `p12` or `native-tls` |
| Kerberos / GSSAPI / SPNEGO | `sspi` (Windows) or `gssapi` / `krb5` |
| ASN.1 / BER encoding for custom LDAP controls | `rasn` or `der-parser` |
| TLS | `rustls` or `native-tls` |
| JSON serialization | `serde_json` |
| Regex | `regex` |
| Async runtime | `tokio` |

---

## 17. Rust Implementation Guidance

### 17.1 Async Architecture

LDAP queries, SSH tunnel setup, and SOCKS proxy connections are all blocking network operations. The TUI must remain responsive during these operations. Recommended approach:

- Run all network I/O on a `tokio` async runtime
- Keep the TUI render/input loop on the main thread
- Use channels (e.g., `tokio::sync::mpsc`) to send query results from async tasks back to the TUI thread
- Poll channels with a short timeout each frame to drain pending results without blocking

### 17.2 Concurrent Cache Access

The entry cache is read from the TUI thread and written from async query results. Safe concurrent access is required. Standard Rust options: `Arc<Mutex<_>>` for simple cases, or message-passing (send all mutations through a channel) for stricter single-ownership designs.

### 17.3 TUI Event Loop Pattern

The standard ratatui event loop pattern — draw, poll input with a timeout, process async results — works well here:

```rust
loop {
    terminal.draw(|f| app.render(f))?;

    if crossterm::event::poll(Duration::from_millis(50))? {
        let event = crossterm::event::read()?;
        app.handle_event(event)?;
    }

    // drain pending results from async tasks
    while let Ok(msg) = result_rx.try_recv() {
        app.apply(msg);
    }
}
```

### 17.4 Tree Widget

ratatui does not include a built-in expand/collapse tree widget. Options:
- `tui-tree-widget` community crate
- Custom widget implementing lazy-load on expand, collapse, keyboard navigation

### 17.5 Modal Forms

Modal forms (object creation, password change, ACE editor, connection config, etc.) must render over the current page and capture all keyboard input until dismissed. Implement as an overlay layer drawn last in the frame; Escape dismisses, Tab cycles focus between fields.

Form field types needed: text input, masked password input, dropdown/select, checkbox, read-only text view, action buttons.

### 17.6 Error Handling

- Network and LDAP errors: display in the log panel with timestamp; update the connection status indicator
- On connection loss: prompt the user to reconnect (the reconnect keybinding is `Ctrl+R`)
- SSH host key unknown: show a modal with the fingerprint and remediation instructions (e.g., `ssh-keyscan` command)

---

## 18. Version

Current version: `Godap v2.11.1`

The Rust version should start its own versioning scheme (e.g., `0.1.0`) while noting compatibility with the original's feature set.
