# Spec: Color Display — Observable TUI Behavior

## Overview

Colors are controlled by the `--colors` / `-C` CLI flag (default: `true`) and the `c` / `C` keybinding at runtime. The header panel labeled **"Colors (c)"** shows `ON` in green or `OFF` in red to reflect the current state.

Toggling Colors affects five areas of the TUI. Many other elements are always colored regardless of this toggle (documented in section 7).

---

## Header State Panels

Every toggle-state panel in the header (TLS, Bind, Format, Emoji, Colors, Expand, Deleted) always shows:

- **ON** — text `ON`, green
- **OFF** — text `OFF`, red

The Sort panel shows `OFF` (red), `ASC` (green), or `DESC` (green).

---

## 1. Explorer Tree — Node Colors

**Affected by Colors toggle.**

| Node state | Colors ON | Colors OFF |
|------------|-----------|------------|
| Deleted + recycled | Red | Default (white) |
| Deleted, not recycled | Gray | Default (white) |
| Disabled account (UAC bit 2 set) | Yellow | Default (white) |
| All other nodes | Default (white) | Default (white) |

---

## 2. Search Results Tree — Node Colors

**Affected by Colors toggle.** Same rules as Explorer tree nodes.

---

## 3. Attribute Value Cells — Colors ON vs OFF

**Affected by Colors toggle.** When Colors is OFF, all attribute value cells render in the default text color. When Colors is ON, the following per-attribute coloring applies.

### Time-based attributes — colored by age of the timestamp value

**Attributes:** `lastLogonTimestamp`, `accountExpires`, `badPasswordTime`, `lastLogoff`, `lastLogon`, `pwdLastSet`, `creationTime`, `lockoutTime`, `whenCreated`, `whenChanged`

| Age | Color |
|-----|-------|
| ≤ 7 days | Green |
| ≤ 90 days | Yellow |
| > 90 days | Red |

### Lockout duration — colored by duration length

**Attributes:** `lockoutDuration`, `msDS-LockoutDuration`, `lockOutObservationWindow`, `msDS-LockoutObservationWindow`

| Duration | Color |
|----------|-------|
| ≤ 5 minutes | Green |
| ≤ 30 minutes | Yellow |
| > 30 minutes | Red |

### Maximum password age — shorter is more secure

**Attributes:** `maxPwdAge`, `msDS-MaximumPasswordAge`

| Value | Color |
|-------|-------|
| ≤ 30 days | Red |
| ≤ 90 days | Yellow |
| > 90 days | Green |

### Minimum password age

**Attributes:** `minPwdAge`, `msDS-MinimumPasswordAge`

| Value | Color |
|-------|-------|
| 0 (no minimum) | Green |
| ≤ 1 day | Yellow |
| > 1 day | Red |

### Force logoff timeout

**Attribute:** `forceLogoff`

| Value | Color |
|-------|-------|
| 0 (no forced logoff) | Red |
| ≤ 2 hours | Yellow |
| > 2 hours | Green |

### Kerberos TGT lifetimes

**Attributes:** `msDS-UserTGTLifetime`, `msDS-ComputerTGTLifetime`, `msDS-ServiceTGTLifetime`

| Value | Color |
|-------|-------|
| ≥ 24 hours | Green |
| ≥ 4 hours | Yellow |
| < 4 hours | Red |

### Lockout threshold

**Attributes:** `lockoutThreshold`, `msDS-LockoutThreshold`

| Value | Color |
|-------|-------|
| 0 (no lockout) | Green |
| < 5 | Red |
| ≥ 5 | Yellow |

### Minimum password length

**Attributes:** `minPwdLength`, `msDS-MinimumPasswordLength`

| Value | Color |
|-------|-------|
| ≥ 12 | Red |
| ≥ 8 | Yellow |
| < 8 | Green |

### Bad password count

**Attribute:** `badPwdCount`

| Value | Color |
|-------|-------|
| > 0 | Yellow |
| 0 | Green |

### Logon count

**Attribute:** `logonCount`

| Value | Color |
|-------|-------|
| ≥ 10 | Green |
| > 0 | Yellow |
| 0 | Red |

### GUID and SID — always gray (when Colors ON)

**Attributes:** `objectGUID`, `objectSid`

Always rendered gray when Colors is ON.

### Semantic value coloring — overrides attribute-based rules above

When Colors is ON, certain formatted value strings override any attribute-name-based color:

| Displayed value | Color |
|-----------------|-------|
| `TRUE`, `Enabled`, `Normal`, `PwdNotExpired` | Green |
| `FALSE`, `NotNormal`, `PwdExpired` | Red |
| `Disabled` | Yellow |

---

## 4. DNS Zone Properties Table — Value Column

**Affected by Colors toggle.**

When Colors is OFF, all values are plain text. When Colors is ON:

| Value | Color |
|-------|-------|
| `Enabled` | Green |
| `Disabled`, `None` | Red |
| `Unknown`, `Not specified` | Gray |
| Zone type `PRIMARY` | Green |
| Zone type `CACHE` | Blue |
| ALLOW_UPDATE `None` | Red |
| ALLOW_UPDATE `Nonsecure and secure` | Yellow |
| ALLOW_UPDATE `Secure only` | Green |
| ALLOW_UPDATE other | Gray |

Missing properties (not present in zone): `Not specified` shown in gray when Colors is ON, plain when OFF.

---

## 5. DNS Record Node Labels — Timestamp Color

**Affected by Colors toggle.**

Each record node label has the form `<TYPE> [TTL=<N>] (<timestamp>)`. The timestamp portion:

| Condition | Colors ON | Colors OFF |
|-----------|-----------|------------|
| Static record (msTime = 0) | Gray | Plain text |
| ≤ 7 days old | Green | Plain text |
| ≤ 90 days old | Yellow | Plain text |
| > 90 days old | Red | Plain text |

---

## 6. Log Bar

**Not affected by Colors toggle** — always colored:

| Message type | Color |
|--------------|-------|
| Success | Green |
| Warning / in-progress | Yellow |
| Error | Red |

---

## 7. Always-Colored Elements (not affected by Colors toggle)

### DACL Entries Panel

| Column | Condition | Color |
|--------|-----------|-------|
| ACE Type | Allow | Green |
| ACE Type | Deny | Red |
| Principal | SID unresolved | Red |
| Access/Mask | Severity 1 | Purple |
| Access/Mask | Severity 2 | Blue |
| Access/Mask | Severity 3 | Red |
| Inherited | True | Green |
| Inherited | False | Red |
| No Propagate | True | Green |
| No Propagate | False | Red |
| Owner | SID unresolved | Red |

### ACE Editor Form

| Element | Color |
|---------|-------|
| Type dropdown: `Allow` | Green |
| Type dropdown: `Deny` | Red |
| Mask cell (mask = 0) | Red |
| Mask cell (mask ≠ 0) | Green |
| Principal cell: resolved | Green |
| Principal cell: `Not Found` | Red |

### GPO Links Panel

| Column | Value | Color |
|--------|-------|-------|
| Enforced | Yes | Green |
| Enforced | No | Red |
| Enabled | Yes | Green |
| Enabled | No | Red |

### Cache Finder Panel

| Element | Color |
|---------|-------|
| Match type `ObjectDN` label | Blue |
| Match type `AttrName` label | Violet |
| Match type `AttrVal` label | Purple |
| Matched text segment | Green (highlighted within white) |
| Result count = 0 | Red |
| Result count > 0 | Default |

### Help Page

The godap version string in the Help page header is always rendered in blue.

### Page Tab Navigation Bar

All page tab labels are always rendered in dark cyan.

### Search Sub-tabs (Library / Attrs / History)

Always white text on black background.

### Form Validation

Add-member form: `Object not found` feedback always rendered in red.

---

## 8. Structural Theme Colors (always applied, not toggleable)

These are set globally via tview styles and affect all borders, titles, and default text:

| Role | Color |
|------|-------|
| Background | Black |
| Contrast background | Blue |
| Border | White |
| Title | White |
| Primary text | White |
| Secondary text (table headers) | Yellow |
| Tertiary text | Green |
