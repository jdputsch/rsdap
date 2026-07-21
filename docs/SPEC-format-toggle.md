# Spec: FormatAttrs Toggle — Observable Field Behavior

## Context

The `--format` / `-F` CLI flag (default: `true`) and the `f` keybinding in the TUI control a global `FormatAttrs` boolean. When ON, LDAP attribute values, DNS zone properties, and DNS record timestamps are displayed in human-readable form. When OFF, raw values are shown as returned by the LDAP server.

This spec describes every observable difference between FormatAttrs ON and OFF, expressed in terms of what text appears in the UI.

---

## 1. Attribute Table — Regular Attributes

### Binary attributes rendered as hex

**Attributes:** `logonHours`, `dSASignature`, `oMObjectClass`, `cACertificate`

| State | Cell content |
|-------|-------------|
| OFF | Raw binary; typically unreadable or empty |
| ON  | `HEX{<lowercase hex string>}` e.g. `HEX{ffffffffffff1f00...}` |

### SID attributes

**Attributes:** `objectSid`, `securityIdentifier`

| State | Cell content |
|-------|-------------|
| OFF | Raw binary bytes (unreadable) |
| ON  | `SID{S-1-5-21-<domain>-<rid>}` e.g. `SID{S-1-5-21-1234567890-987654321-123456789-500}` |

### GUID attributes

**Attributes:** `objectGUID`, `schemaIDGUID`, `attributeSecurityGUID`

| State | Cell content |
|-------|-------------|
| OFF | Raw binary bytes (unreadable) |
| ON  | `GUID{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` in standard UUID format |

### Timestamp attributes — GeneralizedTime

**Attributes:** `whenCreated`, `whenChanged`

| State | Cell content |
|-------|-------------|
| OFF | `20231115103045.0Z` (LDAP GeneralizedTime string) |
| ON  | `<date> (<distance>)` e.g. `15/11/2023 10:30:45 (247 days ago)` |

The date portion uses the active `TimeFormat`:
- EU (default): `DD/MM/YYYY HH:MM:SS`
- US: `MM/DD/YYYY HH:MM:SS`
- ISO8601: `YYYY-MM-DD HH:MM:SS`

Distance suffixes: `(N seconds ago)`, `(N minutes ago)`, `(N hours ago)`, `(yesterday)`, `(N days ago)`, and future equivalents `(N seconds/minutes/hours/days from now)`, `(tomorrow)`.

### Timestamp attributes — Windows FILETIME

**Attributes:** `lastLogonTimestamp`, `accountExpires`, `badPasswordTime`, `lastLogoff`, `lastLogon`, `pwdLastSet`, `creationTime`, `lockoutTime`

| State | Cell content |
|-------|-------------|
| OFF | Raw integer string e.g. `133456789012345678` |
| ON (raw `0`) | `(Never)` |
| ON (`accountExpires` = `9223372036854775807`) | `(Never)` |
| ON (other) | `<date> (<distance>)` same format as GeneralizedTime above |

### Duration attributes

**Attributes:** `msDS-MaximumPasswordAge`, `msDS-MinimumPasswordAge`, `msDS-LockoutDuration`, `msDS-LockoutObservationWindow`, `lockoutDuration`, `lockOutObservationWindow`, `maxPwdAge`, `minPwdAge`, `forceLogoff`, `msDS-UserTGTLifetime`, `msDS-ComputerTGTLifetime`, `msDS-ServiceTGTLifetime`

| State | Cell content |
|-------|-------------|
| OFF | Raw negative integer string e.g. `-36288000000000` |
| ON (zero duration) | `(None)` |
| ON (`forceLogoff` = `0`) | `(Instantly)` |
| ON (`forceLogoff` = `-9223372036854775808`) | `(Never)` |
| ON (non-zero) | Space-separated non-zero parts: `N days`, `N hours`, `N minutes`, `N seconds` e.g. `42 days`, `1 hours 30 minutes` |

### Threshold/length attributes with zero sentinel

**Attributes:** `lockoutThreshold`, `msDS-LockoutThreshold`, `minPwdLength`, `msDS-MinimumPasswordLength`

| State | Cell content |
|-------|-------------|
| OFF | Raw integer e.g. `0` |
| ON (value = `0`) | `(None)` |
| ON (non-zero) | Raw integer unchanged |

### `primaryGroupID`

| State | Cell content |
|-------|-------------|
| OFF | Raw RID integer e.g. `513` |
| ON (known RID) | Group name e.g. `Domain Admins` (512), `Domain Users` (513), `Domain Computers` (515), `Domain Controllers` (516) |
| ON (unknown RID) | Raw integer unchanged |

### `sAMAccountType`

| State | Cell content |
|-------|-------------|
| OFF | Raw integer e.g. `805306368` |
| ON (known) | Type string e.g. `User Object`, `Machine Account`, `Group Object`, `Domain Object` |
| ON (unknown) | Raw integer unchanged |

### `groupType`

| State | Cell content |
|-------|-------------|
| OFF | Raw integer e.g. `-2147483646` |
| ON (known) | Type string e.g. `Global Security Group`, `Universal Distribution Group` |
| ON (unknown) | Raw integer unchanged |

### `instanceType`

| State | Cell content |
|-------|-------------|
| OFF | Raw integer e.g. `4` |
| ON (known) | Type string e.g. `WritableObject`, `NamingContextHead` |
| ON (unknown) | Raw integer unchanged |

---

## 2. Attribute Table — Bitset Attributes (multi-row expansion)

These five attributes expand each set bit into a separate table row regardless of `ExpandAttrs` state, but only when `FormatAttrs` is ON.

**Attributes:** `userAccountControl`, `systemFlags`, `trustAttributes`, `pwdProperties`, `searchFlags`

| State | Display |
|-------|---------|
| OFF | Single cell with raw integer string e.g. `512` |
| ON  | One row per active bit/flag, each row showing the flag name string |

**`userAccountControl` flag names (ON state, only shown when bit is set — except noted):**

`Script`, `Disabled`/`Enabled` (always shown), `HomeDirRequired`, `LockedOut`, `PwdNotRequired`, `CannotChangePwd`, `EncryptedTextPwdAllowed`, `TmpDuplicateAccount`, `NormalAccount`, `InterdomainTrustAccount`, `WorkstationTrustAccount`, `ServerTrustAccount`, `DoNotExpirePwd`, `MNSLogonAccount`, `SmartcardRequired`, `TrustedForDelegation`, `NotDelegated`, `UseDESKeyOnly`, `DoNotRequirePreauth`, `PwdExpired`/`PwdNotExpired` (always shown), `TrustedToAuthForDelegation`, `PartialSecretsAccount`

**`systemFlags` flag names:** `FLAG_ATTR_NOT_REPLICATED`, `FLAG_ATTR_REQ_PARTIAL_SET_MEMBER`, `FLAG_ATTR_IS_CONSTRUCTED`, `FLAG_ATTR_IS_OPERATIONAL`, `FLAG_SCHEMA_BASE_OBJECT`, `FLAG_ATTR_IS_RDN`, `FLAG_DISALLOW_MOVE_ON_DELETE`, `FLAG_DOMAIN_DISALLOW_MOVE`, `FLAG_DOMAIN_DISALLOW_RENAME`, `FLAG_CONFIG_ALLOW_LIMITED_MOVE`, `FLAG_CONFIG_ALLOW_MOVE`, `FLAG_CONFIG_ALLOW_RENAME`, `FLAG_DISALLOW_DELETE`

**`trustAttributes` flag names:** `NON_TRANSITIVE`, `UPLEVEL_ONLY`, `QUARANTINED_DOMAIN`, `FOREST_TRANSITIVE`, `CROSS_ORGANIZATION`, `WITHIN_FOREST`, `TREAT_AS_EXTERNAL`, `USES_RC4_ENCRYPTION`, `CROSS_ORGANIZATION_NO_TGT_DELEGATION`, `PIM_TRUST`, `CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION`

**`pwdProperties` flag names:** `PASSWORD_COMPLEX`, `PASSWORD_NO_ANON_CHANGE`, `PASSWORD_NO_CLEAR_CHANGE`, `LOCKOUT_ADMINS`, `PASSWORD_STORE_CLEARTEXT`, `REFUSE_PASSWORD_CHANGE`

**`searchFlags` flag names:** `fATTINDEX`, `fPDNTATTINDEX`, `fANR`, `fPRESERVEONDELETE`, `fCOPY`, `fTUPLEINDEX`, `fSUBTREEATTINDEX`, `fCONFIDENTIAL`, `fNEVERVALUEAUDIT`, `fRODCFilteredAttribute`, `fEXTENDEDLINKTRACKING`, `fBASEONLY`, `fPARTITIONSECRET`

### Deletion guard for bitset attributes

When `FormatAttrs` is ON and the user attempts to delete a value from any of the five bitset attributes, the log bar shows:

```
Deletion of attribute values for '<attrName>' is not allowed when FormatAttrs is enabled, as it is a bitset.
```

The deletion is cancelled. This guard does not apply when FormatAttrs is OFF.

---

## 3. DNS Zone Properties Table

**Columns:** `Id | Description | Value`

| State | Value cell |
|-------|------------|
| OFF | `fmt.Sprintf("%v", rawData)` — Go default formatting of the exported property value |
| ON  | Human-readable per-property string (see below) |

**Per-property ON behavior:**

| Property | ON output |
|----------|-----------|
| TYPE (0x01) | `CACHE`, `PRIMARY`, `SECONDARY`, `STUB`, `FORWARDER`, `SECONDARY_CACHE`, or `UNKNOWN` |
| ALLOW_UPDATE (0x02) | `None`, `Nonsecure and secure`, `Secure only`, or `Unknown` |
| SECURE_TIME (0x08) | Date in active TimeFormat, or `Not specified` if time is zero |
| NOREFRESH_INTERVAL (0x10) | Duration string e.g. `2 days, 4 hours` or `6 hours` |
| REFRESH_INTERVAL (0x20) | Same format as above |
| AGING_STATE (0x40) | `Enabled` or `Disabled` |
| AGING_ENABLED_TIME (0x12) | Date in active TimeFormat, or `Not specified` |
| DCPROMO_CONVERT (0x83) | `No change`, `Move to DNS domain partition`, `Move to DNS forest partition`, or `Unknown` |
| Server arrays (0x90–0x92, 0x11, 0x82) | `[<ip1> <ip2> ...]` Go slice format |

Missing properties show `Not specified` (gray-colored when Colors is ON) in both states.

---

## 4. DNS Record Node Labels

Each DNS record appears in the tree as:

```
<TYPE> [TTL=<N>] (<timestamp>)
```

The `<timestamp>` portion:

| State | Timestamp display |
|-------|------------------|
| OFF | Raw Unix timestamp integer e.g. `1700044245` |
| ON, non-static record | Date in active TimeFormat e.g. `15/11/2023 10:30:45` (no distance suffix) |
| ON, static record (msTime = 0) | `static` |

With Colors ON, the timestamp is colorized: `gray` for static, `green` if ≤ 7 days old, `yellow` if ≤ 90 days old, `red` if > 90 days old.

---

## Scope notes

- All other attributes not listed above: FormatAttrs ON and OFF produce identical cell content (raw LDAP string value).
- `TimeFormat` and `TimeOffset` affect all date/time formatted outputs above but are independent of FormatAttrs.
- `ExpandAttrs` controls whether multi-value attributes each get their own row, but is orthogonal to FormatAttrs (the bitset expansion above happens regardless of ExpandAttrs).
