# Search Page Specification

The Search page is the second tab in the global navigation bar, labeled **Search**.

---

## Layout

The page is divided into two rows.

### Row 1 — Control Bar

- An input field labeled **"Search Filter"** with placeholder text: `Type an LDAP search filter or the name of an object`. Occupies most of the bar width.
- A tab selector to the right with three labels: `Library | Attrs | History`. Selecting a tab switches the right panel.

### Row 2 — Main Content Area (split horizontally)

- **Left: Search Results tree** — displays matching objects in a hierarchical tree that mirrors the DN hierarchy under the search base.
- **Right: Side panel** — content depends on the active tab:
  - **Library** — a tree of predefined query categories and named queries.
  - **Attrs** — a two-column table showing attribute names and values for the currently selected result object.
  - **History** — a table of past searches with columns: `StartTime | Duration | Results | Query | BaseDN | Scope`.

---

## Running a Search

Type an LDAP filter or a plain name into the Search Filter field and press `Enter`.

- If the input is a plain name (no parentheses), the app automatically searches for it across `samAccountName`, `cn`, `ou`, and `name` — the user does not need to write the filter manually.
- Results appear in the Search Results tree, organized by DN hierarchy under the configured search base.
- When the search completes, the log bar at the bottom shows: `Query completed (N objects found in X.XXXXs)`.
- Each search is recorded in the History panel.

---

## Library Panel

Shows predefined queries organized by category in a collapsible tree. Top-level nodes are category names; child nodes are individual named queries. The tree is navigable via keyboard (arrow keys, Enter to select) and mouse (click to expand/collapse, click to run a query). Selecting a query populates the Search Filter and runs the search immediately.

Some library queries use time-relative placeholders (e.g., queries scoped to the last 24 hours or last 30 days) that are resolved at execution time.

Some queries (notably ADCS queries) use a specific Base DN override rather than the globally configured search base.

### MicrosoftAD flavor

#### Enum

| Name | Filter |
|---|---|
| All Organizational Units | `(objectCategory=organizationalUnit)` |
| All Containers | `(objectCategory=container)` |
| All Groups | `(objectCategory=group)` |
| All Computers | `(objectClass=computer)` |
| All Users | `(&(objectCategory=person)(objectClass=user))` |
| All Objects | `(objectClass=*)` |

#### Users

| Name | Filter |
|---|---|
| Recently Created Users | `(&(objectCategory=user)(whenCreated>=<timestamp1d>))` |
| Users With Description | `(&(objectCategory=user)(description=*))` |
| Users Without Email | `(&(objectCategory=user)(!(mail=*)))` |
| Likely Service Users | `(&(objectCategory=user)(sAMAccountName=*svc*))` |
| Disabled Users | `(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2))` |
| Expired Users | `(&(objectCategory=user)(accountExpires<=<timestamp>))` |
| Users With Sensitive Infos | `(&(objectCategory=user)(|(telephoneNumber=*)(pager=*)(homePhone=*)(mobile=*)(info=*)(streetAddress=*)))` |
| Inactive Users | `(&(objectCategory=user)(lastLogonTimestamp<=<timestamp30d>))` |

#### Computers

| Name | Filter |
|---|---|
| Domain Controllers | `(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))` |
| Non-DC Servers | `(&(objectCategory=computer)(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))` |
| Non-Server Computers | `(&(objectCategory=computer)(!(operatingSystem=*server*))(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))` |
| Stale Computers | `(&(objectCategory=computer)(!lastLogonTimestamp=*))` |
| Computers With Outdated OS | `(&(objectCategory=computer)(|(operatingSystem=*Server 2008*)(operatingSystem=*Server 2003*)(operatingSystem=*Windows XP*)(operatingSystem=*Windows 7*)))` |

#### Security

| Name | Filter | Base DN override |
|---|---|---|
| High Privilege Users | `(&(objectCategory=user)(adminCount=1))` | |
| Users With SPN | `(&(objectCategory=user)(servicePrincipalName=*))` | |
| Users With SIDHistory | `(&(objectCategory=person)(objectClass=user)(sidHistory=*))` | |
| KrbPreauth Disabled Users | `(&(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))` | |
| KrbPreauth Disabled Computers | `(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=4194304))` | |
| Constrained Delegation Objects | `(msDS-AllowedToDelegateTo=*)` | |
| Unconstrained Delegation Objects | `(userAccountControl:1.2.840.113556.1.4.803:=524288)` | |
| RBCD Objects | `(msDS-AllowedToActOnBehalfOfOtherIdentity=*)` | |
| Not Trusted For Delegation | `(&(samaccountname=*)(userAccountControl:1.2.840.113556.1.4.803:=1048576))` | |
| Shadow Credentials Targets | `(msDS-KeyCredentialLink=*)` | |
| Must Change Password Users | `(&(objectCategory=person)(objectClass=user)(pwdLastSet=0)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))` | |
| Password Never Changed Users | `(&(objectCategory=user)(pwdLastSet=0))` | |
| Never Expire Password Users | `(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))` | |
| Users with PASSWD_NOTREQD | `(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=32))` | |
| LockedOut Users | `(&(objectCategory=user)(lockoutTime>=1))` | |
| Trusted Domains | `(objectClass=trustedDomain)` | |
| ADCS Enterprise CAs | `(objectClass=pKIEnrollmentService)` | `CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,<root DN>` |
| ADCS Certificate Templates | `(objectClass=pKICertificateTemplate)` | `CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,<root DN>` |

#### Group Members

| Name | Filter |
|---|---|
| Enterprise Admins | `(memberOf=CN=Enterprise Admins,CN=Users,<root DN>)` |
| Administrators | `(memberOf=CN=Administrators,CN=Builtin,<root DN>)` |
| Domain Admins | `(memberOf=CN=Domain Admins,CN=Users,<root DN>)` |
| Schema Admins | `(memberOf=CN=Schema Admins,CN=Users,<root DN>)` |
| DNS Admins | `(memberOf=CN=DnsAdmins,CN=Users,<root DN>)` |
| Server Operators | `(memberOf=CN=Server Operators,CN=Builtin,<root DN>)` |
| Backup Operators | `(memberOf=CN=Backup Operators,CN=Builtin,<root DN>)` |
| Account Operators | `(memberOf=CN=Account Operators,CN=Builtin,<root DN>)` |
| WinRMRemoteWMIUsers__ | `(memberOf=CN=WinRMRemoteWMIUsers__,CN=Users,<root DN>)` |
| Group Policy Creator Owners | `(memberOf=CN=Group Policy Creator Owners,CN=Users,<root DN>)` |
| Remote Desktop Users | `(memberOf=CN=Remote Desktop Users,CN=Builtin,<root DN>)` |
| Remote Management Users | `(memberOf=CN=Remote Management Users,CN=Builtin,<root DN>)` |
| Print Operators | `(memberOf=CN=Print Operators,CN=Builtin,<root DN>)` |
| DHCP Administrators | `(memberOf=CN=DHCP Administrators,CN=Users,<root DN>)` |
| Hyper-V Administrators | `(memberOf=CN=Hyper-V Administrators,CN=Builtin,<root DN>)` |
| Cert Publishers | `(memberOf=CN=Cert Publishers,CN=Users,<root DN>)` |
| Protected Users | `(memberOf=CN=Protected Users,CN=Users,<root DN>)` |

> `<root DN>` is substituted with the directory's root DN at runtime.

---

### BasicLDAP flavor

#### Enum

| Name | Filter |
|---|---|
| All Organizations | `(objectClass=organization)` |
| All Users | `(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=person))` |
| All Groups | `(|(objectClass=posixGroup)(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))` |
| All Computers | `(|(objectClass=ipHost)(objectClass=device))` |
| All Organizational Units | `(objectClass=organizationalUnit)` |
| All Organizational Roles | `(objectClass=organizationalRole)` |
| All Sudo Roles | `(objectClass=sudoRole)` |
| All Netgroups | `(objectClass=nisNetgroup)` |
| All Objects | `(objectClass=*)` |

#### Users

| Name | Filter |
|---|---|
| Users With Email | `(&(mail=*)(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=person)))` |
| Users With Phone Number | `(&(telephoneNumber=*)(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=person)))` |
| Users With Home Directory | `(&(homeDirectory=*)(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=person)))` |
| Users With UID | `(&(uid=*)(|(objectClass=inetOrgPerson)(objectClass=posixAccount)(objectClass=person)))` |
| Users With Password | `(userPassword=*)` |
| Users With SSH Keys | `(sshPublicKey=*)` |

#### Groups

| Name | Filter |
|---|---|
| Groups With Members (groupOfNames) | `(&(objectClass=groupOfNames)(member=*))` |
| Groups With Members (posixGroup) | `(&(objectClass=posixGroup)(memberUid=*))` |
| Groups With Members (groupOfUniqueNames) | `(&(objectClass=groupOfUniqueNames)(uniqueMember=*))` |

---

## Attrs Panel

Shows all attributes of the currently selected node in the Search Results tree. Columns: attribute name, attribute value.

Multi-value attributes may show a `[N entries hidden]` row; pressing `Enter` on that row expands it.

---

## History Panel

Shows past searches in reverse chronological order. Columns: `StartTime | Duration | Results | Query | BaseDN | Scope`.

Scope values are displayed as: `WholeSubtree`, `SingleLevel`, or `BaseObject`.

Pressing `Enter` on a history row copies its filter into the Search Filter field and focuses the filter input.

---

## Search Settings

Press **Ctrl+B** to open the Search Settings form. Fields:

| Field | Description |
|---|---|
| Base DN | The base of the search tree. Defaults to the directory root. |
| Scope | Dropdown: `WholeSubtree` / `SingleLevel` / `BaseObject` |
| Attributes | Comma-separated list of attributes to fetch; leave empty to fetch all. |

Buttons: **Go Back** (discard), **Set** (apply and re-run the search). If a required attribute is omitted from a non-empty list, a warning is shown before applying.

---

## Cache Finder Overlay

Press **Ctrl+F** to open the Cache Finder, a full-screen overlay titled **"Cache Finder (Object Search)"**.

### Layout

- Top row: a regexp input field, a count of cached objects, and a count of current matches.
- Main area: results table with columns `Match | Object | AttrName | AttrValue | ValIdx`.
- Bottom: **Go Back** button.

### Behavior

- As the user types a regexp, results update live.
- The type of match (`ObjectDN`, `AttrName`, or `AttrVal`) is color-coded (blue, violet, and purple respectively).
- The matched substring within the field is highlighted green.
- Press `Escape` or click **Go Back** to return to the Search page.

---

## Keybindings

### Page-level

| Key | Action |
|---|---|
| `Tab` | Cycle focus: Search Results tree → Search Filter → Side panel → (repeat) |
| `Shift+Tab` | Cycle focus in reverse |
| `Ctrl+F` | Open Cache Finder overlay |
| `Ctrl+B` | Open Search Settings form |

### Search Filter

| Key | Action |
|---|---|
| `Enter` | Execute the search |

### Search Results Tree

| Key | Action |
|---|---|
| `Right Arrow` | Expand the selected node |
| `Left Arrow` | Collapse the selected node; if already collapsed, collapse its parent and navigate to it |
| `r` / `R` | Reload the selected node's attributes from the server |
| `Delete` | Open a confirmation form to delete the selected object |
| `Ctrl+S` | Export all nodes in the selected subtree to a JSON file |
| `Ctrl+P` | Open a form to change the password of the selected user or computer |
| `Ctrl+L` | Open a form to move the selected object |
| `Ctrl+A` | Open a form to edit userAccountControl (UAC) flags |
| `Ctrl+N` | Open a form to create a new object under the selected node |
| `Ctrl+G` | Open a form to add a member to the selected group, or to add the selected object to a group |
| `Ctrl+D` | Navigate to the DACLs page and load the DACL for the selected object |

### Attrs Panel

| Key | Action |
|---|---|
| `r` / `R` | Reload attributes for the selected entry |
| `Ctrl+E` | Open the attribute editor for the selected row |
| `Ctrl+N` | Open a form to add a new attribute |
| `Delete` | Delete the selected attribute or attribute value |
| `Down Arrow` | Move to the next attribute (skips value-expansion rows) |
| `Up Arrow` | Move to the previous attribute |
| `Left Arrow` | Jump focus to the attribute name column |
| `Enter` | Expand hidden attribute values |

### History Panel

| Key | Action |
|---|---|
| `Enter` | Copy the selected entry's filter into the Search Filter and focus it |

### Global keybindings (apply on all pages, including Search)

| Key | Action |
|---|---|
| `Ctrl+J` | Advance to the next page |
| `f` / `F` | Toggle attribute value formatting |
| `c` / `C` | Toggle colors |
| `a` / `A` | Toggle attribute expansion |
| `s` / `S` | Toggle attribute sorting |
| `e` / `E` | Toggle emojis on tree node icons |
| `d` / `D` | Toggle inclusion of deleted/tombstoned objects (MicrosoftAD only) |
| `h` / `H` | Show/hide the header panel |
| `l` / `L` | Open the connection configuration form |
| `Ctrl+U` | Upgrade the connection with StartTLS |
| `Ctrl+R` | Reconnect |

---

## Navigation Into/Out of the Search Page

- The Search page is activated by selecting the **Search** tab in the global nav bar, or by pressing `Ctrl+J` to cycle through pages.
- Pressing `Ctrl+D` on a selected object navigates directly to the **DACLs** page and loads that object's DACL.
