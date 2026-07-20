//! Object naming, emoji prefix assignment, and deleted-object display.

use std::collections::HashMap;

/// Derive the display name for an LDAP entry from its attributes.
///
/// Priority: cn → ou → dc → name → uid → `<NoName:first_RDN_value>`.
pub fn entry_display_name(dn: &str, attrs: &HashMap<String, Vec<String>>) -> String {
    for attr in &["cn", "ou", "dc", "name", "uid"] {
        if let Some(vals) = attrs.get(*attr) {
            if let Some(v) = vals.first() {
                if !v.is_empty() {
                    // For all-DC DNs show dotted domain form
                    if *attr == "dc" && is_all_dc(dn) {
                        return dn_to_domain(dn);
                    }
                    return v.clone();
                }
            }
        }
    }
    first_rdn_value(dn)
        .map(|v| format!("<NoName:{v}>"))
        .unwrap_or_else(|| "<NoName>".to_owned())
}

/// Return the emoji prefix for an entry based on its `objectClass` values.
pub fn emoji_for_entry(object_classes: &[String]) -> &'static str {
    for class in object_classes {
        let emoji = match class.to_lowercase().as_str() {
            "user" => "👤",
            "computer" => "💻",
            "group" => "👥",
            "organizationalunit" => "📂",
            "container" => "📁",
            "domain" => "🌐",
            "grouppolicycontainer" => "⚙️",
            "person" => "👤",
            "organizationalperson" => "👤",
            "inettorgperson" => "👤",
            "posixaccount" => "👤",
            "posixgroup" => "👥",
            "groupofnames" => "👥",
            "groupofuniquenames" => "👥",
            "dnsdomain" => "🌐",
            "dnszone" => "🌐",
            "dnsnode" => "📃",
            "crossref" => "🔗",
            "trustedomain" => "🤝",
            "subnet" => "🕸️",
            "site" => "🏢",
            "configuration" => "⚙️",
            "schema" => "📋",
            "foreignsecurityprincipal" => "🔒",
            "msds-managedserviceaccount" => "🔑",
            _ => continue,
        };
        return emoji;
    }
    // Fallback by DN prefix
    "📁"
}

/// Strip the `DEL:<GUID>` suffix from a deleted-object name.
pub fn strip_deleted_suffix(name: &str) -> &str {
    name.find("\nDEL:")
        .or_else(|| name.find("\\0ADEL:"))
        .map(|pos| &name[..pos])
        .unwrap_or(name)
}

fn is_all_dc(dn: &str) -> bool {
    dn.split(',')
        .all(|part| part.trim().to_uppercase().starts_with("DC="))
}

fn dn_to_domain(dn: &str) -> String {
    dn.split(',')
        .filter_map(|part| {
            let part = part.trim();
            if part.to_uppercase().starts_with("DC=") {
                Some(&part[3..])
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn first_rdn_value(dn: &str) -> Option<&str> {
    let rdn = dn.split(',').next()?;
    let eq = rdn.find('=')?;
    Some(rdn[eq + 1..].trim())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn attrs(pairs: &[(&str, &str)]) -> HashMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), vec![v.to_string()]))
            .collect()
    }

    // entry_display_name — priority order

    #[test]
    fn display_name_prefers_cn() {
        let a = attrs(&[("cn", "Alice"), ("ou", "Users"), ("name", "Alice-name")]);
        assert_eq!(
            entry_display_name("cn=Alice,dc=example,dc=com", &a),
            "Alice"
        );
    }

    #[test]
    fn display_name_falls_back_to_ou() {
        let a = attrs(&[("ou", "Finance"), ("name", "Finance-name")]);
        assert_eq!(
            entry_display_name("ou=Finance,dc=example,dc=com", &a),
            "Finance"
        );
    }

    #[test]
    fn display_name_dc_only_returns_domain() {
        let dn = "dc=sub,dc=example,dc=com";
        let a = attrs(&[("dc", "sub")]);
        assert_eq!(entry_display_name(dn, &a), "sub.example.com");
    }

    #[test]
    fn display_name_uid_fallback() {
        let a = attrs(&[("uid", "jsmith")]);
        assert_eq!(
            entry_display_name("uid=jsmith,dc=example,dc=com", &a),
            "jsmith"
        );
    }

    #[test]
    fn display_name_no_known_attr() {
        let a = HashMap::new();
        let result = entry_display_name("cn=Alice,dc=example,dc=com", &a);
        assert!(result.starts_with("<NoName:") || result == "<NoName>");
    }

    // emoji_for_entry — known classes and fallback

    #[test]
    fn emoji_user() {
        let classes = vec!["top".to_string(), "user".to_string()];
        assert_eq!(emoji_for_entry(&classes), "👤");
    }

    #[test]
    fn emoji_group() {
        let classes = vec!["group".to_string()];
        assert_eq!(emoji_for_entry(&classes), "👥");
    }

    #[test]
    fn emoji_computer() {
        let classes = vec!["computer".to_string()];
        assert_eq!(emoji_for_entry(&classes), "💻");
    }

    #[test]
    fn emoji_ou() {
        let classes = vec!["organizationalUnit".to_string()];
        assert_eq!(emoji_for_entry(&classes), "📂");
    }

    #[test]
    fn emoji_fallback_unknown_class() {
        let classes = vec!["unknownObjectClass".to_string()];
        assert_eq!(emoji_for_entry(&classes), "📁");
    }

    #[test]
    fn emoji_empty_classes() {
        assert_eq!(emoji_for_entry(&[]), "📁");
    }
}
