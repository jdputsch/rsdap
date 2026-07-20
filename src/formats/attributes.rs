//! AD-specific attribute value formatting: SID, GUID, UAC bitmasks, etc.

use crate::config::TimeFmt;
use crate::formats::timestamp;

/// Format a raw string attribute value for display, auto-detecting the attribute type.
pub fn format_value(attr_name: &str, raw_value: &str, fmt: &TimeFmt, offset_hours: i32) -> String {
    match attr_name.to_lowercase().as_str() {
        // Windows FILETIME attributes (100ns since 1601)
        "lastlogon"
        | "lastlogontimestamp"
        | "lastlogoff"
        | "badpasswordtime"
        | "pwdlastset"
        | "accountexpires"
        | "lockouttime"
        | "msds-lastsuccessfulinteractivelogontime"
        | "msds-lastfailedinteractivelogontime" => raw_value
            .parse::<i64>()
            .map(|ft| timestamp::format_filetime(ft, fmt, offset_hours))
            .unwrap_or_else(|_| raw_value.to_owned()),

        // MS duration (negative 100ns interval)
        "maxpwdage" | "minpwdage" | "lockoutduration" | "lockoutobservationwindow" => raw_value
            .parse::<i64>()
            .map(timestamp::format_ms_duration)
            .unwrap_or_else(|_| raw_value.to_owned()),

        // Generalized Time (YYYYMMDDHHmmss.0Z)
        "whencreated" | "whenchanged" | "dscorepropagationdata" => {
            timestamp::format_generalized_time(raw_value, fmt, offset_hours)
        }

        // userAccountControl bitmask
        "useraccountcontrol" => raw_value
            .parse::<u32>()
            .map(|v| {
                let flags = uac_flags(v);
                if flags.is_empty() {
                    format!("{v} (no flags)")
                } else {
                    format!("{v} ({})", flags.join(", "))
                }
            })
            .unwrap_or_else(|_| raw_value.to_owned()),

        // groupType bitmask
        "grouptype" => raw_value
            .parse::<i32>()
            .map(group_type_string)
            .unwrap_or_else(|_| raw_value.to_owned()),

        // sAMAccountType
        "samaccounttype" => raw_value
            .parse::<u32>()
            .map(sam_account_type_string)
            .unwrap_or_else(|_| raw_value.to_owned()),

        // Pass everything else through unchanged (includes objectSid/objectGUID which
        // are binary and handled separately by format_bin_value).
        _ => raw_value.to_owned(),
    }
}

/// Format a binary attribute value (bytes delivered in ldap3's bin_attrs map).
pub fn format_bin_value(attr_name: &str, bytes: &[u8]) -> String {
    match attr_name.to_lowercase().as_str() {
        "objectsid" => sid_to_string(bytes),
        "objectguid" | "msds-generationid" => guid_to_string(bytes),
        _ => {
            // Fallback: hex dump
            bytes
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join(" ")
        }
    }
}

/// Convert a binary SID to its `S-1-5-...` string form.
pub fn sid_to_string(bytes: &[u8]) -> String {
    crate::security::Sid::parse(bytes)
        .map(|(sid, _)| {
            let s = sid.to_string();
            match sid.well_known_name() {
                Some(name) => format!("{s} ({name})"),
                None => s,
            }
        })
        .unwrap_or_else(|_| format!("<invalid SID: {} bytes>", bytes.len()))
}

/// Convert a binary GUID (16 bytes, little-endian mixed) to `{XXXXXXXX-XXXX-...}` form.
pub fn guid_to_string(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return format!("<invalid GUID: {} bytes>", bytes.len());
    }
    format!(
        "{{{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        bytes[3],
        bytes[2],
        bytes[1],
        bytes[0],
        bytes[5],
        bytes[4],
        bytes[7],
        bytes[6],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

/// Decode `userAccountControl` bitmask to a list of flag names.
pub fn uac_flags(value: u32) -> Vec<&'static str> {
    const FLAGS: &[(u32, &str)] = &[
        (0x0001, "SCRIPT"),
        (0x0002, "ACCOUNTDISABLE"),
        (0x0008, "HOMEDIR_REQUIRED"),
        (0x0010, "LOCKOUT"),
        (0x0020, "PASSWD_NOTREQD"),
        (0x0040, "PASSWD_CANT_CHANGE"),
        (0x0080, "ENCRYPTED_TEXT_PWD_ALLOWED"),
        (0x0100, "TEMP_DUPLICATE_ACCOUNT"),
        (0x0200, "NORMAL_ACCOUNT"),
        (0x0800, "INTERDOMAIN_TRUST_ACCOUNT"),
        (0x1000, "WORKSTATION_TRUST_ACCOUNT"),
        (0x2000, "SERVER_TRUST_ACCOUNT"),
        (0x10000, "DONT_EXPIRE_PASSWORD"),
        (0x20000, "MNS_LOGON_ACCOUNT"),
        (0x40000, "SMARTCARD_REQUIRED"),
        (0x80000, "TRUSTED_FOR_DELEGATION"),
        (0x100000, "NOT_DELEGATED"),
        (0x200000, "USE_DES_KEY_ONLY"),
        (0x400000, "DONT_REQ_PREAUTH"),
        (0x800000, "PASSWORD_EXPIRED"),
        (0x1000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
        (0x4000000, "PARTIAL_SECRETS_ACCOUNT"),
    ];
    FLAGS
        .iter()
        .filter(|(bit, _)| value & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

fn group_type_string(value: i32) -> String {
    let kind = match value & 0x0F {
        0x02 => "Global",
        0x04 => "Domain Local",
        0x08 => "Universal",
        _ => "Unknown",
    };
    let scope = if value < 0 {
        "Security"
    } else {
        "Distribution"
    };
    format!("{value} ({scope} {kind})")
}

fn sam_account_type_string(value: u32) -> String {
    let name = match value {
        0x00000000 => "Domain Object",
        0x10000000 => "Group Object",
        0x10000001 => "Non-Security Group Object",
        0x20000000 => "Alias Object",
        0x20000001 => "Non-Security Alias Object",
        0x30000000 => "User Object",
        0x30000001 => "Machine Account",
        0x30000002 => "Trust Account",
        0x40000000 => "App Basic Group",
        0x40000001 => "App Query Group",
        0x7FFFFFFF => "Account Type Max",
        _ => "Unknown",
    };
    format!("{value} ({name})")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TimeFmt;

    #[test]
    fn guid_known() {
        let bytes: &[u8] = &[
            0x6b, 0xa0, 0x7b, 0x96, 0x4b, 0x08, 0xd1, 0x11, 0xad, 0x9b, 0x00, 0xc0, 0x4f, 0xd8,
            0xd5, 0xcd,
        ];
        let s = guid_to_string(bytes);
        assert!(s.starts_with('{'));
        assert!(s.ends_with('}'));
        assert_eq!(s.len(), 38);
    }

    #[test]
    fn sid_system() {
        let bytes: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let s = sid_to_string(bytes);
        assert!(s.contains("S-1-5-18"));
        assert!(s.contains("SYSTEM"));
    }

    #[test]
    fn uac_normal_account() {
        let flags = uac_flags(0x0200);
        assert_eq!(flags, vec!["NORMAL_ACCOUNT"]);
    }

    #[test]
    fn uac_disabled_normal() {
        let flags = uac_flags(0x0202);
        assert!(flags.contains(&"ACCOUNTDISABLE"));
        assert!(flags.contains(&"NORMAL_ACCOUNT"));
    }

    #[test]
    fn format_uac_value() {
        let out = format_value("userAccountControl", "512", &TimeFmt::Iso8601, 0);
        assert!(out.contains("NORMAL_ACCOUNT"));
    }

    #[test]
    fn format_whencreated() {
        let out = format_value("whenCreated", "20240115120000.0Z", &TimeFmt::Iso8601, 0);
        assert_eq!(out, "2024-01-15 12:00:00");
    }
}
