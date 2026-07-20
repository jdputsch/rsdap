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
        | "creationtime"
        | "msds-lastsuccessfulinteractivelogontime"
        | "msds-lastfailedinteractivelogontime" => raw_value
            .parse::<i64>()
            .map(|ft| timestamp::format_filetime(ft, fmt, offset_hours))
            .unwrap_or_else(|_| raw_value.to_owned()),

        // forceLogoff has distinct sentinels: 0 = Instantly, MIN = Never
        "forcelogoff" => raw_value
            .parse::<i64>()
            .map(timestamp::format_ms_duration_forcelogoff)
            .unwrap_or_else(|_| raw_value.to_owned()),

        // MS duration (negative 100ns interval)
        "maxpwdage"
        | "minpwdage"
        | "lockoutduration"
        | "lockoutobservationwindow"
        | "lockoutobservationwindow2"
        | "msds-maximumpasswordage"
        | "msds-minimumpasswordage"
        | "msds-lockoutduration"
        | "msds-lockoutobservationwindow"
        | "msds-usertgtlifetime"
        | "msds-computertgtlifetime"
        | "msds-servicetgtlifetime" => raw_value
            .parse::<i64>()
            .map(timestamp::format_ms_duration)
            .unwrap_or_else(|_| raw_value.to_owned()),

        // Generalized Time (YYYYMMDDHHmmss.0Z)
        "whencreated" | "whenchanged" | "dscorepropagationdata" => {
            timestamp::format_generalized_time(raw_value, fmt, offset_hours)
        }

        // Threshold/length attrs: 0 → (None)
        "lockoutthreshold"
        | "msds-lockoutthreshold"
        | "minpwdlength"
        | "msds-minimumpasswordlength" => raw_value
            .parse::<i64>()
            .map(|n| {
                if n == 0 {
                    "(None)".to_owned()
                } else {
                    raw_value.to_owned()
                }
            })
            .unwrap_or_else(|_| raw_value.to_owned()),

        // primaryGroupID: RID → group name
        "primarygroupid" => raw_value
            .parse::<u32>()
            .map(|rid| primary_group_name(rid, raw_value))
            .unwrap_or_else(|_| raw_value.to_owned()),

        // sAMAccountType
        "samaccounttype" => raw_value
            .parse::<u32>()
            .map(|v| sam_account_type_string(v, raw_value))
            .unwrap_or_else(|_| raw_value.to_owned()),

        // groupType bitmask
        "grouptype" => raw_value
            .parse::<i32>()
            .map(|v| group_type_string(v, raw_value))
            .unwrap_or_else(|_| raw_value.to_owned()),

        // instanceType
        "instancetype" => raw_value
            .parse::<u32>()
            .map(|v| instance_type_string(v, raw_value))
            .unwrap_or_else(|_| raw_value.to_owned()),

        // Bitset attributes: single-value string (expansion is handled in display_rows via
        // format_bitset_rows which returns Vec<String> for these attrs).
        // Here we just return the raw value; the caller uses format_bitset_rows instead.
        _ => raw_value.to_owned(),
    }
}

/// Returns true if the attribute name is a bitset that should be expanded row-by-row.
pub fn is_bitset_attr(attr_name: &str) -> bool {
    matches!(
        attr_name.to_lowercase().as_str(),
        "useraccountcontrol" | "systemflags" | "trustattributes" | "pwdproperties" | "searchflags"
    )
}

/// Expand a bitset attribute into one label string per active bit.
///
/// Returns an empty vec if the value cannot be parsed.
pub fn format_bitset_rows(attr_name: &str, raw_value: &str) -> Vec<String> {
    let Ok(value) = raw_value.parse::<i64>() else {
        return vec![];
    };
    let flags: &[(i64, &str)] = match attr_name.to_lowercase().as_str() {
        "useraccountcontrol" => UAC_FLAGS,
        "systemflags" => SYSTEM_FLAGS,
        "trustattributes" => TRUST_ATTRIBUTES,
        "pwdproperties" => PWD_PROPERTIES,
        "searchflags" => SEARCH_FLAGS,
        _ => return vec![],
    };
    flags
        .iter()
        .filter(|(bit, _)| value & bit != 0)
        .map(|(_, name)| (*name).to_owned())
        .collect()
}

/// Format a binary attribute value (bytes delivered in ldap3's bin_attrs map).
pub fn format_bin_value(attr_name: &str, bytes: &[u8]) -> String {
    match attr_name.to_lowercase().as_str() {
        "objectsid" | "securityidentifier" => {
            format!("SID{{{}}}", sid_to_string_inner(bytes))
        }
        "objectguid" | "schemaidguid" | "attributesecurityguid" | "msds-generationid" => {
            format!("GUID{{{}}}", guid_to_string_inner(bytes))
        }
        "logonhours" | "dsasignature" | "omobjectclass" | "cacertificate" => {
            format!("HEX{{{}}}", bytes_to_hex_lower(bytes))
        }
        _ => {
            // Fallback: hex without prefix
            bytes_to_hex_lower(bytes)
        }
    }
}

fn bytes_to_hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Convert a binary SID to its `S-1-5-...` string form (without prefix).
pub fn sid_to_string(bytes: &[u8]) -> String {
    format!("SID{{{}}}", sid_to_string_inner(bytes))
}

fn sid_to_string_inner(bytes: &[u8]) -> String {
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

/// Convert a binary GUID (16 bytes, little-endian mixed) to UUID string form (without prefix).
pub fn guid_to_string(bytes: &[u8]) -> String {
    format!("GUID{{{}}}", guid_to_string_inner(bytes))
}

fn guid_to_string_inner(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return format!("<invalid GUID: {} bytes>", bytes.len());
    }
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
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
    UAC_FLAGS
        .iter()
        .filter(|(bit, _)| value as i64 & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

fn primary_group_name(rid: u32, raw: &str) -> String {
    let name = match rid {
        512 => "Domain Admins",
        513 => "Domain Users",
        514 => "Domain Guests",
        515 => "Domain Computers",
        516 => "Domain Controllers",
        517 => "Cert Publishers",
        518 => "Schema Admins",
        519 => "Enterprise Admins",
        520 => "Group Policy Creator Owners",
        _ => return raw.to_owned(),
    };
    name.to_owned()
}

fn group_type_string(value: i32, raw: &str) -> String {
    let kind = match value & 0x0F {
        0x02 => "Global",
        0x04 => "Domain Local",
        0x08 => "Universal",
        _ => return raw.to_owned(),
    };
    let scope = if value < 0 {
        "Security"
    } else {
        "Distribution"
    };
    format!("{scope} {kind} Group")
}

fn sam_account_type_string(value: u32, raw: &str) -> String {
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
        _ => return raw.to_owned(),
    };
    name.to_owned()
}

fn instance_type_string(value: u32, raw: &str) -> String {
    let name = match value {
        0 => "NotANamingContext",
        1 => "NamingContextHead",
        2 => "NotInstantiatedReplica",
        4 => "WritableObject",
        8 => "NamingContextAbove",
        16 => "NamingContextBeingConstructed",
        32 => "NamingContextBeingRemoved",
        _ => return raw.to_owned(),
    };
    name.to_owned()
}

const UAC_FLAGS: &[(i64, &str)] = &[
    (0x0001, "Script"),
    (0x0002, "Disabled"),
    (0x0008, "HomeDirRequired"),
    (0x0010, "LockedOut"),
    (0x0020, "PwdNotRequired"),
    (0x0040, "CannotChangePwd"),
    (0x0080, "EncryptedTextPwdAllowed"),
    (0x0100, "TmpDuplicateAccount"),
    (0x0200, "NormalAccount"),
    (0x0800, "InterdomainTrustAccount"),
    (0x1000, "WorkstationTrustAccount"),
    (0x2000, "ServerTrustAccount"),
    (0x10000, "DoNotExpirePwd"),
    (0x20000, "MNSLogonAccount"),
    (0x40000, "SmartcardRequired"),
    (0x80000, "TrustedForDelegation"),
    (0x100000, "NotDelegated"),
    (0x200000, "UseDESKeyOnly"),
    (0x400000, "DoNotRequirePreauth"),
    (0x800000, "PwdExpired"),
    (0x1000000, "TrustedToAuthForDelegation"),
    (0x4000000, "PartialSecretsAccount"),
];

const SYSTEM_FLAGS: &[(i64, &str)] = &[
    (0x00000001, "FLAG_ATTR_NOT_REPLICATED"),
    (0x00000002, "FLAG_ATTR_REQ_PARTIAL_SET_MEMBER"),
    (0x00000004, "FLAG_ATTR_IS_CONSTRUCTED"),
    (0x00000008, "FLAG_ATTR_IS_OPERATIONAL"),
    (0x00000010, "FLAG_SCHEMA_BASE_OBJECT"),
    (0x00000020, "FLAG_ATTR_IS_RDN"),
    (0x02000000, "FLAG_DISALLOW_MOVE_ON_DELETE"),
    (0x04000000, "FLAG_DOMAIN_DISALLOW_MOVE"),
    (0x08000000, "FLAG_DOMAIN_DISALLOW_RENAME"),
    (0x10000000, "FLAG_CONFIG_ALLOW_LIMITED_MOVE"),
    (0x20000000, "FLAG_CONFIG_ALLOW_MOVE"),
    (0x40000000, "FLAG_CONFIG_ALLOW_RENAME"),
    (-0x80000000i64, "FLAG_DISALLOW_DELETE"),
];

const TRUST_ATTRIBUTES: &[(i64, &str)] = &[
    (0x00000001, "NON_TRANSITIVE"),
    (0x00000002, "UPLEVEL_ONLY"),
    (0x00000004, "QUARANTINED_DOMAIN"),
    (0x00000008, "FOREST_TRANSITIVE"),
    (0x00000010, "CROSS_ORGANIZATION"),
    (0x00000020, "WITHIN_FOREST"),
    (0x00000040, "TREAT_AS_EXTERNAL"),
    (0x00000080, "USES_RC4_ENCRYPTION"),
    (0x00000200, "CROSS_ORGANIZATION_NO_TGT_DELEGATION"),
    (0x00000400, "PIM_TRUST"),
    (0x00000800, "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION"),
];

const PWD_PROPERTIES: &[(i64, &str)] = &[
    (0x00000001, "PASSWORD_COMPLEX"),
    (0x00000002, "PASSWORD_NO_ANON_CHANGE"),
    (0x00000004, "PASSWORD_NO_CLEAR_CHANGE"),
    (0x00000008, "LOCKOUT_ADMINS"),
    (0x00000010, "PASSWORD_STORE_CLEARTEXT"),
    (0x00000020, "REFUSE_PASSWORD_CHANGE"),
];

const SEARCH_FLAGS: &[(i64, &str)] = &[
    (0x00000001, "fATTINDEX"),
    (0x00000002, "fPDNTATTINDEX"),
    (0x00000004, "fANR"),
    (0x00000008, "fPRESERVEONDELETE"),
    (0x00000010, "fCOPY"),
    (0x00000020, "fTUPLEINDEX"),
    (0x00000040, "fSUBTREEATTINDEX"),
    (0x00000080, "fCONFIDENTIAL"),
    (0x00000100, "fNEVERVALUEAUDIT"),
    (0x00000200, "fRODCFilteredAttribute"),
    (0x00000400, "fEXTENDEDLINKTRACKING"),
    (0x00000800, "fBASEONLY"),
    (0x00001000, "fPARTITIONSECRET"),
];

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
        assert!(s.starts_with("GUID{"));
        assert!(s.ends_with('}'));
        // GUID{ + 36 chars + }
        assert_eq!(s.len(), 42);
    }

    #[test]
    fn sid_system() {
        let bytes: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let s = sid_to_string(bytes);
        assert!(s.starts_with("SID{"));
        assert!(s.contains("S-1-5-18"));
        assert!(s.contains("SYSTEM"));
    }

    #[test]
    fn uac_normal_account() {
        let flags = uac_flags(0x0200);
        assert_eq!(flags, vec!["NormalAccount"]);
    }

    #[test]
    fn uac_disabled_normal() {
        let flags = uac_flags(0x0202);
        assert!(flags.contains(&"Disabled"));
        assert!(flags.contains(&"NormalAccount"));
    }

    #[test]
    fn format_whencreated() {
        let out = format_value("whenCreated", "20240115120000.0Z", &TimeFmt::Iso8601, 0);
        // Has the date prefix and a distance suffix
        assert!(out.starts_with("2024-01-15 12:00:00"), "unexpected: {out}");
        assert!(out.contains('('), "missing distance suffix: {out}");
    }

    #[test]
    fn format_bin_value_sid_prefix() {
        let bytes: &[u8] = &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let s = format_bin_value("objectSid", bytes);
        assert!(s.starts_with("SID{"), "no SID prefix: {s}");
    }

    #[test]
    fn format_bin_value_guid_prefix() {
        let bytes: &[u8] = &[0u8; 16];
        let s = format_bin_value("objectGUID", bytes);
        assert!(s.starts_with("GUID{"), "no GUID prefix: {s}");
    }

    #[test]
    fn format_bin_value_hex_prefix() {
        let bytes: &[u8] = &[0xff, 0xff];
        let s = format_bin_value("logonHours", bytes);
        assert!(s.starts_with("HEX{"), "no HEX prefix: {s}");
        assert!(s.contains("ffff"), "wrong hex: {s}");
    }

    #[test]
    fn threshold_zero_is_none() {
        let out = format_value("lockoutThreshold", "0", &TimeFmt::Iso8601, 0);
        assert_eq!(out, "(None)");
    }

    #[test]
    fn threshold_nonzero_unchanged() {
        let out = format_value("lockoutThreshold", "5", &TimeFmt::Iso8601, 0);
        assert_eq!(out, "5");
    }

    #[test]
    fn primary_group_domain_users() {
        let out = format_value("primaryGroupID", "513", &TimeFmt::Iso8601, 0);
        assert_eq!(out, "Domain Users");
    }

    #[test]
    fn primary_group_unknown_rid() {
        let out = format_value("primaryGroupID", "999", &TimeFmt::Iso8601, 0);
        assert_eq!(out, "999");
    }

    #[test]
    fn sam_account_type_user() {
        let out = format_value("sAMAccountType", "805306368", &TimeFmt::Iso8601, 0);
        assert_eq!(out, "User Object");
    }

    #[test]
    fn group_type_global_security() {
        // -2147483646 = 0x80000002 as i32
        let out = format_value("groupType", "-2147483646", &TimeFmt::Iso8601, 0);
        assert_eq!(out, "Security Global Group");
    }

    #[test]
    fn instance_type_writable() {
        let out = format_value("instanceType", "4", &TimeFmt::Iso8601, 0);
        assert_eq!(out, "WritableObject");
    }

    #[test]
    fn instance_type_unknown() {
        let out = format_value("instanceType", "99", &TimeFmt::Iso8601, 0);
        assert_eq!(out, "99");
    }

    #[test]
    fn bitset_uac_normal_account() {
        let rows = format_bitset_rows("userAccountControl", "512");
        assert!(rows.contains(&"NormalAccount".to_owned()));
    }

    #[test]
    fn bitset_pwd_properties() {
        let rows = format_bitset_rows("pwdProperties", "1");
        assert_eq!(rows, vec!["PASSWORD_COMPLEX"]);
    }

    #[test]
    fn bitset_unknown_attr() {
        let rows = format_bitset_rows("someOtherAttr", "512");
        assert!(rows.is_empty());
    }

    #[test]
    fn is_bitset_known() {
        assert!(is_bitset_attr("userAccountControl"));
        assert!(is_bitset_attr("systemFlags"));
        assert!(!is_bitset_attr("cn"));
    }
}
