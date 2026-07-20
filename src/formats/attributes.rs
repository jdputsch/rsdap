//! AD-specific attribute value formatting: SID, GUID, UAC bitmasks, etc.

use crate::config::TimeFmt;
use crate::formats::timestamp;

/// Format a raw attribute value for display, auto-detecting the attribute type.
pub fn format_value(attr_name: &str, raw_value: &str, fmt: &TimeFmt, offset_hours: i32) -> String {
    todo!(
        "match attr_name (case-insensitive) to known formatters: \
         objectSid → sid_to_string, objectGUID → guid_to_string, \
         lastLogonTimestamp/pwdLastSet/etc → format_filetime, \
         whenCreated/whenChanged → format_generalized_time, \
         userAccountControl → uac_flags, maxPwdAge/minPwdAge → format_ms_duration"
    )
}

/// Convert a binary SID (base64 or hex) to its `S-1-5-...` string form.
pub fn sid_to_string(bytes: &[u8]) -> String {
    crate::security::Sid::parse(bytes)
        .map(|(sid, _)| sid.to_string())
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
