//! Attribute-value color rules for the Colors toggle.
//!
//! Each function returns a `ratatui::style::Color` to apply to the value cell.
//! All functions are called only when Colors is ON.

use ratatui::style::Color;

/// Determine the color for a text attribute value.
///
/// Returns `None` when no special coloring applies (caller uses default).
pub fn attr_value_color(attr_name: &str, raw_value: &str) -> Option<Color> {
    // Semantic value overrides take priority over attribute-name rules.
    if let Some(c) = semantic_color(raw_value) {
        return Some(c);
    }

    match attr_name.to_lowercase().as_str() {
        // Time-based: colored by age via distance_color_level from timestamp module.
        // The caller handles these with filetime_parts / generalized_time_parts; this
        // arm covers the fallback for sentinels like "(Never)".
        "lastlogontimestamp" | "accountexpires" | "badpasswordtime" | "lastlogoff"
        | "lastlogon" | "pwdlastset" | "creationtime" | "lockouttime" | "whencreated"
        | "whenchanged" => {
            // Sentinels that survived to formatted string — keep default.
            None
        }

        // Lockout duration: shorter is better (locks people out briefly)
        "lockoutduration"
        | "msds-lockoutduration"
        | "lockoutobservationwindow"
        | "lockoutobservationwindow2"
        | "msds-lockoutobservationwindow" => lockout_duration_color(raw_value),

        // Max password age: shorter forces more frequent changes (more secure)
        "maxpwdage" | "msds-maximumpasswordage" => max_pwd_age_color(raw_value),

        // Min password age
        "minpwdage" | "msds-minimumpasswordage" => min_pwd_age_color(raw_value),

        // Force logoff
        "forcelogoff" => force_logoff_color(raw_value),

        // Kerberos TGT lifetimes
        "msds-usertgtlifetime" | "msds-computertgtlifetime" | "msds-servicetgtlifetime" => {
            tgt_lifetime_color(raw_value)
        }

        // Lockout threshold: 0 = no lockout (green), low = risky (red), high = ok (yellow)
        "lockoutthreshold" | "msds-lockoutthreshold" => lockout_threshold_color(raw_value),

        // Minimum password length
        "minpwdlength" | "msds-minimumpasswordlength" => min_pwd_length_color(raw_value),

        // Bad password count
        "badpwdcount" => bad_pwd_count_color(raw_value),

        // Logon count
        "logoncount" => logon_count_color(raw_value),

        // GUID and SID: always gray
        "objectguid" | "objectsid" => Some(Color::DarkGray),

        _ => None,
    }
}

/// Color for binary attribute values (GUID/SID already handled in attr_value_color via name).
pub fn bin_attr_value_color(attr_name: &str) -> Option<Color> {
    match attr_name.to_lowercase().as_str() {
        "objectguid" | "objectsid" => Some(Color::DarkGray),
        _ => None,
    }
}

/// Semantic overrides: certain formatted strings get a fixed color regardless of attr name.
fn semantic_color(value: &str) -> Option<Color> {
    match value {
        "TRUE" | "Enabled" | "Normal" | "PwdNotExpired" => Some(Color::Green),
        "FALSE" | "NotNormal" | "PwdExpired" => Some(Color::Red),
        "Disabled" => Some(Color::Yellow),
        _ => None,
    }
}

// ── Duration helpers ────────────────────────────────────────────────────────
// All durations are stored as negative 100ns intervals; parse the raw integer.

fn parse_duration_secs(raw: &str) -> Option<u64> {
    raw.parse::<i64>()
        .ok()
        .map(|v| v.unsigned_abs() / 10_000_000)
}

fn lockout_duration_color(raw: &str) -> Option<Color> {
    let secs = parse_duration_secs(raw)?;
    let mins = secs / 60;
    Some(if mins <= 5 {
        Color::Green
    } else if mins <= 30 {
        Color::Yellow
    } else {
        Color::Red
    })
}

fn max_pwd_age_color(raw: &str) -> Option<Color> {
    let secs = parse_duration_secs(raw)?;
    let days = secs / 86400;
    Some(if days <= 30 {
        Color::Red
    } else if days <= 90 {
        Color::Yellow
    } else {
        Color::Green
    })
}

fn min_pwd_age_color(raw: &str) -> Option<Color> {
    let secs = parse_duration_secs(raw)?;
    let days = secs / 86400;
    Some(if days == 0 {
        Color::Green
    } else if days <= 1 {
        Color::Yellow
    } else {
        Color::Red
    })
}

fn force_logoff_color(raw: &str) -> Option<Color> {
    let v = raw.parse::<i64>().ok()?;
    if v == 0 {
        return Some(Color::Red);
    }
    let secs = v.unsigned_abs() / 10_000_000;
    let hours = secs / 3600;
    Some(if hours <= 2 {
        Color::Yellow
    } else {
        Color::Green
    })
}

fn tgt_lifetime_color(raw: &str) -> Option<Color> {
    // Stored as negative 100ns interval (same as durations).
    let secs = parse_duration_secs(raw)?;
    let hours = secs / 3600;
    Some(if hours >= 24 {
        Color::Green
    } else if hours >= 4 {
        Color::Yellow
    } else {
        Color::Red
    })
}

fn lockout_threshold_color(raw: &str) -> Option<Color> {
    let v = raw.parse::<i64>().ok()?;
    Some(if v == 0 {
        Color::Green
    } else if v < 5 {
        Color::Red
    } else {
        Color::Yellow
    })
}

fn min_pwd_length_color(raw: &str) -> Option<Color> {
    let v = raw.parse::<i64>().ok()?;
    Some(if v >= 12 {
        Color::Red
    } else if v >= 8 {
        Color::Yellow
    } else {
        Color::Green
    })
}

fn bad_pwd_count_color(raw: &str) -> Option<Color> {
    let v = raw.parse::<i64>().ok()?;
    Some(if v > 0 { Color::Yellow } else { Color::Green })
}

fn logon_count_color(raw: &str) -> Option<Color> {
    let v = raw.parse::<i64>().ok()?;
    Some(if v >= 10 {
        Color::Green
    } else if v > 0 {
        Color::Yellow
    } else {
        Color::Red
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_enabled_is_green() {
        assert_eq!(attr_value_color("someAttr", "Enabled"), Some(Color::Green));
    }

    #[test]
    fn semantic_disabled_is_yellow() {
        assert_eq!(
            attr_value_color("someAttr", "Disabled"),
            Some(Color::Yellow)
        );
    }

    #[test]
    fn semantic_false_is_red() {
        assert_eq!(attr_value_color("someAttr", "FALSE"), Some(Color::Red));
    }

    #[test]
    fn lockout_threshold_zero_green() {
        assert_eq!(
            attr_value_color("lockoutThreshold", "0"),
            Some(Color::Green)
        );
    }

    #[test]
    fn lockout_threshold_low_red() {
        assert_eq!(attr_value_color("lockoutThreshold", "3"), Some(Color::Red));
    }

    #[test]
    fn lockout_threshold_high_yellow() {
        assert_eq!(
            attr_value_color("lockoutThreshold", "10"),
            Some(Color::Yellow)
        );
    }

    #[test]
    fn bad_pwd_count_zero_green() {
        assert_eq!(attr_value_color("badPwdCount", "0"), Some(Color::Green));
    }

    #[test]
    fn bad_pwd_count_nonzero_yellow() {
        assert_eq!(attr_value_color("badPwdCount", "3"), Some(Color::Yellow));
    }

    #[test]
    fn logon_count_zero_red() {
        assert_eq!(attr_value_color("logonCount", "0"), Some(Color::Red));
    }

    #[test]
    fn logon_count_high_green() {
        assert_eq!(attr_value_color("logonCount", "50"), Some(Color::Green));
    }

    #[test]
    fn guid_is_gray() {
        assert_eq!(
            attr_value_color("objectGUID", "anything"),
            Some(Color::DarkGray)
        );
    }

    #[test]
    fn unknown_attr_no_color() {
        assert_eq!(attr_value_color("cn", "Alice"), None);
    }
}
