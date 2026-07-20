//! Timestamp formatting for Windows FILETIME, Generalized Time, and MS Duration.

use chrono::{DateTime, Duration, NaiveDateTime, TimeZone, Utc};

use crate::config::TimeFmt;

// Seconds between Windows epoch (1601-01-01) and Unix epoch (1970-01-01).
const WINDOWS_EPOCH_OFFSET: i64 = 11_644_473_600;

/// Human-readable distance from now, e.g. "3 days ago" or "tomorrow".
fn time_distance(dt: DateTime<Utc>) -> String {
    let now = Utc::now();
    let delta = now.signed_duration_since(dt);
    let total_secs = delta.num_seconds().abs();
    let is_past = delta.num_seconds() >= 0;

    if total_secs < 60 {
        let n = total_secs;
        if is_past {
            format!("{n} seconds ago")
        } else {
            format!("{n} seconds from now")
        }
    } else if total_secs < 3600 {
        let n = total_secs / 60;
        if is_past {
            format!("{n} minutes ago")
        } else {
            format!("{n} minutes from now")
        }
    } else if total_secs < 86400 {
        let n = total_secs / 3600;
        if is_past {
            format!("{n} hours ago")
        } else {
            format!("{n} hours from now")
        }
    } else if total_secs < 2 * 86400 {
        if is_past {
            "yesterday".to_owned()
        } else {
            "tomorrow".to_owned()
        }
    } else {
        let n = total_secs / 86400;
        if is_past {
            format!("{n} days ago")
        } else {
            format!("{n} days from now")
        }
    }
}

/// Convert a Windows FILETIME (100ns intervals since 1601-01-01) to a formatted string.
///
/// Returns `(Never)` for the sentinel values 0 and `i64::MAX` (`accountExpires`).
/// For valid timestamps, appends a human-readable distance suffix.
pub fn format_filetime(filetime: i64, fmt: &TimeFmt, offset_hours: i32) -> String {
    if filetime == 0 || filetime == i64::MAX {
        return "(Never)".to_owned();
    }
    let secs = filetime / 10_000_000 - WINDOWS_EPOCH_OFFSET;
    let nanos = ((filetime % 10_000_000) * 100) as u32;
    let Some(dt_utc) = DateTime::from_timestamp(secs, nanos) else {
        return format!("<invalid filetime: {filetime}>");
    };
    let dt = dt_utc + Duration::hours(offset_hours as i64);
    format!("{} ({})", apply_format(dt, fmt), time_distance(dt_utc))
}

/// Parse and format a Generalized Time string (`YYYYMMDDHHmmss.0Z`).
///
/// Appends a human-readable distance suffix to the formatted date.
pub fn format_generalized_time(value: &str, fmt: &TimeFmt, offset_hours: i32) -> String {
    // Accept both "YYYYMMDDHHmmss.fZ" and "YYYYMMDDHHmmssZ"
    let trimmed = value.trim_end_matches('Z');
    let base = trimmed.split('.').next().unwrap_or(trimmed);
    let Ok(naive) = NaiveDateTime::parse_from_str(base, "%Y%m%d%H%M%S") else {
        return value.to_owned();
    };
    let dt_utc = Utc.from_utc_datetime(&naive);
    let dt = dt_utc + Duration::hours(offset_hours as i64);
    format!("{} ({})", apply_format(dt, fmt), time_distance(dt_utc))
}

/// Format a negative 100ns MS Duration interval (e.g. `maxPwdAge`) as a human-readable string.
///
/// - `0` → `(None)` (no minimum / no limit)
/// - `i64::MIN` → `(Never)`
/// - other → space-separated non-zero time parts
pub fn format_ms_duration(value: i64) -> String {
    if value == i64::MIN {
        return "(Never)".to_owned();
    }
    if value == 0 {
        return "(None)".to_owned();
    }
    format_duration_parts(value)
}

/// Like `format_ms_duration` but with `forceLogoff`-specific sentinels.
///
/// - `0` → `(Instantly)` (log off immediately)
/// - `i64::MIN` → `(Never)` (never force logoff)
/// - other → space-separated non-zero time parts
pub fn format_ms_duration_forcelogoff(value: i64) -> String {
    if value == i64::MIN {
        return "(Never)".to_owned();
    }
    if value == 0 {
        return "(Instantly)".to_owned();
    }
    format_duration_parts(value)
}

fn format_duration_parts(value: i64) -> String {
    let total_secs = value.unsigned_abs() / 10_000_000;
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;

    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days} days"));
    }
    if hours > 0 {
        parts.push(format!("{hours} hours"));
    }
    if mins > 0 {
        parts.push(format!("{mins} minutes"));
    }
    if secs > 0 {
        parts.push(format!("{secs} seconds"));
    }

    if parts.is_empty() {
        "(None)".to_owned()
    } else {
        parts.join(" ")
    }
}

fn apply_format(dt: DateTime<Utc>, fmt: &TimeFmt) -> String {
    match fmt {
        TimeFmt::Eu => dt.format("%d/%m/%Y %H:%M:%S").to_string(),
        TimeFmt::Us => dt.format("%m/%d/%Y %H:%M:%S").to_string(),
        TimeFmt::Iso8601 => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        TimeFmt::Custom(pattern) => dt.format(pattern).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ms_duration_none() {
        assert_eq!(format_ms_duration(0), "(None)");
    }

    #[test]
    fn ms_duration_never() {
        assert_eq!(format_ms_duration(i64::MIN), "(Never)");
    }

    #[test]
    fn ms_duration_one_day() {
        let one_day = -(86400i64 * 10_000_000);
        assert_eq!(format_ms_duration(one_day), "1 days");
    }

    #[test]
    fn ms_duration_90_days() {
        let ninety = -(90 * 86400i64 * 10_000_000);
        assert_eq!(format_ms_duration(ninety), "90 days");
    }

    #[test]
    fn ms_duration_mixed() {
        // 1 day 2 hours 3 minutes 4 seconds
        let v = -((86400 + 7200 + 180 + 4) * 10_000_000i64);
        assert_eq!(format_ms_duration(v), "1 days 2 hours 3 minutes 4 seconds");
    }

    #[test]
    fn ms_duration_forcelogoff_instantly() {
        assert_eq!(format_ms_duration_forcelogoff(0), "(Instantly)");
    }

    #[test]
    fn ms_duration_forcelogoff_never() {
        assert_eq!(format_ms_duration_forcelogoff(i64::MIN), "(Never)");
    }

    #[test]
    fn filetime_never() {
        assert_eq!(format_filetime(0, &TimeFmt::Iso8601, 0), "(Never)");
        assert_eq!(format_filetime(i64::MAX, &TimeFmt::Iso8601, 0), "(Never)");
    }

    #[test]
    fn filetime_known_date() {
        // 2024-01-15 12:00:00 UTC as FILETIME
        let ft = (1_705_320_000 + WINDOWS_EPOCH_OFFSET) * 10_000_000;
        let out = format_filetime(ft, &TimeFmt::Iso8601, 0);
        // The date portion is deterministic; distance suffix changes daily.
        assert!(
            out.starts_with("2024-01-15 12:00:00"),
            "unexpected output: {out}"
        );
    }

    #[test]
    fn generalized_time_parses() {
        let out = format_generalized_time("20240115120000.0Z", &TimeFmt::Iso8601, 0);
        assert!(
            out.starts_with("2024-01-15 12:00:00"),
            "unexpected output: {out}"
        );
    }

    #[test]
    fn generalized_time_no_fraction() {
        let out = format_generalized_time("20240115120000Z", &TimeFmt::Iso8601, 0);
        assert!(
            out.starts_with("2024-01-15 12:00:00"),
            "unexpected output: {out}"
        );
    }
}
