//! Timestamp formatting for Windows FILETIME, Generalized Time, and MS Duration.

use chrono::{DateTime, Duration, NaiveDateTime, TimeZone, Utc};

use crate::config::TimeFmt;

// Seconds between Windows epoch (1601-01-01) and Unix epoch (1970-01-01).
const WINDOWS_EPOCH_OFFSET: i64 = 11_644_473_600;

/// Convert a Windows FILETIME (100ns intervals since 1601-01-01) to a formatted string.
pub fn format_filetime(filetime: i64, fmt: &TimeFmt, offset_hours: i32) -> String {
    if filetime == 0 || filetime == i64::MAX {
        return "Never".to_owned();
    }
    let secs = filetime / 10_000_000 - WINDOWS_EPOCH_OFFSET;
    let nanos = ((filetime % 10_000_000) * 100) as u32;
    let Some(dt_utc) = DateTime::from_timestamp(secs, nanos) else {
        return format!("<invalid filetime: {filetime}>");
    };
    let dt = dt_utc + Duration::hours(offset_hours as i64);
    apply_format(dt, fmt)
}

/// Parse and format a Generalized Time string (`YYYYMMDDHHmmss.0Z`).
pub fn format_generalized_time(value: &str, fmt: &TimeFmt, offset_hours: i32) -> String {
    // Accept both "YYYYMMDDHHmmss.fZ" and "YYYYMMDDHHmmssZ"
    let trimmed = value.trim_end_matches('Z');
    let base = trimmed.split('.').next().unwrap_or(trimmed);
    let Ok(naive) = NaiveDateTime::parse_from_str(base, "%Y%m%d%H%M%S") else {
        return value.to_owned();
    };
    let dt = Utc.from_utc_datetime(&naive) + Duration::hours(offset_hours as i64);
    apply_format(dt, fmt)
}

/// Format a negative 100ns MS Duration interval (e.g. `maxPwdAge`) as a human-readable string.
pub fn format_ms_duration(value: i64) -> String {
    if value == 0 || value == i64::MIN {
        return "Never".to_owned();
    }
    let total_secs = value.unsigned_abs() / 10_000_000;
    let days = total_secs / 86400;
    let hours = (total_secs % 86400) / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    format!("{days}d {hours}h {mins}m {secs}s")
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
    fn ms_duration_never() {
        assert_eq!(format_ms_duration(0), "Never");
        assert_eq!(format_ms_duration(i64::MIN), "Never");
    }

    #[test]
    fn ms_duration_one_day() {
        let one_day = -(86400i64 * 10_000_000);
        assert_eq!(format_ms_duration(one_day), "1d 0h 0m 0s");
    }

    #[test]
    fn ms_duration_90_days() {
        let ninety = -(90 * 86400i64 * 10_000_000);
        assert_eq!(format_ms_duration(ninety), "90d 0h 0m 0s");
    }

    #[test]
    fn filetime_never() {
        assert_eq!(format_filetime(0, &TimeFmt::Iso8601, 0), "Never");
        assert_eq!(format_filetime(i64::MAX, &TimeFmt::Iso8601, 0), "Never");
    }

    #[test]
    fn filetime_known_date() {
        // 2024-01-15 12:00:00 UTC as FILETIME
        // Unix ts: 1705320000  -> filetime = (1705320000 + 11644473600) * 10_000_000
        let ft = (1_705_320_000 + WINDOWS_EPOCH_OFFSET) * 10_000_000;
        assert_eq!(
            format_filetime(ft, &TimeFmt::Iso8601, 0),
            "2024-01-15 12:00:00"
        );
    }

    #[test]
    fn generalized_time_parses() {
        assert_eq!(
            format_generalized_time("20240115120000.0Z", &TimeFmt::Iso8601, 0),
            "2024-01-15 12:00:00"
        );
    }

    #[test]
    fn generalized_time_no_fraction() {
        assert_eq!(
            format_generalized_time("20240115120000Z", &TimeFmt::Iso8601, 0),
            "2024-01-15 12:00:00"
        );
    }
}
