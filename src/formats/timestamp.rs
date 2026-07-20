//! Timestamp formatting for Windows FILETIME, Generalized Time, and MS Duration.

use chrono::{DateTime, Duration, NaiveDateTime, TimeZone, Utc};

use crate::config::TimeFmt;

/// Convert a Windows FILETIME (100ns intervals since 1601-01-01) to a formatted string.
pub fn format_filetime(filetime: i64, fmt: &TimeFmt, offset_hours: i32) -> String {
    todo!(
        "convert filetime to DateTime<Utc> by subtracting the Windows epoch offset \
         (11644473600 seconds), apply offset_hours, then format per fmt"
    )
}

/// Parse and format a Generalized Time string (`YYYYMMDDHHmmss.0Z`).
pub fn format_generalized_time(value: &str, fmt: &TimeFmt, offset_hours: i32) -> String {
    todo!("parse YYYYMMDDHHmmss.0Z using chrono, apply offset, format per fmt")
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
        // -1 day in 100ns intervals
        let one_day = -(86400i64 * 10_000_000);
        assert_eq!(format_ms_duration(one_day), "1d 0h 0m 0s");
    }
}
