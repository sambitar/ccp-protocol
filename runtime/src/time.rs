//! RFC 3339 UTC timestamps with second precision.
//!
//! The protocol compares timestamps as strings, so every value this module
//! produces is normalized to `YYYY-MM-DDTHH:MM:SSZ`. The civil-date helpers
//! avoid a calendar dependency and follow Howard Hinnant's `days_from_civil`
//! algorithm.

use std::time::{SystemTime, UNIX_EPOCH};

/// The current UTC time as an RFC 3339 second-precision string.
pub fn utcnow() -> String {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    timestamp_from_unix(seconds)
}

/// True when `value` is a well-formed RFC 3339 UTC timestamp with seconds.
pub fn is_timestamp(value: &str) -> bool {
    timestamp_to_unix(value).is_some()
}

/// Parse a normalized timestamp into Unix seconds.
pub fn timestamp_to_unix(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() != 20 {
        return None;
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
    {
        return None;
    }
    let year: i64 = digits(&bytes[0..4])?;
    let month: u32 = digits(&bytes[5..7])? as u32;
    let day: u32 = digits(&bytes[8..10])? as u32;
    let hour: u32 = digits(&bytes[11..13])? as u32;
    let minute: u32 = digits(&bytes[14..16])? as u32;
    let second: u32 = digits(&bytes[17..19])? as u32;

    if !(1..=12).contains(&month) || day == 0 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    if day > days_in_month(year, month) {
        return None;
    }

    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour as i64 * 3_600 + minute as i64 * 60 + second as i64)
}

/// Format Unix seconds as a normalized timestamp.
pub fn timestamp_from_unix(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let within = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = within / 3_600;
    let minute = (within % 3_600) / 60;
    let second = within % 60;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, minute, second
    )
}

/// Shift a normalized timestamp by a number of seconds.
pub fn add_seconds(value: &str, seconds: i64) -> Option<String> {
    timestamp_to_unix(value).map(|base| timestamp_from_unix(base + seconds))
}

fn digits(bytes: &[u8]) -> Option<i64> {
    let mut value = 0i64;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value * 10 + (byte - b'0') as i64;
    }
    Some(value)
}

fn is_leap(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = month as i64;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_known_timestamps() {
        for value in [
            "1970-01-01T00:00:00Z",
            "2000-02-29T12:34:56Z",
            "2026-10-22T00:00:00Z",
            "9999-12-31T23:59:59Z",
        ] {
            let seconds = timestamp_to_unix(value).expect(value);
            assert_eq!(timestamp_from_unix(seconds), value);
        }
    }

    #[test]
    fn rejects_bad_timestamps() {
        for value in [
            "2026-10-22T00:00:00",
            "2026-13-01T00:00:00Z",
            "2026-02-30T00:00:00Z",
            "2026-10-22T24:00:00Z",
            "not-a-timestamp",
        ] {
            assert!(!is_timestamp(value), "{value}");
        }
    }

    #[test]
    fn adds_seconds_across_boundaries() {
        assert_eq!(
            add_seconds("2026-12-31T23:59:59Z", 1).unwrap(),
            "2027-01-01T00:00:00Z"
        );
        assert_eq!(
            add_seconds("2026-03-01T00:00:00Z", -1).unwrap(),
            "2026-02-28T23:59:59Z"
        );
    }
}
