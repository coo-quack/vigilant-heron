//! Calendar and time formatting for log lines, in UTC: the access-log time variables and the
//! syslog timestamp.

use std::time::{SystemTime, UNIX_EPOCH};

/// Narrows a calendar component to `u32`. Every component fits, so the fallback is never used.
fn component(value: i64) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Splits Unix seconds into (year, month, day, hour, minute, second), in UTC.
fn civil(seconds: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    // Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = component(doy - (153 * mp + 2) / 5 + 1);
    let month = component(if mp < 10 { mp + 3 } else { mp - 9 });
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        month,
        day,
        component(rest / 3600),
        component((rest % 3600) / 60),
        component(rest % 60),
    )
}

fn unix_parts(time: SystemTime) -> (i64, u32) {
    match time.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => (
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
            elapsed.subsec_millis(),
        ),
        Err(before) => {
            let back = i64::try_from(before.duration().as_secs()).unwrap_or(i64::MAX);
            (-back, 0)
        }
    }
}

/// `2026-10-25T08:00:00+00:00`, in UTC.
pub(crate) fn iso8601(time: SystemTime) -> String {
    let (y, mo, d, h, mi, s) = civil(unix_parts(time).0);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}+00:00")
}

/// `25/Oct/2026:08:00:00 +0000`, in UTC. There is no timezone database, so local time is UTC.
pub(crate) fn time_local(time: SystemTime) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (y, mo, d, h, mi, s) = civil(unix_parts(time).0);
    let name = MONTHS
        .get(mo.saturating_sub(1) as usize)
        .copied()
        .unwrap_or("Jan");
    format!("{d:02}/{name}/{y:04}:{h:02}:{mi:02}:{s:02} +0000")
}

/// Unix time with milliseconds, like nginx's `$msec`.
pub(crate) fn msec(time: SystemTime) -> String {
    let (seconds, millis) = unix_parts(time);
    format!("{seconds}.{millis:03}")
}

/// `Oct 25 08:00:00`, the RFC 3164 timestamp used for syslog, in UTC.
pub(crate) fn syslog_stamp(time: SystemTime) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (_, mo, d, h, mi, s) = civil(unix_parts(time).0);
    let name = MONTHS
        .get(mo.saturating_sub(1) as usize)
        .copied()
        .unwrap_or("Jan");
    format!("{name} {d:>2} {h:02}:{mi:02}:{s:02}")
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn leap_days_are_placed_correctly() {
        assert_eq!(civil(951_782_400), (2000, 2, 29, 0, 0, 0));
        assert_eq!(civil(0), (1970, 1, 1, 0, 0, 0));
    }

    fn days_in_month(year: i64, month: u32) -> u32 {
        match month {
            2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        }
    }

    #[test]
    fn civil_matches_the_gregorian_calendar_for_every_day_from_1600_to_2400() {
        // 1600-01-01T00:00:00Z, then every following day with a fixed time of day.
        let mut seconds: i64 = -11_676_096_000;
        let (mut year, mut month, mut day) = (1600_i64, 1_u32, 1_u32);
        while year <= 2400 {
            assert_eq!(
                civil(seconds + 13 * 3600 + 37 * 60 + 42),
                (year, month, day, 13, 37, 42),
                "unix seconds {seconds}"
            );
            seconds += 86_400;
            day += 1;
            if day > days_in_month(year, month) {
                day = 1;
                month += 1;
                if month > 12 {
                    month = 1;
                    year += 1;
                }
            }
        }
    }

    #[test]
    fn times_before_the_epoch_are_placed_before_it() {
        let before = UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(iso8601(before), "1969-12-31T23:59:59+00:00");
        assert_eq!(time_local(before), "31/Dec/1969:23:59:59 +0000");
    }
}
