//! Full-dates (RFC 3339 `full-date`), the 20-character date-times the mdoc profile and the circuit
//! use, and the clock.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use vega_age::presentation::{Date, Time};

fn days_in_month(year: u32, month: u32) -> u32 {
  match month {
    1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
    4 | 6 | 9 | 11 => 30,
    2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
    2 => 28,
    _ => 0,
  }
}

fn digits(s: &str) -> Option<u32> {
  (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok()).flatten()
}

/// A calendar date written `YYYY-MM-DD`.
pub fn date(s: &str) -> Result<Date, String> {
  let b = s.as_bytes();
  let ok_form = b.len() == 10 && b[4] == b'-' && b[7] == b'-';
  let parts = (digits(s.get(0..4).unwrap_or("")), digits(s.get(5..7).unwrap_or("")), digits(s.get(8..10).unwrap_or("")));
  match (ok_form, parts) {
    (true, (Some(year), Some(month), Some(day)))
      if (1..=12).contains(&month) && (1..=days_in_month(year, month)).contains(&day) =>
    {
      Ok(Date { year, month, day })
    }
    _ => Err(format!("not a calendar date YYYY-MM-DD: {s:?}")),
  }
}

/// A date-time written `YYYY-MM-DDThh:mm:ssZ`, 20 characters (the mdoc profile's tdate and the
/// circuit's time T).
pub fn date_time(s: &str) -> Result<Time, String> {
  let b = s.as_bytes();
  let ok_form = b.len() == 20 && b[10] == b'T' && b[13] == b':' && b[16] == b':' && b[19] == b'Z';
  if !ok_form {
    return Err(format!("not a date-time YYYY-MM-DDThh:mm:ssZ: {s:?}"));
  }
  let date = date(&s[..10])?;
  match (digits(&s[11..13]), digits(&s[14..16]), digits(&s[17..19])) {
    (Some(hour), Some(minute), Some(second)) if hour < 24 && minute < 60 && second < 60 => {
      Ok(Time { date, hour, minute, second })
    }
    _ => Err(format!("not a date-time YYYY-MM-DDThh:mm:ssZ: {s:?}")),
  }
}

/// Days between two dates, `b − a`.
pub fn days_between(a: &Date, b: &Date) -> i64 {
  fn days(d: &Date) -> i64 {
    // days_from_civil, Howard Hinnant.
    let year = i64::from(d.year) - i64::from(d.month <= 2);
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let doy = (153 * i64::from((d.month + 9) % 12) + 2) / 5 + i64::from(d.day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
  }
  days(b) - days(a)
}

/// The UTC time of `unix` seconds since 1970 (civil_from_days, Howard Hinnant).
pub fn from_unix(unix: i64) -> Result<Time, String> {
  let z = unix.div_euclid(86_400) + 719_468;
  let era = z.div_euclid(146_097);
  let doe = z - era * 146_097;
  let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
  let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  let mp = (5 * doy + 2) / 153;
  let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).map_err(|e| e.to_string())?;
  let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).map_err(|e| e.to_string())?;
  let year = u32::try_from(yoe + era * 400 + i64::from(month <= 2)).map_err(|e| e.to_string())?;
  let r = unix.rem_euclid(86_400);
  let time = Time {
    date: Date { year, month, day },
    hour: u32::try_from(r / 3600).map_err(|e| e.to_string())?,
    minute: u32::try_from(r % 3600 / 60).map_err(|e| e.to_string())?,
    second: u32::try_from(r % 60).map_err(|e| e.to_string())?,
  };
  if i64::try_from(time.seconds_since_1970()).ok() != Some(unix) {
    return Err(format!("time {unix} out of range"));
  }
  Ok(time)
}

/// Seconds since 1970 of a time.
pub fn unix(t: &Time) -> Result<i64, String> {
  i64::try_from(t.seconds_since_1970()).map_err(|e| e.to_string())
}

/// The clock, to the second.
pub fn now() -> Result<Time, String> {
  from_unix(OffsetDateTime::now_utc().unix_timestamp())
}

/// An RFC 3339 date-time with any offset and fraction (the site sends `Date.toISOString()`), to
/// the second.
pub fn rfc3339(s: &str) -> Result<i64, String> {
  OffsetDateTime::parse(s, &Rfc3339)
    .map(|t| t.unix_timestamp())
    .map_err(|e| format!("not an RFC 3339 date-time: {s:?} ({e})"))
}

#[cfg(test)]
mod tests {
  use super::*;

  /// The three forms the code must refuse, and the round trip of the clock's conversion.
  #[test]
  fn parse_and_round_trip() {
    assert!(date("2011-03-14").is_ok());
    assert!(date("2011-02-29").is_err());
    assert!(date("2012-02-29").is_ok());
    assert!(date_time("2026-10-13T25:00:00Z").is_err());
    let t = date_time("2026-10-13T12:34:56Z").expect("valid");
    assert_eq!(from_unix(unix(&t).expect("after 1970")).expect("in range"), t);
    assert_eq!(rfc3339("2026-10-13T12:34:56.789Z"), unix(&t));
  }
}
