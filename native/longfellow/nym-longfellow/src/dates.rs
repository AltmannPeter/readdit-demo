//! Full-dates (RFC 3339 `full-date`), the 20-character date-times the mdoc profile and the circuit
//! use, and the clock. The same rules as `native/vega` (nym-vega `dates`), with this crate's own
//! types.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// A calendar date.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Date {
  pub year: u32,
  pub month: u32,
  pub day: u32,
}

impl Date {
  /// YYYYMMDD as a number: dates compare as their digits.
  pub fn digits(&self) -> u32 {
    self.year * 10_000 + self.month * 100 + self.day
  }

  /// `YYYY-MM-DD`.
  pub fn text(&self) -> String {
    format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
  }
}

/// A UTC time to the second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Time {
  pub date: Date,
  pub hour: u32,
  pub minute: u32,
  pub second: u32,
}

impl Time {
  /// `YYYY-MM-DDThh:mm:ssZ`, 20 characters: T as the circuit reads it (SPEC.md §3).
  pub fn text(&self) -> String {
    format!("{}T{:02}:{:02}:{:02}Z", self.date.text(), self.hour, self.minute, self.second)
  }
}

fn days_in_month(year: u32, month: u32) -> u32 {
  match month {
    1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
    4 | 6 | 9 | 11 => 30,
    2 if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) => 29,
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

/// A date-time written `YYYY-MM-DDThh:mm:ssZ`, 20 characters.
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

/// days_from_civil (Howard Hinnant): days since 1970-01-01.
fn days(d: &Date) -> i64 {
  let year = i64::from(d.year) - i64::from(d.month <= 2);
  let era = year.div_euclid(400);
  let yoe = year - era * 400;
  let doy = (153 * i64::from((d.month + 9) % 12) + 2) / 5 + i64::from(d.day) - 1;
  let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  era * 146_097 + doe - 719_468
}

/// Days between two dates, `b − a`.
pub fn days_between(a: &Date, b: &Date) -> i64 {
  days(b) - days(a)
}

/// Seconds since 1970 of a time.
pub fn unix(t: &Time) -> i64 {
  days(&t.date) * 86_400 + i64::from(t.hour) * 3600 + i64::from(t.minute) * 60 + i64::from(t.second)
}

/// The UTC time of `unix` seconds since 1970 (civil_from_days, Howard Hinnant).
pub fn from_unix(unix_s: i64) -> Result<Time, String> {
  let z = unix_s.div_euclid(86_400) + 719_468;
  let era = z.div_euclid(146_097);
  let doe = z - era * 146_097;
  let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
  let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  let mp = (5 * doy + 2) / 153;
  let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).map_err(|e| e.to_string())?;
  let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).map_err(|e| e.to_string())?;
  let year = u32::try_from(yoe + era * 400 + i64::from(month <= 2)).map_err(|e| e.to_string())?;
  let r = unix_s.rem_euclid(86_400);
  let time = Time {
    date: Date { year, month, day },
    hour: u32::try_from(r / 3600).map_err(|e| e.to_string())?,
    minute: u32::try_from(r % 3600 / 60).map_err(|e| e.to_string())?,
    second: u32::try_from(r % 60).map_err(|e| e.to_string())?,
  };
  if year > 9999 || unix(&time) != unix_s {
    return Err(format!("time {unix_s} out of range"));
  }
  Ok(time)
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

  #[test]
  fn parse_and_round_trip() {
    assert!(date("2011-03-14").is_ok());
    assert!(date("2011-02-29").is_err());
    assert!(date("2012-02-29").is_ok());
    assert!(date_time("2026-10-13T25:00:00Z").is_err());
    let t = date_time("2026-10-13T12:34:56Z").expect("valid");
    assert_eq!(from_unix(unix(&t)).expect("in range"), t);
    assert_eq!(rfc3339("2026-10-13T12:34:56.789Z"), Ok(unix(&t)));
    assert_eq!(t.text(), "2026-10-13T12:34:56Z");
    assert_eq!(unix(&date_time("1970-01-01T00:00:00Z").expect("epoch")), 0);
  }
}

/// An age range in whole years (rulebook v0.5, `age_check.range`): "A-B", "A+" or "B-".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgeRange {
  pub min: Option<u32>,
  pub max: Option<u32>,
}

impl AgeRange {
  pub fn parse(s: &str) -> Result<AgeRange, String> {
    let bad = || format!("range {s} is not A-B, A+ or B-");
    let n = |t: &str| digits(t).ok_or_else(bad);
    if let Some(a) = s.strip_suffix('+') {
      return Ok(AgeRange { min: Some(n(a)?), max: None });
    }
    if let Some(b) = s.strip_suffix('-').filter(|b| !b.contains('-')) {
      return Ok(AgeRange { min: None, max: Some(n(b)?) });
    }
    let (a, b) = s.split_once('-').ok_or_else(bad)?;
    let (a, b) = (n(a)?, n(b)?);
    if a > b {
      return Err(format!("range {s}: A is greater than B"));
    }
    Ok(AgeRange { min: Some(a), max: Some(b) })
  }
}

/// E (born on or after) and C (born on or before) of an age range on D (rulebook v0.5): C is the
/// latest calendar date on or before D minus A years, E the earliest calendar date after D minus
/// (B + 1) years; D minus N years keeps D's month and day, and 29 February in another year is no
/// date (C: 28 February; E: 1 March). `A+` has no E, `B-` no C; a year below 1 gives no E.
pub fn range_bounds(r: &AgeRange, d: &Date) -> (Option<Date>, Option<Date>) {
  let born_by = r.min.map(|a| {
    let year = d.year.saturating_sub(a);
    Date { year, month: d.month, day: d.day.min(days_in_month(year, d.month)) }
  });
  let born_from = r.max.and_then(|b| {
    let year = d.year.checked_sub(b + 1).filter(|y| *y >= 1)?;
    let last = days_in_month(year, d.month);
    Some(if d.day > last {
      Date { year, month: d.month + 1, day: 1 }
    } else if d.day < last {
      Date { year, month: d.month, day: d.day + 1 }
    } else if d.month < 12 {
      Date { year, month: d.month + 1, day: 1 }
    } else {
      Date { year: year + 1, month: 1, day: 1 }
    })
  });
  (born_from, born_by)
}

#[cfg(test)]
mod range_tests {
  use super::*;

  fn b(r: &str, d: &str) -> (Option<String>, Option<String>) {
    let (e, c) = range_bounds(&AgeRange::parse(r).unwrap(), &date(d).unwrap());
    (e.map(|x| x.text()), c.map(|x| x.text()))
  }

  #[test]
  fn rulebook_v05_bounds() {
    // "With proof_time on 2026-10-20, the range 13-17 gives E = 2008-10-21 and C = 2013-10-20."
    assert_eq!(b("13-17", "2026-10-20"), (Some("2008-10-21".into()), Some("2013-10-20".into())));
    assert_eq!(b("18+", "2028-02-29"), (None, Some("2010-02-28".into())));
    assert_eq!(b("17-", "2028-02-29"), (Some("2010-03-01".into()), None));
    assert_eq!(b("0-0", "2026-12-31"), (Some("2026-01-01".into()), Some("2026-12-31".into())));
    assert!(AgeRange::parse("17-13").is_err());
    assert!(AgeRange::parse("13--17").is_err());
  }
}
