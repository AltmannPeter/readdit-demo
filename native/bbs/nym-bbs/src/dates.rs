//! Dates for rulebook v0.5's `age_check` and `proof_time` (`docs/nym_auth_rulebook-v0.5.md`,
//! "Date predicate function" and "Presentation encoding"): `proof_time` as
//! `YYYY-MM-DDThh:mm:ssZ` (UTC, to the second), and the birth-date bounds of an age range on D,
//! the UTC date of `proof_time`.
//!
//! * D minus N years keeps D's month and day and subtracts N from the year; the result may be no
//!   calendar date (29 February in another year).
//! * C, for "at least A years": the latest calendar date on or before D minus A years.
//! * E, for "at most B years": the earliest calendar date after D minus (B + 1) years.
//! * `A+` has no E, `B-` has no C; a bound before the date-range plugin's first year (1900) is no
//!   bound (the widest value).

use cd_date_range::Ymd;
use std::time::{SystemTime, UNIX_EPOCH};

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's days_from_civil).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
  let y = if m <= 2 { y - 1 } else { y };
  let era = if y >= 0 { y } else { y - 399 } / 400;
  let yoe = y - era * 400;
  let m = i64::from(m);
  let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
  let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  era * 146_097 + doe - 719_468
}

/// The date of a day number (civil_from_days).
pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
  let z = z + 719_468;
  let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
  let doe = z - era * 146_097;
  let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
  let y = yoe + era * 400;
  let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  let mp = (5 * doy + 2) / 153;
  let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
  let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
  (if m <= 2 { y + 1 } else { y }, m, d)
}

fn leap(y: i64) -> bool {
  (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> u32 {
  match m {
    2 if leap(y) => 29,
    2 => 28,
    4 | 6 | 9 | 11 => 30,
    _ => 31,
  }
}

/// A UTC time to the second.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Utc {
  pub year: i64,
  pub month: u32,
  pub day: u32,
  pub secs_of_day: u32,
}

impl Utc {
  pub fn now() -> Result<Utc, String> {
    let s = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();
    Ok(Utc::from_unix(i64::try_from(s).map_err(|e| e.to_string())?))
  }

  pub fn from_unix(t: i64) -> Utc {
    let (year, month, day) = civil_from_days(t.div_euclid(86_400));
    Utc { year, month, day, secs_of_day: t.rem_euclid(86_400) as u32 }
  }

  pub fn unix(&self) -> i64 {
    days_from_civil(self.year, self.month, self.day) * 86_400 + i64::from(self.secs_of_day)
  }

  /// `YYYY-MM-DDThh:mm:ssZ`.
  pub fn text(&self) -> String {
    let s = self.secs_of_day;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", self.year, self.month, self.day, s / 3600, s / 60 % 60, s % 60)
  }

  /// Reads `YYYY-MM-DDThh:mm:ssZ` exactly (the form `proof_time` takes).
  pub fn parse_proof_time(s: &str) -> Result<Utc, String> {
    let b = s.as_bytes();
    let form = b.len() == 20 && b[4] == b'-' && b[7] == b'-' && b[10] == b'T' && b[13] == b':' && b[16] == b':' && b[19] == b'Z';
    if !form {
      return Err(format!("not YYYY-MM-DDThh:mm:ssZ: {s:?}"));
    }
    Utc::parse_prefix(s)
  }

  /// Reads an RFC 3339 UTC date-time with an optional fraction (`Date.toISOString()`), to the second.
  pub fn parse_rfc3339(s: &str) -> Result<Utc, String> {
    let b = s.as_bytes();
    let tail_ok = b.len() >= 20 && b[b.len() - 1] == b'Z' && (b.len() == 20 || (b[19] == b'.' && b[20..b.len() - 1].iter().all(u8::is_ascii_digit)));
    if !tail_ok || b[10] != b'T' {
      return Err(format!("not an RFC 3339 UTC date-time: {s:?}"));
    }
    Utc::parse_prefix(s)
  }

  fn parse_prefix(s: &str) -> Result<Utc, String> {
    let n = |r: std::ops::Range<usize>| -> Result<u32, String> {
      let t = s.get(r).ok_or("short")?;
      if !t.bytes().all(|c| c.is_ascii_digit()) {
        return Err(format!("not a date-time: {s:?}"));
      }
      t.parse::<u32>().map_err(|e| e.to_string())
    };
    let (year, month, day, h, mi, se) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    let year = i64::from(year);
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) || h > 23 || mi > 59 || se > 59 {
      return Err(format!("not a calendar date-time: {s:?}"));
    }
    Ok(Utc { year, month, day, secs_of_day: h * 3600 + mi * 60 + se })
  }

  /// D: the UTC date.
  pub fn date(&self) -> (i64, u32, u32) {
    (self.year, self.month, self.day)
  }
}

/// An age range in whole years: "A-B", "A+" or "B-" (rulebook v0.5, ABNF in "Parameters").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgeRange {
  pub min: Option<u32>,
  pub max: Option<u32>,
}

impl AgeRange {
  pub fn parse(s: &str) -> Result<AgeRange, String> {
    let digits = |t: &str| -> Result<u32, String> {
      if t.is_empty() || !t.bytes().all(|c| c.is_ascii_digit()) {
        return Err(format!("range {s} is not A-B, A+ or B-"));
      }
      t.parse::<u32>().map_err(|_| format!("range {s}: an age is too large"))
    };
    if let Some(a) = s.strip_suffix('+') {
      return Ok(AgeRange { min: Some(digits(a)?), max: None });
    }
    if let Some(b) = s.strip_suffix('-') {
      if !b.contains('-') {
        return Ok(AgeRange { min: None, max: Some(digits(b)?) });
      }
    }
    let (a, b) = s.split_once('-').ok_or_else(|| format!("range {s} is not A-B, A+ or B-"))?;
    let (a, b) = (digits(a)?, digits(b)?);
    if a > b {
      return Err(format!("range {s}: A is greater than B"));
    }
    Ok(AgeRange { min: Some(a), max: Some(b) })
  }

  /// The bounds (E, C) on `d`; None: no bound on that side.
  pub fn bounds(&self, d: (i64, u32, u32)) -> Result<(Option<Ymd>, Option<Ymd>), String> {
    let (y, m, day) = d;
    // C: the latest calendar date on or before (y - A, m, day).
    let le = match self.min {
      None => None,
      Some(a) => {
        let cy = y - i64::from(a);
        let cd = day.min(days_in_month(cy, m));
        Some(ymd(cy, m, cd).ok_or_else(|| format!("the latest birth date for age {a} is before 1900"))?)
      }
    };
    // E: the earliest calendar date after (y - (B + 1), m, day).
    let ge = match self.max {
      None => None,
      Some(b) => {
        let ey = y - i64::from(b) - 1;
        let (ny, nm, nd) = if day > days_in_month(ey, m) {
          // No such date (29 February): the earliest date after it is 1 March.
          (ey, m + 1, 1)
        } else {
          civil_from_days(days_from_civil(ey, m, day) + 1)
        };
        // Before the plugin's first year: no lower bound (the widest value).
        if ny < 1900 { None } else { ymd(ny, nm, nd) }
      }
    };
    Ok((ge, le))
  }
}

fn ymd(y: i64, m: u32, d: u32) -> Option<Ymd> {
  Ymd::new(u16::try_from(y).ok()?, u8::try_from(m).ok()?, u8::try_from(d).ok()?)
}

/// `YYYY-MM-DD` of a bound.
pub fn iso(d: &Ymd) -> String {
  format!("{:04}-{:02}-{:02}", d.year, d.month, d.day)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn b(r: &str, d: (i64, u32, u32)) -> (Option<String>, Option<String>) {
    let (ge, le) = AgeRange::parse(r).unwrap().bounds(d).unwrap();
    (ge.as_ref().map(iso), le.as_ref().map(iso))
  }

  #[test]
  fn rulebook_example() {
    // "With proof_time on 2026-10-20, the range 13-17 gives E = 2008-10-21 and C = 2013-10-20."
    assert_eq!(b("13-17", (2026, 10, 20)), (Some("2008-10-21".into()), Some("2013-10-20".into())));
    assert_eq!(b("18+", (2026, 10, 20)), (None, Some("2008-10-20".into())));
    assert_eq!(b("17-", (2026, 10, 20)), (Some("2008-10-21".into()), None));
  }

  #[test]
  fn leap_days() {
    // D = 2028-02-29: D - 18 years = (2010, 2, 29), no date; C = 2010-02-28, E (B = 17) = 2010-03-01.
    assert_eq!(b("18+", (2028, 2, 29)), (None, Some("2010-02-28".into())));
    assert_eq!(b("17-", (2028, 2, 29)), (Some("2010-03-01".into()), None));
    // D - 4 years is a leap day: a calendar date.
    assert_eq!(b("4+", (2028, 2, 29)), (None, Some("2024-02-29".into())));
    assert_eq!(b("3-", (2028, 2, 29)), (Some("2024-03-01".into()), None));
    // Year end.
    assert_eq!(b("0-0", (2026, 12, 31)), (Some("2026-01-01".into()), Some("2026-12-31".into())));
  }

  #[test]
  fn ranges() {
    assert!(AgeRange::parse("17-13").is_err());
    assert!(AgeRange::parse("13").is_err());
    assert!(AgeRange::parse("-13").is_err());
    assert!(AgeRange::parse("a-b").is_err());
    assert!(AgeRange::parse("13--17").is_err());
    assert_eq!(AgeRange::parse("0-0").unwrap(), AgeRange { min: Some(0), max: Some(0) });
    // Lower bound before 1900: none.
    assert_eq!(b("200-", (2026, 10, 20)), (None, None));
  }

  #[test]
  fn times() {
    let t = Utc::parse_proof_time("2026-10-20T12:00:00Z").unwrap();
    assert_eq!(t.text(), "2026-10-20T12:00:00Z");
    assert_eq!(Utc::from_unix(t.unix()), t);
    assert_eq!(Utc::parse_rfc3339("2026-10-20T12:00:00.123Z").unwrap(), t);
    assert!(Utc::parse_proof_time("2026-10-20T12:00:00.1Z").is_err());
    assert!(Utc::parse_proof_time("2026-02-30T12:00:00Z").is_err());
    assert!(Utc::parse_proof_time("2026-10-20T12:00:00+01:00").is_err());
  }
}
