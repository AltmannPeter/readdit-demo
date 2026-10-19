//! The `date-packed` attribute type (docs/plugins/DATE-RANGE.md §1).
//!
//! A date (Y, M, D) is the integer (Y − 1900)·372 + (M − 1)·31 + (D − 1):
//! 31 slots per month and 372 per year, so packed values compare like dates
//! with no calendar arithmetic.  Days that don't exist are unused values.
use bbs_cd::types::ScalarInput;
use bbs_cd_plugin::error::{Error, Result};
use bbs_cd_plugin::issuer::{scalar_from_u128, AttrHandler};
use bbs_cd_plugin::schema::{AttributeSpec, ScalarsSpec};

/// Attribute type id.
pub const TYPE_DATE: &str = "date-packed";
/// Allowed attribute widths, in bits.
pub const MIN_BITS: u16 = 16;
pub const MAX_BITS: u16 = 32;
/// Recommended width: dates up to the year 2252.
pub const RECOMMENDED_BITS: u16 = 17;

/// First year that can be encoded.
pub const BASE_YEAR: u16 = 1900;
/// Last year a request may name.
pub const MAX_YEAR: u16 = 9999;

/// A date by its fields.  `Ymd::new` checks field ranges only (month 1–12,
/// day 1–31), not the calendar; `is_calendar_date` checks the calendar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ymd {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

impl Ymd {
    /// Fields in range: year in [1900, 9999], month in [1, 12], day in [1, 31].
    pub fn new(year: u16, month: u8, day: u8) -> Option<Ymd> {
        let ok = (BASE_YEAR..=MAX_YEAR).contains(&year) && (1..=12).contains(&month) && (1..=31).contains(&day);
        ok.then_some(Ymd { year, month, day })
    }

    /// From the decimal number YYYYMMDD (20081018 is 2008-10-18).
    pub fn from_yyyymmdd(n: u32) -> Option<Ymd> {
        if n > 99_991_231 {
            return None;
        }
        Ymd::new((n / 10_000) as u16, (n / 100 % 100) as u8, (n % 100) as u8)
    }

    pub fn to_yyyymmdd(&self) -> u32 {
        self.year as u32 * 10_000 + self.month as u32 * 100 + self.day as u32
    }

    /// Strict ASCII `YYYY-MM-DD` (fields in range; no calendar check).
    pub fn parse_iso(s: &[u8]) -> Option<Ymd> {
        if s.len() != 10 || s[4] != b'-' || s[7] != b'-' {
            return None;
        }
        let num = |r: std::ops::Range<usize>| -> Option<u32> {
            s[r].iter().try_fold(0u32, |a, &c| c.is_ascii_digit().then(|| a * 10 + (c - b'0') as u32))
        };
        Ymd::new(num(0..4)? as u16, num(5..7)? as u8, num(8..10)? as u8)
    }

    /// Whether the date exists in the (proleptic) Gregorian calendar.
    pub fn is_calendar_date(&self) -> bool {
        self.day <= days_in_month(self.year, self.month)
    }

    /// The packed value.
    pub fn pack(&self) -> u64 {
        (self.year - BASE_YEAR) as u64 * 372 + (self.month as u64 - 1) * 31 + (self.day as u64 - 1)
    }

    /// Inverse of `pack` for values of in-range fields.
    pub fn unpack(v: u64) -> Option<Ymd> {
        let year = BASE_YEAR as u64 + v / 372;
        if year > MAX_YEAR as u64 {
            return None;
        }
        Ymd::new(year as u16, (v % 372 / 31 + 1) as u8, (v % 31 + 1) as u8)
    }
}

impl std::fmt::Display for Ymd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.year, self.month, self.day)
    }
}

pub fn is_leap_year(y: u16) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

pub fn days_in_month(y: u16, m: u8) -> u8 {
    match m {
        2 if is_leap_year(y) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Bit width of a `date-packed` attribute, or an error for another type or
/// layout.
pub fn date_bits(attr: &AttributeSpec) -> Result<u16> {
    match attr.scalars_spec() {
        Some(s) if s.type_id == TYPE_DATE && s.count == 1 && (MIN_BITS..=MAX_BITS).contains(&s.bits) => Ok(s.bits),
        _ => Err(Error::Reject(format!("date-range: attribute {} is not a {TYPE_DATE} attribute", attr.name))),
    }
}

/// Issuance input for a date: ASCII `YYYY-MM-DD`.
pub fn date_input(iso: &str) -> Vec<u8> {
    iso.as_bytes().to_vec()
}

/// Issuance handler for `date-packed`: input is ASCII `YYYY-MM-DD`, a real
/// Gregorian date from 1900-01-01 on whose packed value fits the attribute.
pub struct DateHandler;

impl AttrHandler for DateHandler {
    fn type_id(&self) -> &str {
        TYPE_DATE
    }
    fn encode(&self, spec: &ScalarsSpec, input: &[u8]) -> Result<Vec<ScalarInput>> {
        if spec.count != 1 || !(MIN_BITS..=MAX_BITS).contains(&spec.bits) {
            return Err(Error::Prover(format!(
                "{TYPE_DATE}: layout must be one scalar of {MIN_BITS}..={MAX_BITS} bits"
            )));
        }
        let d = Ymd::parse_iso(input)
            .filter(Ymd::is_calendar_date)
            .ok_or_else(|| Error::Prover(format!("{TYPE_DATE}: not a valid YYYY-MM-DD date from 1900 on")))?;
        let v = d.pack();
        if (v >> spec.bits) != 0 {
            return Err(Error::Prover(format!("{TYPE_DATE}: {d} does not fit {} bits", spec.bits)));
        }
        Ok(vec![scalar_from_u128(v as u128)])
    }
}
