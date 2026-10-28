//! The verifier's side of a presentation request, as the nym_auth rulebook defines it: the age
//! range and its date bounds, the proof time, the verifier input of the pseudonym, and the
//! session binding (the bytes the device key signs).

use crate::cbor;
use crate::Error;
use sha2::{Digest, Sha256};

/// A UTC calendar date (year, month, day). Comparisons are in date order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Date {
    pub y: u32,
    pub m: u32,
    pub d: u32,
}

fn is_leap(y: u32) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

fn days_in(y: u32, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => 0,
    }
}

impl Date {
    pub fn is_valid(&self) -> bool {
        (1..=12).contains(&self.m) && self.d >= 1 && self.d <= days_in(self.y, self.m)
    }

    /// "YYYY-MM-DD".
    pub fn parse(s: &str) -> Result<Date, Error> {
        let b = s.as_bytes();
        let digits = |r: std::ops::Range<usize>| -> Result<u32, Error> {
            let mut v = 0u32;
            for &c in &b[r] {
                if !c.is_ascii_digit() {
                    return Err(Error::Request("not a full-date"));
                }
                v = v * 10 + u32::from(c - b'0');
            }
            Ok(v)
        };
        if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
            return Err(Error::Request("not a full-date"));
        }
        let d = Date {
            y: digits(0..4)?,
            m: digits(5..7)?,
            d: digits(8..10)?,
        };
        if !d.is_valid() {
            return Err(Error::Request("no calendar date"));
        }
        Ok(d)
    }

    /// YYYYMMDD as a number, the circuit's encoding of a bound.
    pub fn yyyymmdd(&self) -> u64 {
        u64::from(self.y) * 10_000 + u64::from(self.m) * 100 + u64::from(self.d)
    }

    fn next(&self) -> Date {
        if self.d < days_in(self.y, self.m) {
            Date { d: self.d + 1, ..*self }
        } else if self.m < 12 {
            Date { m: self.m + 1, d: 1, ..*self }
        } else {
            Date { y: self.y + 1, m: 1, d: 1 }
        }
    }
}

/// The rulebook's age range: `A-B`, `A+` or `B-`, in whole years.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgeRange {
    pub min: Option<u32>,
    pub max: Option<u32>,
}

impl AgeRange {
    pub fn parse(s: &str) -> Result<AgeRange, Error> {
        let num = |t: &str| t.parse::<u32>().map_err(|_| Error::Request("age range"));
        if let Some(a) = s.strip_suffix('+') {
            Ok(AgeRange { min: Some(num(a)?), max: None })
        } else if let Some(b) = s.strip_suffix('-') {
            Ok(AgeRange { min: None, max: Some(num(b)?) })
        } else if let Some((a, b)) = s.split_once('-') {
            let (a, b) = (num(a)?, num(b)?);
            if a > b {
                return Err(Error::Request("age range with A > B"));
            }
            Ok(AgeRange { min: Some(a), max: Some(b) })
        } else {
            Err(Error::Request("age range"))
        }
    }

    /// The bounds E and C from the UTC date D of proof_time (the rulebook): C is the latest
    /// calendar date on or before D minus A years, E the earliest calendar date after D minus
    /// (B + 1) years; D minus N years keeps D's month and day, and may be no calendar date (such
    /// as 02-29 in a common year). A missing bound is `None`.
    pub fn bounds(&self, d: Date) -> (Option<Date>, Option<Date>) {
        let minus = |n: u32| (d.y.saturating_sub(n), d.m, d.d);
        let c = self.min.map(|a| {
            let (y, m, mut dd) = minus(a);
            while !(Date { y, m, d: dd }).is_valid() {
                dd -= 1;
            }
            Date { y, m, d: dd }
        });
        let e = self.max.map(|b| {
            let (y, m, dd) = minus(b + 1);
            let t = Date { y, m, d: dd };
            if t.is_valid() {
                t.next()
            } else {
                let mut dd = dd;
                while !(Date { y, m, d: dd }).is_valid() {
                    dd -= 1;
                }
                Date { y, m, d: dd }.next()
            }
        });
        (e, c)
    }
}

/// The circuit's bounds as numbers: E's YYYYMMDD or 0, C's or 99999999 (the widest values).
pub fn bound_numbers(e: Option<Date>, c: Option<Date>) -> (u64, u64) {
    (e.map_or(0, |d| d.yyyymmdd()), c.map_or(99_999_999, |d| d.yyyymmdd()))
}

/// proof_time "YYYY-MM-DDThh:mm:ssZ" as the number YYYYMMDDhhmmss, and its UTC date.
pub fn proof_time(s: &str) -> Result<(u64, Date), Error> {
    let b = s.as_bytes();
    if b.len() != 20 || b[10] != b'T' || b[13] != b':' || b[16] != b':' || b[19] != b'Z' {
        return Err(Error::Request("proof_time is not YYYY-MM-DDThh:mm:ssZ"));
    }
    let date = Date::parse(&s[..10])?;
    let mut v = 0u64;
    for (i, &c) in b.iter().enumerate().take(19) {
        if [4, 7, 10, 13, 16].contains(&i) {
            continue;
        }
        if !c.is_ascii_digit() {
            return Err(Error::Request("proof_time"));
        }
        v = v * 10 + u64::from(c - b'0');
    }
    let hh = (v / 10_000) % 100;
    let mm = (v / 100) % 100;
    let ss = v % 100;
    if hh > 23 || mm > 59 || ss > 59 {
        return Err(Error::Request("proof_time"));
    }
    Ok((v, date))
}

/// verifier_input = SHA-256(verifier_id), the pseudonym's verifier input for
/// known-offender-matching-ssc.
pub fn verifier_input(verifier_id: &str) -> [u8; 32] {
    Sha256::digest(verifier_id.as_bytes()).into()
}

/// The session the device signature binds (OpenID4VP's mdoc handovers, as the rulebook's test
/// vectors encode them).
#[derive(Clone, Debug)]
pub enum Session {
    /// Redirect flow: OpenID4VPHandover over [client_id, nonce, jwk_thumbprint, response_uri].
    Redirect {
        client_id: String,
        nonce: String,
        jwk_thumbprint: Option<[u8; 32]>,
        response_uri: String,
    },
    /// DC API: OpenID4VPDCAPIHandover over [origin, nonce, jwk_thumbprint].
    DcApi {
        origin: String,
        nonce: String,
        jwk_thumbprint: Option<[u8; 32]>,
    },
}

fn put_opt_bytes(out: &mut Vec<u8>, b: &Option<[u8; 32]>) {
    match b {
        Some(t) => cbor::put_bytes(out, t),
        None => cbor::put_null(out),
    }
}

impl Session {
    /// SessionTranscript = [null, null, [name, SHA-256(handover info)]].
    pub fn transcript(&self) -> Vec<u8> {
        let mut info = Vec::new();
        let name = match self {
            Session::Redirect { client_id, nonce, jwk_thumbprint, response_uri } => {
                cbor::put_array(&mut info, 4);
                cbor::put_text(&mut info, client_id);
                cbor::put_text(&mut info, nonce);
                put_opt_bytes(&mut info, jwk_thumbprint);
                cbor::put_text(&mut info, response_uri);
                "OpenID4VPHandover"
            }
            Session::DcApi { origin, nonce, jwk_thumbprint } => {
                cbor::put_array(&mut info, 3);
                cbor::put_text(&mut info, origin);
                cbor::put_text(&mut info, nonce);
                put_opt_bytes(&mut info, jwk_thumbprint);
                "OpenID4VPDCAPIHandover"
            }
        };
        let mut st = Vec::new();
        cbor::put_array(&mut st, 3);
        cbor::put_null(&mut st);
        cbor::put_null(&mut st);
        cbor::put_array(&mut st, 2);
        cbor::put_text(&mut st, name);
        cbor::put_bytes(&mut st, &Sha256::digest(&info));
        st
    }
}

/// The bytes the device key signs: the COSE Sig_structure ["Signature1", {1: -7}, h'',
/// DeviceAuthenticationBytes] of the detached device signature, DeviceAuthentication =
/// ["DeviceAuthentication", SessionTranscript, docType, tag 24 on the empty map].
pub fn device_signed_bytes(session: &Session, doc_type: &str) -> Vec<u8> {
    let st = session.transcript();
    let mut da = Vec::new();
    cbor::put_array(&mut da, 4);
    cbor::put_text(&mut da, "DeviceAuthentication");
    da.extend_from_slice(&st);
    cbor::put_text(&mut da, doc_type);
    cbor::put_tag(&mut da, 24);
    cbor::put_bytes(&mut da, &[0xa0]);
    let mut dab = Vec::new();
    cbor::put_tag(&mut dab, 24);
    cbor::put_bytes(&mut dab, &da);
    let mut ss = Vec::new();
    cbor::put_array(&mut ss, 4);
    cbor::put_text(&mut ss, "Signature1");
    cbor::put_bytes(&mut ss, &[0xa1, 0x01, 0x26]);
    cbor::put_bytes(&mut ss, &[]);
    cbor::put_bytes(&mut ss, &dab);
    ss
}

#[cfg(test)]
mod tests {
    use super::*;
    fn d(s: &str) -> Date {
        Date::parse(s).unwrap()
    }
    fn b(r: &str, day: &str) -> (Option<Date>, Option<Date>) {
        AgeRange::parse(r).unwrap().bounds(d(day))
    }
    #[test]
    fn rulebook_examples() {
        assert_eq!(b("13-17", "2026-10-20"), (Some(d("2008-10-21")), Some(d("2013-10-20"))));
        assert_eq!(b("13+", "2028-02-29"), (None, Some(d("2015-02-28"))));
        assert_eq!(b("17-", "2028-02-29"), (Some(d("2010-03-01")), None));
        assert_eq!(b("15-15", "2027-03-01"), (Some(d("2011-03-02")), Some(d("2012-03-01"))));
        assert_eq!(b("0-0", "2027-02-28"), (Some(d("2026-03-01")), Some(d("2027-02-28"))));
    }
}
