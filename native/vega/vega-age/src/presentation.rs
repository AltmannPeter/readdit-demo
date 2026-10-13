//! One presentation: the values the verifier names and the rules that use them.
//!
//! A core circuit splits its rules the way clause 5.4 splits the witness. The rules that depend
//! only on the credential go in the precommitted segment, which the prover commits to once and
//! reuses. They end in [`Facts`]. The rules that depend on the presentation go in the rest
//! segment, and [`check`] adds them. Clause 5.6 asks for this split. The request's patterns
//! ([`crate::request`]) are values of the presentation, so the credential's bytes they are
//! compared with pass to the rest segment as facts.
//!
//! The public values are allocated in the rest segment too, because the prover recomputes that
//! segment, and with it the public values, for each presentation.

use bellpepper_core::{ConstraintSystem, SynthesisError, num::AllocatedNum};
use vega_prover::provider::pt256::t256;

use crate::gadgets::bits::{digest_bits, range_check};
use crate::gadgets::lc::{Lc, equal, from_be, to_num};
use crate::gadgets::p256::{Point, PublicKey, Signature, verify};
use crate::request::{self, Request, Window};

/// The positions of the digits in a date YYYY-MM-DD.
pub const DATE_DIGITS: [usize; 8] = [0, 1, 2, 3, 5, 6, 8, 9];

/// The positions of the digits in a date-time YYYY-MM-DDThh:mm:ssZ.
pub const DATE_TIME_DIGITS: [usize; 14] = [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18];

/// The end of validity of a credential that sets none, 2^47 − 1. The validity checks allow no
/// later time, and it lies about 4.5 million years after 1970.
pub const NO_END: u64 = (1 << 47) - 1;

/// A calendar date.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Date {
  pub year: u32,
  pub month: u32,
  pub day: u32,
}

impl Date {
  /// The date as the number YYYYMMDD. Earlier dates give smaller numbers.
  pub fn digits(&self) -> u64 {
    u64::from(self.year) * 10_000 + u64::from(self.month) * 100 + u64::from(self.day)
  }

  /// The date as YYYY-MM-DD, as RFC 3339 writes a full-date.
  pub fn text(&self) -> String {
    format!("{:04}-{:02}-{:02}", self.year, self.month, self.day)
  }

  /// The number of days since 1970-01-01, by the days_from_civil algorithm of Howard Hinnant.
  fn days_since_1970(&self) -> i64 {
    let year = i64::from(self.year) - i64::from(self.month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_from_march = i64::from((self.month + 9) % 12);
    let day_of_year = (153 * month_from_march + 2) / 5 + i64::from(self.day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
  }
}

/// A time in UTC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Time {
  pub date: Date,
  pub hour: u32,
  pub minute: u32,
  pub second: u32,
}

impl Time {
  /// The time as the number YYYYMMDDhhmmss. Earlier times give smaller numbers.
  pub fn digits(&self) -> u64 {
    self.date.digits() * 1_000_000
      + u64::from(self.hour) * 10_000
      + u64::from(self.minute) * 100
      + u64::from(self.second)
  }

  /// The time as YYYY-MM-DDThh:mm:ssZ, as RFC 3339 writes a date-time.
  pub fn text(&self) -> String {
    format!("{}T{:02}:{:02}:{:02}Z", self.date.text(), self.hour, self.minute, self.second)
  }

  /// The number of seconds since 1970-01-01T00:00:00Z, which JWT calls a NumericDate.
  pub fn seconds_since_1970(&self) -> u64 {
    let days = u64::try_from(self.date.days_since_1970()).expect("a time after 1970");
    days * 86_400
      + u64::from(self.hour) * 3_600
      + u64::from(self.minute) * 60
      + u64::from(self.second)
  }
}

/// How a credential format writes the start and the end of its validity, which is how the
/// verifier's time is encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeEncoding {
  /// An mdoc writes validFrom and validUntil as RFC 3339 date-times. The rules read their digits.
  Digits,
  /// An SD-JWT writes nbf and exp as seconds since 1970.
  Seconds,
}

impl TimeEncoding {
  pub fn encode(&self, time: &Time) -> u64 {
    match self {
      TimeEncoding::Digits => time.digits(),
      TimeEncoding::Seconds => time.seconds_since_1970(),
    }
  }
}

/// The values the verifier names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Public {
  /// The issuer's public key.
  pub issuer_key: PublicKey,
  /// The earliest birth date that passes the age check, which sets a maximum age. None sets no
  /// maximum.
  pub born_from: Option<Date>,
  /// The latest birth date that passes the age check, which sets the minimum age.
  pub born_by: Date,
  /// The time at which the credential must be valid.
  pub now: Time,
  /// The SHA-256 digest of the message the verifier asks the device key to sign
  /// ([`crate::challenge`]).
  pub challenge: [u8; 32],
  /// The type of credential and the name of the birth-date attribute.
  pub request: Request,
}

/// The number of public values before the request's.
pub const BASE_VALUES: usize = 7;

impl Public {
  /// The public values of a core circuit, in their order. Without a maximum age the earliest
  /// birth date is 0, which every date passes. The challenge takes two values of 128 bits each,
  /// because a 256-bit digest can exceed the field prime. The request's values follow
  /// ([`Request::values`]).
  pub fn values(&self, times: TimeEncoding) -> Vec<t256::Scalar> {
    let mut values = vec![
      from_be(&self.issuer_key.x),
      from_be(&self.issuer_key.y),
      t256::Scalar::from(self.born_from.map_or(0, |date| date.digits())),
      t256::Scalar::from(self.born_by.digits()),
      t256::Scalar::from(times.encode(&self.now)),
      from_be(&self.challenge[..16]),
      from_be(&self.challenge[16..]),
    ];
    values.extend(self.request.values());
    values
  }
}

/// What the prover adds for one presentation: the public values, and the device key's signature
/// on the challenge.
#[derive(Clone, Debug)]
pub struct Presentation {
  pub public: Public,
  pub device_signature: Signature,
}

/// What a core circuit reads from the credential, once per credential.
pub struct Facts {
  /// The key that the issuer's signature verifies under.
  pub issuer_key: Point,
  /// The birth date as YYYYMMDD. The rules take its digits as the issuer wrote them, so the
  /// issuer writes a complete date.
  pub birth_date: Lc,
  /// The start and the end of validity, encoded as [`TimeEncoding`] says. A credential that sets
  /// no start has 0, and one that sets no end has [`NO_END`].
  pub valid_from: Lc,
  pub valid_until: Lc,
  /// The device key that the credential binds.
  pub device_key: Point,
  /// The credential's bytes in the windows of its type and of its attribute's name, which the
  /// rest segment compares with the request's patterns.
  pub windows: [Vec<AllocatedNum<t256::Scalar>>; 2],
}

impl Facts {
  /// Puts the facts into slots, which the rest segment reads, in a fixed order: the seven values,
  /// then the bytes of each window.
  pub fn into_slots<CS: ConstraintSystem<t256::Scalar>>(
    self,
    mut cs: CS,
  ) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
    let facts = [
      ("issuer key x", self.issuer_key.x),
      ("issuer key y", self.issuer_key.y),
      ("birth date", self.birth_date),
      ("valid from", self.valid_from),
      ("valid until", self.valid_until),
      ("device key x", self.device_key.x),
      ("device key y", self.device_key.y),
    ];
    let mut slots = facts
      .iter()
      .map(|(name, fact)| to_num(cs.namespace(|| *name), fact))
      .collect::<Result<Vec<_>, _>>()?;
    for window in self.windows {
      slots.extend(window);
    }
    Ok(slots)
  }
}

/// The slots of a window's bytes, one slot each, for [`Facts::windows`].
pub fn window_slots<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  bytes: &[Lc],
) -> Result<Vec<AllocatedNum<t256::Scalar>>, SynthesisError> {
  bytes
    .iter()
    .enumerate()
    .map(|(i, byte)| to_num(cs.namespace(|| format!("byte {i}")), byte))
    .collect()
}

/// Adds the rules of one presentation, over the slots of [`Facts::into_slots`], for a format
/// whose request has patterns in `windows`.
///
/// 1. The credential's type and its attribute's name are the patterns the verifier names
///    ([`request::check`]).
/// 2. The issuer key is the key the verifier names.
/// 3. The birth date lies from the earliest to the latest birth date the verifier names.
/// 4. The credential is valid at the verifier's time. Its validity has started and has not ended.
/// 5. The device key signed the challenge.
///
/// The request comes first: the birth date of another attribute, or of another type of
/// credential, need not even be a date.
///
/// A date is below 10^8 < 2^27, so born_by − birth_date lies in 0..2^27 exactly when the
/// birth date is not later, and birth_date − born_from exactly when it is not earlier. A time in
/// either encoding is below 10^14 < 2^47, and the validity checks work the same way. A credential
/// without an end passes the expiry check at every time below [`NO_END`].
pub fn check<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  facts: &[AllocatedNum<t256::Scalar>],
  presentation: Option<&Presentation>,
  times: TimeEncoding,
  windows: [Window; 2],
) -> Result<(), SynthesisError> {
  // A request for another format has other windows, and no witness satisfies its rules.
  if presentation.is_some_and(|p| p.public.request.windows() != windows) {
    return Err(SynthesisError::Unsatisfiable);
  }
  let values = presentation.map(|p| p.public.values(times));
  let names = [
    "issuer key x",
    "issuer key y",
    "born from",
    "born by",
    "now",
    "challenge high",
    "challenge low",
  ];
  let public = names
    .iter()
    .enumerate()
    .map(|(i, name)| {
      let value = values.as_ref().map(|v| v[i]);
      let input = AllocatedNum::alloc_input(cs.namespace(|| format!("public {name}")), || {
        value.ok_or(SynthesisError::AssignmentMissing)
      })?;
      Ok(Lc::num(&input))
    })
    .collect::<Result<Vec<_>, SynthesisError>>()?;
  // The precommitted segment passes the seven facts and the windows' bytes. A rest segment
  // given other slots, such as a state prepared from replays (`app::Replay`), has no witness.
  if facts.len() != BASE_VALUES + windows[0].len + windows[1].len {
    return Err(SynthesisError::AssignmentMissing);
  }
  let (facts, bytes) = facts.split_at(BASE_VALUES);
  let fact: Vec<Lc> = facts.iter().map(Lc::num).collect();
  let [issuer_x, issuer_y, birth_date, valid_from, valid_until, device_x, device_y] = &fact[..]
  else {
    unreachable!("a core circuit reads seven facts");
  };
  let [public_x, public_y, born_from, born_by, now, challenge_high, challenge_low] = &public[..]
  else {
    unreachable!("there are seven public values");
  };

  let (type_bytes, attribute_bytes) = bytes.split_at(windows[0].len);
  let request_values =
    values.as_ref().map(|v| v[BASE_VALUES..].split_at(windows[0].public_count()));
  let (type_values, attribute_values) = (request_values.map(|v| v.0), request_values.map(|v| v.1));
  request::check(cs.namespace(|| "type"), windows[0], type_bytes, type_values)?;
  request::check(cs.namespace(|| "attribute"), windows[1], attribute_bytes, attribute_values)?;

  equal(cs.namespace(|| "same issuer key x"), issuer_x, public_x);
  equal(cs.namespace(|| "same issuer key y"), issuer_y, public_y);

  range_check(cs.namespace(|| "born from the earliest date"), &(birth_date - born_from), 27)?;
  range_check(cs.namespace(|| "born by the cutoff"), &(born_by - birth_date), 27)?;

  range_check(cs.namespace(|| "validity started"), &(now - valid_from), 47)?;
  let remaining = valid_until - now - &Lc::small(1);
  range_check(cs.namespace(|| "not expired"), &remaining, 47)?;

  let halves = [challenge_high.clone(), challenge_low.clone()];
  let challenge = digest_bits(cs.namespace(|| "challenge bits"), &halves)?;
  let device_key = Point { x: device_x.clone(), y: device_y.clone() };
  verify(
    cs.namespace(|| "device signature"),
    &challenge,
    &device_key,
    presentation.map(|p| &p.device_signature),
  )
}
