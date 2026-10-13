//! The request: the type of credential and the name of the birth-date attribute that the verifier
//! asks for.
//!
//! The verifier names each as a pattern, the bytes that the issuer writes there with their key: the
//! docType and the element identifier of an mdoc in CBOR, the vct and the claim name of an SD-JWT VC
//! in JSON. A pattern sits at one end of a window of fixed length, and the window's other bytes are
//! zero. A thermometer of public bits gives the pattern's length. Bit k is one for every k below
//! the count, and each bit switches the comparison of one window byte. The bytes that every pattern
//! covers, at the end the pattern is aligned to, are always compared.
//!
//! | Parameter | Pattern | Window | Aligned | Thermometer counts |
//! | --- | --- | --- | --- | --- |
//! | mdoc docType | 0x67 `docType`, the text's head, the docType | 48 | right | the pattern's bytes |
//! | mdoc identifier | 0x71 `elementIdentifier`, the head, the identifier | 40 | right | the pattern's bytes |
//! | SD-JWT vct | `"vct":"`, the vct, `"` | 48 | left | the vct's bytes, at most 40 |
//! | SD-JWT claim name | `"`, the name, `",` | 19 | right | the name's bytes, at least 1 and at most 16 |
//!
//! Each pattern ends where its value ends: the CBOR head fixes the text's length, and JSON's quote
//! closes the string. A pattern therefore matches a whole value, never a part of a longer one.
//! The vct is aligned to its key, which the payload writes once. The claim name is aligned to the
//! comma after it, so the birth date that follows the name sits at a fixed place after the window.
//!
//! The patterns are request values, which the verifier knows and every holder of such a credential
//! shares. The rules compare them in the rest segment, so the prepared state holds none of them.

use bellpepper_core::{ConstraintSystem, SynthesisError, num::AllocatedNum};
use ff::Field;
use vega_prover::provider::pt256::t256;

use crate::gadgets::bits::{bits, pack_bytes};
use crate::gadgets::lc::{Lc, equal, from_be, mul};

/// The end of a window that a pattern is aligned to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Align {
  Left,
  Right,
}

/// A window of fixed length that holds one pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
  /// The window's length in bytes.
  pub len: usize,
  /// The number of bytes whose comparison a thermometer bit switches. The others, at the end the
  /// pattern is aligned to, are always compared.
  pub thermometer: usize,
  pub align: Align,
  /// Whether the pattern holds at least one thermometer byte: the name of a claim is not empty.
  pub nonempty: bool,
}

/// The public values carry a window in limbs of at most 31 bytes, each below the field prime.
pub const LIMB: usize = 31;

impl Window {
  /// The number of bytes that every pattern covers.
  pub fn fixed(&self) -> usize {
    self.len - self.thermometer
  }

  /// The window position of thermometer bit k. Bit k is one when the count exceeds k.
  pub fn position(&self, k: usize) -> usize {
    match self.align {
      Align::Right => self.thermometer - 1 - k,
      Align::Left => self.fixed() + k,
    }
  }

  /// The number of public values of a pattern: its limbs and its thermometer.
  pub fn public_count(&self) -> usize {
    self.len.div_ceil(LIMB) + 1
  }
}

/// The docType: the key, the text's head and the text. The PID's pattern takes 32 bytes and
/// nym_auth's 38.
pub const DOC_TYPE_WINDOW: Window =
  Window { len: 48, thermometer: 48, align: Align::Right, nonempty: false };

/// The element identifier: the key, the text's head and the text. birth_date's pattern takes 29
/// bytes.
pub const IDENTIFIER_WINDOW: Window =
  Window { len: 40, thermometer: 40, align: Align::Right, nonempty: false };

/// The vct: the key, a vct of at most 40 bytes and the closing quote.
pub const VCT_WINDOW: Window =
  Window { len: 48, thermometer: 40, align: Align::Left, nonempty: false };

/// The claim name: the opening quote, a name of 1 to 16 bytes, the closing quote and the comma.
pub const CLAIM_WINDOW: Window =
  Window { len: 19, thermometer: 16, align: Align::Right, nonempty: true };

/// The key docType, which the MSO holds once.
pub const DOC_TYPE_KEY: &[u8] = b"\x67docType";

/// The key elementIdentifier, which an item holds once.
pub const IDENTIFIER_KEY: &[u8] = b"\x71elementIdentifier";

/// The key vct and the opening quote of its value, which the payload holds once.
pub const VCT_KEY: &[u8] = b"\"vct\":\"";

/// The head of a CBOR text string of `len` bytes (RFC 8949, clause 3).
fn text_head(len: usize) -> Result<Vec<u8>, String> {
  match len {
    0..24 => Ok(vec![0x60 + len as u8]),
    24..256 => Ok(vec![0x78, len as u8]),
    _ => Err(format!("a text of {len} bytes is longer than any window")),
  }
}

/// A pattern the verifier names, in its window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pattern {
  window: Window,
  bytes: Vec<u8>,
}

impl Pattern {
  /// The pattern `bytes` in `window`. A pattern longer than the window does not fit, and one
  /// shorter than the bytes every pattern covers leaves a compared byte outside the pattern.
  pub fn new(window: Window, bytes: &[u8]) -> Result<Self, String> {
    if bytes.len() > window.len {
      return Err(format!(
        "a pattern of {} bytes is longer than its window of {}",
        bytes.len(),
        window.len
      ));
    }
    if bytes.len() < window.fixed() {
      return Err(format!(
        "a pattern of {} bytes is shorter than the {} bytes its window always compares",
        bytes.len(),
        window.fixed()
      ));
    }
    Ok(Pattern { window, bytes: bytes.to_vec() })
  }

  /// An mdoc's docType.
  pub fn doc_type(doc_type: &str) -> Result<Self, String> {
    let text = doc_type.as_bytes();
    Self::new(DOC_TYPE_WINDOW, &[DOC_TYPE_KEY, &text_head(text.len())?, text].concat())
  }

  /// The element identifier of an mdoc item.
  pub fn identifier(identifier: &str) -> Result<Self, String> {
    let text = identifier.as_bytes();
    Self::new(IDENTIFIER_WINDOW, &[IDENTIFIER_KEY, &text_head(text.len())?, text].concat())
  }

  /// An SD-JWT VC's vct, as the payload's JSON writes it.
  pub fn vct(vct: &str) -> Result<Self, String> {
    Self::new(VCT_WINDOW, &[VCT_KEY, vct.as_bytes(), b"\""].concat())
  }

  /// The claim name of an SD-JWT disclosure, as the disclosure's JSON writes it.
  pub fn claim(name: &str) -> Result<Self, String> {
    if name.is_empty() {
      return Err("a claim name is not empty".to_string());
    }
    Self::new(CLAIM_WINDOW, &[b"\"", name.as_bytes(), b"\","].concat())
  }

  pub fn window(&self) -> Window {
    self.window
  }

  pub fn bytes(&self) -> &[u8] {
    &self.bytes
  }

  /// The thermometer's count: the pattern's bytes beyond those every pattern covers.
  pub fn count(&self) -> usize {
    self.bytes.len() - self.window.fixed()
  }

  /// The window's bytes: the pattern at its end, and zeros.
  pub fn aligned(&self) -> Vec<u8> {
    let mut window = vec![0; self.window.len];
    let at = match self.window.align {
      Align::Left => 0,
      Align::Right => self.window.len - self.bytes.len(),
    };
    window[at..at + self.bytes.len()].copy_from_slice(&self.bytes);
    window
  }

  /// The public values: the window's bytes in limbs of [`LIMB`] bytes, each a big-endian integer,
  /// and then the thermometer 2^count − 1.
  pub fn values(&self) -> Vec<t256::Scalar> {
    let mut values: Vec<t256::Scalar> = self.aligned().chunks(LIMB).map(from_be).collect();
    let thermometer =
      (0..self.count()).fold(t256::Scalar::ZERO, |sum, _| sum.double() + t256::Scalar::ONE);
    values.push(thermometer);
    values
  }
}

/// The two patterns of a request: the credential's type and the birth-date attribute's name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
  pub credential_type: Pattern,
  pub attribute: Pattern,
}

impl Request {
  /// An mdoc of the docType `doc_type` whose item `identifier` holds the birth date.
  pub fn mdoc(doc_type: &str, identifier: &str) -> Result<Self, String> {
    Ok(Request {
      credential_type: Pattern::doc_type(doc_type)?,
      attribute: Pattern::identifier(identifier)?,
    })
  }

  /// An SD-JWT VC of the type `vct` whose claim `claim` holds the birth date.
  pub fn sdjwt(vct: &str, claim: &str) -> Result<Self, String> {
    Ok(Request { credential_type: Pattern::vct(vct)?, attribute: Pattern::claim(claim)? })
  }

  /// The windows of the two patterns.
  pub fn windows(&self) -> [Window; 2] {
    [self.credential_type.window, self.attribute.window]
  }

  /// The public values of both patterns, in their order.
  pub fn values(&self) -> Vec<t256::Scalar> {
    [self.credential_type.values(), self.attribute.values()].concat()
  }
}

/// Adds the rules that the credential's bytes in `window` hold the pattern whose public values
/// the verifier names, and allocates those values as public inputs.
///
/// The thermometer's bits come from its value with a range check of the window's thermometer
/// length, so a thermometer with more ones than the window has bytes has no bits and fails. Each
/// switched byte is multiplied by its bit, and the bytes of each limb, packed as a big-endian
/// integer, equal the limb. A byte is below 256 and a limb has at most 31 of them, so the packed
/// values are equal exactly when every compared byte equals the pattern's and every other byte of
/// the pattern's window is zero.
pub fn check<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  window: Window,
  credential: &[AllocatedNum<t256::Scalar>],
  values: Option<&[t256::Scalar]>,
) -> Result<(), SynthesisError> {
  assert_eq!(credential.len(), window.len);
  let inputs = (0..window.public_count())
    .map(|i| {
      let value = values.map(|v| v[i]);
      let input = AllocatedNum::alloc_input(cs.namespace(|| format!("public {i}")), || {
        value.ok_or(SynthesisError::AssignmentMissing)
      })?;
      Ok(Lc::num(&input))
    })
    .collect::<Result<Vec<_>, SynthesisError>>()?;
  let (limbs, thermometer) = inputs.split_at(inputs.len() - 1);
  let thermometer = bits(cs.namespace(|| "thermometer bits"), &thermometer[0], window.thermometer)?;
  if window.nonempty {
    // The thermometer 2^count − 1 has its lowest bit set exactly when count is at least one.
    equal(
      cs.namespace(|| "nonempty"),
      &Lc::bit(&thermometer[window.thermometer - 1]),
      &Lc::small(1),
    );
  }
  // `bits` lists the most significant bit first.
  let mut switch: Vec<Option<Lc>> = vec![None; window.len];
  for k in 0..window.thermometer {
    switch[window.position(k)] = Some(Lc::bit(&thermometer[window.thermometer - 1 - k]));
  }
  let compared = credential
    .iter()
    .zip(&switch)
    .enumerate()
    .map(|(i, (byte, bit))| match bit {
      Some(bit) => mul(cs.namespace(|| format!("byte {i}")), bit, &Lc::num(byte)),
      None => Ok(Lc::num(byte)),
    })
    .collect::<Result<Vec<_>, _>>()?;
  for (l, (bytes, limb)) in compared.chunks(LIMB).zip(limbs).enumerate() {
    equal(cs.namespace(|| format!("limb {l}")), &pack_bytes(bytes), limb);
  }
  Ok(())
}
