//! Test credentials, signed with test keys.
//!
//! The keys come from fixed labels, and each signature's nonce from the key and the message, so
//! the fixtures are the same on every run. Such keys and nonces are only fit for tests.

pub mod cbor;
pub mod mdoc;
pub mod sdjwt;

use ff::{Field, FromUniformBytes};
use group::Curve;
use halo2curves::secp256r1::{Fq, Secp256r1, Secp256r1Affine};
use sha2::{Digest, Sha256};
use vega_prover::provider::pt256::t256;

use crate::gadgets::lc::{from_be, to_be};
use crate::gadgets::p256::{PublicKey, Signature, scalar_to_be};
use crate::presentation::{Date, Time};
use crate::table::sha256;

/// A standard ECDSA signature (r, s), as big-endian bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcdsaSignature {
  pub r: [u8; 32],
  pub s: [u8; 32],
}

impl EcdsaSignature {
  /// The signature as the rules take it.
  pub fn for_rules(&self) -> Signature {
    Signature::from_rs(&self.r, &self.s)
  }
}

/// A 256-bit big-endian integer reduced modulo the group order n.
fn reduce(bytes: &[u8; 32]) -> Fq {
  let mut wide = [0u8; 64];
  for (i, b) in bytes.iter().rev().enumerate() {
    wide[i] = *b;
  }
  Fq::from_uniform_bytes(&wide)
}

/// A scalar derived from labelled data, reduced from 512 bits so that it is close to uniform.
fn derive_scalar(parts: &[&[u8]]) -> Fq {
  let mut wide = [0u8; 64];
  for (half, chunk) in wide.chunks_mut(32).enumerate() {
    let mut hasher = Sha256::new();
    hasher.update([half as u8]);
    for part in parts {
      hasher.update(part);
    }
    chunk.copy_from_slice(&hasher.finalize());
  }
  Fq::from_uniform_bytes(&wide)
}

/// A key pair for tests.
#[derive(Clone, Debug)]
pub struct KeyPair {
  secret: Fq,
  pub public: PublicKey,
}

impl KeyPair {
  pub fn from_label(label: &str) -> Self {
    let secret = derive_scalar(&[b"vega-age test key", label.as_bytes()]);
    let point = (Secp256r1::generator() * secret).to_affine();
    KeyPair { secret, public: PublicKey::from_point(&point) }
  }

  /// Signs the SHA-256 digest of `message` (FIPS 186-5, clause 6.4.1). The signature has the
  /// smaller of the two valid values of s.
  pub fn sign(&self, message: &[u8]) -> EcdsaSignature {
    let digest = sha256(message);
    let z = reduce(&digest);
    let secret_bytes = scalar_to_be(&self.secret);
    let k = derive_scalar(&[b"vega-age test nonce", &secret_bytes, &digest]);
    let point = (Secp256r1::generator() * k).to_affine();
    let r = reduce(&to_be(&point.x));
    let s = Option::<Fq>::from(k.invert()).expect("a nonzero nonce") * (z + r * self.secret);
    assert!(!bool::from(r.is_zero()) && !bool::from(s.is_zero()));
    let s = [s, -s].into_iter().min_by_key(scalar_to_be).expect("two candidates");
    EcdsaSignature { r: scalar_to_be(&r), s: scalar_to_be(&s) }
  }
}

/// A curve point whose x-coordinate is `x`, when there is one: the holder's side of the
/// planted-key attempt.
pub fn point_with_x(x: &[u8; 32]) -> Option<PublicKey> {
  let field_x = from_be(x);
  if to_be(&field_x) != *x {
    return None;
  }
  let y_squared = field_x * field_x * field_x - field_x.double() - field_x
    + <Secp256r1Affine as halo2curves::CurveAffine>::b();
  let y: t256::Scalar = Option::from(y_squared.sqrt())?;
  Some(PublicKey { x: *x, y: to_be(&y) })
}

/// Sixteen bytes derived from a label, as the issuer's random salts.
pub fn salt(label: &str) -> [u8; 16] {
  let digest = sha256(label.as_bytes());
  let mut out = [0u8; 16];
  out.copy_from_slice(&digest[..16]);
  out
}

/// The dates of the test credentials.
pub const BIRTH_DATE: Date = Date { year: 1984, month: 1, day: 26 };
pub const ISSUED: Time =
  Time { date: Date { year: 2026, month: 1, day: 1 }, hour: 0, minute: 0, second: 0 };
pub const VALID_UNTIL: Time =
  Time { date: Date { year: 2031, month: 1, day: 1 }, hour: 0, minute: 0, second: 0 };
