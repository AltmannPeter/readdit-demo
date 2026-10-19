//! Tom-256 (prime-order curve whose group order is the P-256 base-field prime
//! p) over arkworks.  Constants from hpicrypto/ecdsa_pops@e051487 CDLS/t256.
//!
//! Encoding (same as the Python prototype): 33 bytes, 0x02|0x03 || x (big-endian,
//! x < pT); the identity is 33 zero bytes and is accepted only where the caller
//! allows it (commitments and announcements, never U1).

use ark_ec::{
    models::CurveConfig,
    short_weierstrass::{self as sw, SWCurveConfig},
    AdditiveGroup, AffineRepr, CurveGroup,
};
use ark_ff::{
    fields::{Fp256, MontBackend, MontConfig},
    BigInteger, Field, MontFp, One, PrimeField, UniformRand, Zero,
};
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};

use bbs_cd_plugin::error::{decode, Result};

/// Tom-256 base field (pT).  Generator 3 is a quadratic non-residue.
#[derive(MontConfig)]
#[modulus = "115792089210356248762697446949407573530594504085698471288169790229257723883799"]
#[generator = "3"]
pub struct FqConfig;
pub type Fq = Fp256<MontBackend<FqConfig, 4>>;

/// Tom-256 scalar field = P-256 base field p.  Generator 3 is a non-residue.
#[derive(MontConfig)]
#[modulus = "115792089210356248762697446949407573530086143415290314195533631308867097853951"]
#[generator = "3"]
pub struct FrConfig;
pub type Fr = Fp256<MontBackend<FrConfig, 4>>;

#[derive(Copy, Clone, Default, PartialEq, Eq)]
pub struct TomConfig;

impl CurveConfig for TomConfig {
    type BaseField = Fq;
    type ScalarField = Fr;
    const COFACTOR: &'static [u64] = &[1];
    const COFACTOR_INV: Fr = Fr::ONE;
}

impl SWCurveConfig for TomConfig {
    const COEFF_A: Fq = MontFp!("115792089210356248762697446949407573530594504085698471288169790229257723883796");
    const COEFF_B: Fq = MontFp!("81531206846337786915455327229510804132577517753388365729879493166393691077718");
    const GENERATOR: TomAffine = TomAffine::new_unchecked(
        MontFp!("3"),
        MontFp!("40902200210088653215032584946694356296222563095503428277299570638400093548589"),
    );
}

pub type TomAffine = sw::Affine<TomConfig>;
pub type TomPoint = sw::Projective<TomConfig>;

/// Second commitment generator HT: the Tom-256 point with x = 5 and the
/// smaller of the two y roots (y < pT − y).  Same value as the pinned HPI
/// source.
///
/// Provenance (review findings G-1/H-3).  GT is the point with x = 3 and the
/// smaller y; HT the point with x = 5 and the smaller y (x = 4 is also on
/// the curve, so the rule is "these two points", not "the two smallest x").
/// Both are fixed by tiny public constants, so nobody can have chosen them
/// to know log_GT(HT): finding such a pair would itself solve a discrete
/// logarithm.  This is the usual "nothing up my sleeve" argument; a
/// hash-to-curve derivation would give the same assurance but change every
/// Tom-256 commitment value and break value compatibility with HPI.
/// `tests/arith.rs` re-derives both points from this rule.
pub fn ht() -> TomAffine {
    TomAffine::new_unchecked(
        MontFp!("5"),
        MontFp!("28281484859698624956664858566852274012236038028101624500031073655422126514829"),
    )
}

/// First commitment generator GT (the curve generator): x = 3, smaller y.
/// See [`ht`] for the provenance of both.
pub fn gt() -> TomAffine {
    TomConfig::GENERATOR
}

/// Pedersen commitment v*GT + r*HT (scalars mod p), via the fixed-base
/// tables of `comb` (A3).
pub fn commit(v: Fr, r: Fr) -> TomPoint {
    crate::comb::gt_comb().mul(&v) + crate::comb::ht_comb().mul(&r)
}

/// s·GT via the fixed-base table (A3).
pub fn gt_mul(s: &Fr) -> TomPoint {
    crate::comb::gt_comb().mul(s)
}

/// s·HT via the fixed-base table (A3).
pub fn ht_mul(s: &Fr) -> TomPoint {
    crate::comb::ht_comb().mul(s)
}

/// Encode a batch of points with one shared field inversion (A7).
pub fn encode_batch(ps: &[TomPoint], allow_identity: impl Fn(usize) -> bool) -> Vec<[u8; 33]> {
    TomPoint::normalize_batch(ps).iter().enumerate().map(|(i, a)| encode_affine(a, allow_identity(i))).collect()
}

/// s·P with shortcuts for s ∈ {0, 1, −1} (A4).  In `draft00-shared-bit`
/// the PA challenge is a bit, so −e ∈ {0, −1}; a generic multiplication by
/// −1 = p − 1 would cost a full 256-bit scalar multiplication.  The result
/// is identical; only the work differs.
pub fn mul(p: &TomPoint, s: &Fr) -> TomPoint {
    if s.is_zero() {
        TomPoint::zero()
    } else if s.is_one() {
        *p
    } else if (-*s).is_one() {
        -*p
    } else {
        // width-4 wNAF instead of arkworks' default double-and-add for SW
        // curves (about 52 additions instead of about 128 per multiplication).
        ark_ec::scalar_mul::wnaf::WnafContext::new(4).mul(*p, s)
    }
}

/// Sum of scalar multiples (uses the A4 shortcuts of [`mul`]).
pub fn lin(terms: &[(TomPoint, Fr)]) -> TomPoint {
    let mut acc = TomPoint::zero();
    for (p, s) in terms {
        if !s.is_zero() {
            acc += mul(p, s);
        }
    }
    acc
}

pub fn fr_rand<R: RngCore + CryptoRng>(rng: &mut R) -> Fr {
    Fr::rand(rng)
}

pub fn fr_from_be(b: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(b)
}

/// Canonical 32-byte big-endian encoding of an Fr element.
pub fn fr_to_be(x: &Fr) -> [u8; 32] {
    let v = x.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(&v);
    out
}

/// Parse a canonical Fr element (rejects values >= p).
pub fn fr_from_canonical(b: &[u8; 32]) -> Result<Fr> {
    let x = BigUint::from_bytes_be(b);
    let m = BigUint::from_bytes_be(&Fr::MODULUS.to_bytes_be());
    if x >= m {
        return decode("Tom scalar out of range");
    }
    Ok(Fr::from_be_bytes_mod_order(b))
}

pub fn fr_to_biguint(x: &Fr) -> BigUint {
    BigUint::from_bytes_be(&x.into_bigint().to_bytes_be())
}

pub fn fr_from_biguint(x: &BigUint) -> Fr {
    Fr::from_be_bytes_mod_order(&x.to_bytes_be())
}

pub fn encode(p: &TomPoint, allow_identity: bool) -> [u8; 33] {
    encode_affine(&p.into_affine(), allow_identity)
}

pub fn encode_affine(a: &TomAffine, allow_identity: bool) -> [u8; 33] {
    if a.infinity {
        assert!(allow_identity, "identity not encodable here");
        return [0u8; 33];
    }
    let mut out = [0u8; 33];
    out[0] = 2 | (a.y.into_bigint().is_odd() as u8);
    let xb = a.x.into_bigint().to_bytes_be();
    out[33 - xb.len()..].copy_from_slice(&xb);
    out
}

pub fn decode_point(b: &[u8], allow_identity: bool) -> Result<TomPoint> {
    if b.len() != 33 {
        return decode("Tom point must be 33 bytes");
    }
    if b.iter().all(|&x| x == 0) {
        if allow_identity {
            return Ok(TomPoint::zero());
        }
        return decode("Tom identity not allowed here");
    }
    if b[0] != 2 && b[0] != 3 {
        return decode("Tom point prefix");
    }
    let xi = BigUint::from_bytes_be(&b[1..]);
    let m = BigUint::from_bytes_be(&Fq::MODULUS.to_bytes_be());
    if xi >= m {
        return decode("Tom x non-canonical");
    }
    let x = Fq::from_be_bytes_mod_order(&b[1..]);
    let rhs = x * x * x + TomConfig::COEFF_A * x + TomConfig::COEFF_B;
    let mut y = match rhs.sqrt() {
        Some(y) => y,
        None => return decode("Tom x not on curve"),
    };
    if y.is_zero() && b[0] == 3 {
        return decode("Tom y parity non-canonical");
    }
    if (y.into_bigint().is_odd() as u8) != (b[0] & 1) {
        y = -y;
    }
    let a = TomAffine::new_unchecked(x, y);
    debug_assert!(a.is_on_curve());
    Ok(a.into_group())
}

/// Precomputation-free check helper for tests.
pub fn is_on_curve_affine(x: &Fq, y: &Fq) -> bool {
    TomAffine::new_unchecked(*x, *y).is_on_curve()
}

#[allow(dead_code)]
fn _assert_group(_: TomPoint) -> TomPoint {
    TomPoint::ZERO
}
