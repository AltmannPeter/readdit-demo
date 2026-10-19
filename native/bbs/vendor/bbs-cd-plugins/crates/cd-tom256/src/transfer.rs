//! Cross-group equality of a bounded integer committed in BLS12-381 G1
//! (ETSI committed-disclosure commitment D = Y0*m + Y1*s) and in Tom-256
//! (T = m*GT + rho*HT).  Fiat–Shamir with aborts (HPI dleq_rok / ePrint
//! 2022/1593), parametric (decision D6):
//!   m < 2^b_x;  k <- [0, 2^(b_x+b_c+b_f));  z = k + c*m (integers)
//!   accept iff 2^(b_x+b_c) <= z < 2^(b_x+b_c+b_f)
//! Each transfer aborts with probability exactly 2^-b_f, and an accepted z
//! is uniform on the accepted interval, independent of m.
//! **ETSI generator roles:** Y0 multiplies the message, Y1 the opening.
use bls12_381::{G1Projective, Scalar as BlsScalar};
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};

use crate::config::TransferConfig;
use crate::tom::{commit, fr_from_biguint, Fr, TomPoint};

/// Integer bounds of one transfer configuration for a limb size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bounds {
    pub limb_bits: u8,
    pub z_bits: u32,
    pub z_bytes: usize,
    pub z_lo: BigUint,
    pub z_hi: BigUint,
    pub c_hi: BigUint,
    pub m_hi: BigUint,
}

impl Bounds {
    /// Caller must have validated `cfg` for `limb_bits`.
    pub fn new(limb_bits: u8, cfg: &TransferConfig) -> Self {
        let one = BigUint::from(1u8);
        let z_bits = cfg.z_bits(limb_bits);
        Bounds {
            limb_bits,
            z_bits,
            z_bytes: cfg.z_bytes(limb_bits),
            z_lo: &one << (limb_bits as u32 + cfg.b_c as u32),
            z_hi: &one << z_bits,
            c_hi: &one << cfg.b_c as u32,
            m_hi: &one << limb_bits as u32,
        }
    }

    pub fn in_range(&self, z: &BigUint) -> bool {
        *z >= self.z_lo && *z < self.z_hi
    }
}

/// BLS scalar from an integer < r (panics otherwise; callers bound inputs).
pub fn bls_from_biguint(x: &BigUint) -> BlsScalar {
    let mut le = x.to_bytes_le();
    assert!(le.len() <= 32);
    le.resize(32, 0);
    Option::<BlsScalar>::from(BlsScalar::from_bytes(&le.try_into().unwrap())).expect("< r")
}

pub fn bls_rand<R: RngCore + CryptoRng>(rng: &mut R) -> BlsScalar {
    let mut w = [0u8; 64];
    rng.fill_bytes(&mut w);
    BlsScalar::from_bytes_wide(&w)
}

/// Uniform integer in [0, 2^bits).
fn uniform_bits<R: RngCore + CryptoRng>(bits: u32, rng: &mut R) -> BigUint {
    let nbytes = (bits as usize).div_ceil(8);
    let mut b = vec![0u8; nbytes];
    rng.fill_bytes(&mut b);
    let excess = nbytes * 8 - bits as usize;
    if excess > 0 {
        b[0] &= 0xff >> excess;
    }
    BigUint::from_bytes_be(&b)
}

pub struct DleqPrepared {
    k: BigUint,
    k1: BlsScalar,
    k2: Fr,
    pub big_k1: G1Projective,
    pub big_k2: TomPoint,
}

pub fn dleq_prepare<R: RngCore + CryptoRng>(
    y0: &G1Projective,
    y1: &G1Projective,
    bounds: &Bounds,
    rng: &mut R,
) -> DleqPrepared {
    let k = uniform_bits(bounds.z_bits, rng);
    let k1 = bls_rand(rng);
    let k2 = <Fr as ark_ff::UniformRand>::rand(rng);
    let kb = bls_from_biguint(&k);
    // fixed-base tables for the suite's Y0, Y1 (A3); generic otherwise
    let big_k1 = match crate::comb::y_combs(y0, y1) {
        Some((t0, t1)) => t0.mul(&kb) + t1.mul(&k1),
        None => y0 * kb + y1 * k1,
    };
    let big_k2 = commit(fr_from_biguint(&k), k2);
    DleqPrepared { k, k1, k2, big_k1, big_k2 }
}

/// Response (z, s1, s2) or None on abort.  Pure integer/field arithmetic.
pub fn dleq_respond(
    p: &DleqPrepared,
    m: u128,
    r1: &BlsScalar,
    r2: &Fr,
    c: &BigUint,
    bounds: &Bounds,
) -> Option<(BigUint, BlsScalar, Fr)> {
    assert!(*c < bounds.c_hi, "challenge out of range");
    assert!(BigUint::from(m) < bounds.m_hi, "limb out of range");
    let z = &p.k + c * BigUint::from(m);
    if !bounds.in_range(&z) {
        return None;
    }
    let cb = bls_from_biguint(c);
    let cf = fr_from_biguint(c);
    Some((z, p.k1 + cb * r1, p.k2 + cf * r2))
}

#[allow(clippy::too_many_arguments)]
pub fn dleq_verify(
    d: &G1Projective,
    t: &TomPoint,
    big_k1: &G1Projective,
    big_k2: &TomPoint,
    c: &BigUint,
    z: &BigUint,
    s1: &BlsScalar,
    s2: &Fr,
    y0: &G1Projective,
    y1: &G1Projective,
    bounds: &Bounds,
) -> bool {
    if !bounds.in_range(z) || *c >= bounds.c_hi {
        return false;
    }
    let zb = bls_from_biguint(z);
    let cb = bls_from_biguint(c);
    if y0 * zb + y1 * s1 != big_k1 + d * cb {
        return false;
    }
    commit(fr_from_biguint(z), *s2) == *big_k2 + *t * fr_from_biguint(c)
}

// ------------------------------------------------- limb folding, encodings
fn pow2_fr(e: u32) -> Fr {
    fr_from_biguint(&(BigUint::from(1u8) << e))
}

/// Fold 2k Tom-256 limb commitments (x limbs, then y limbs) into commitments
/// to the coordinates: (Σ_i 2^(b·i)·T_i, Σ_i 2^(b·i)·T_{k+i}).
pub fn fold(t: &[TomPoint], limb_bits: u8) -> (TomPoint, TomPoint) {
    let k = t.len() / 2;
    let mut cx = TomPoint::default();
    let mut cy = TomPoint::default();
    for i in 0..k {
        let w = pow2_fr(limb_bits as u32 * i as u32);
        cx += t[i] * w;
        cy += t[k + i] * w;
    }
    (cx, cy)
}

/// The same fold on openings: (Σ 2^(b·i)·ρ_i, Σ 2^(b·i)·ρ_{k+i}).
pub fn fold_fr(rho: &[Fr], limb_bits: u8) -> (Fr, Fr) {
    let k = rho.len() / 2;
    let mut x = Fr::default();
    let mut y = Fr::default();
    for i in 0..k {
        let w = pow2_fr(limb_bits as u32 * i as u32);
        x += rho[i] * w;
        y += rho[k + i] * w;
    }
    (x, y)
}

/// Bytes of one encoded transfer entry: K1 (48) ‖ K2 (33) ‖ z ‖ s1 (32) ‖ s2 (32).
pub fn transfer_entry_bytes(z_bytes: usize) -> usize {
    48 + 33 + z_bytes + 32 + 32
}

/// Encoded announcements (K1 ‖ K2)* of a transfer set.
pub fn transfer_ann_bytes(set: &[DleqPrepared]) -> Vec<u8> {
    let mut out = Vec::with_capacity(set.len() * 81);
    for d in set {
        out.extend_from_slice(&bbs_cd::primitives::point_to_octets_E1(&d.big_k1));
        out.extend_from_slice(&crate::tom::encode(&d.big_k2, true));
    }
    out
}
