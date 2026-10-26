//! Fixed-base precomputed tables (optimization A3).
//!
//! For a base P and window width w ∈ {4, 8}, the table holds
//! d·2^(w·i)·P for every window i < 256/w and digit 1 ≤ d < 2^w (affine
//! entries for Tom-256 and G1, projective entries for P-256).  A scalar multiplication s·P is then the sum of one table entry per
//! non-zero w-bit digit of s: at most 256/w mixed additions and no doublings,
//! instead of about 256 doublings plus additions.  The result is exactly
//! s·P (the scalar is used as its canonical integer < group order).
//!
//! Tables:
//! - Tom-256 GT and HT (w = 8, built once per process on first use): every
//!   Pedersen commitment `tom::commit`, and the GT/HT terms of the PA and
//!   on-curve proofs.
//! - P-256 Q′ (w = 4, built per slot and per verification): the SM round
//!   points U = ω·Q′ (prepare) and W = α·Q′ (verify).
//! - BLS12-381 Y0 and Y1 (w = 4, built once per process): the transfer
//!   announcements K1 = k·Y0 + k1·Y1.
//!
//! **Not constant-time.** Table lookups are indexed by secret scalar digits
//! (a cache-timing channel), like the rest of this prototype.
use std::sync::OnceLock;

use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField, Zero};

use crate::tom::{gt, ht, Fr, TomAffine, TomPoint};

/// The `i`-th w-bit digit of a little-endian 32-byte integer.
#[inline]
fn digit(le: &[u8; 32], i: usize, w: usize) -> usize {
    match w {
        8 => le[i] as usize,
        4 => ((le[i / 2] >> (4 * (i % 2))) & 0x0f) as usize,
        _ => unreachable!("window width must be 4 or 8"),
    }
}

fn check_w(w: usize) {
    assert!(w == 4 || w == 8, "window width must be 4 or 8");
}

/// Table layout shared by all three implementations: for window i, the
/// entries d = 1..2^w − 1 at index i·(2^w − 1) + d − 1.
fn build_projective<G: Copy + core::ops::AddAssign<G>>(p: G, w: usize) -> Vec<G> {
    check_w(w);
    let (windows, per) = (256 / w, (1usize << w) - 1);
    let mut out = Vec::with_capacity(windows * per);
    let mut base = p;
    for _ in 0..windows {
        let mut acc = base;
        for _ in 0..per {
            out.push(acc);
            acc += base;
        }
        base = acc; // 2^w · previous base
    }
    out
}

// ---------------------------------------------------------------- Tom-256
pub struct TomComb {
    w: usize,
    table: Vec<TomAffine>,
}

impl TomComb {
    pub fn new(p: TomPoint, w: usize) -> Self {
        let proj = build_projective(p, w);
        TomComb { w, table: TomPoint::normalize_batch(&proj) }
    }

    pub fn mul(&self, s: &Fr) -> TomPoint {
        let v = s.into_bigint().to_bytes_le();
        let mut le = [0u8; 32];
        le[..v.len()].copy_from_slice(&v);
        let (windows, per) = (256 / self.w, (1usize << self.w) - 1);
        let mut acc = TomPoint::zero();
        for i in 0..windows {
            let d = digit(&le, i, self.w);
            if d != 0 {
                acc += self.table[i * per + d - 1];
            }
        }
        acc
    }
}

pub fn gt_comb() -> &'static TomComb {
    static T: OnceLock<TomComb> = OnceLock::new();
    T.get_or_init(|| TomComb::new(TomPoint::from(gt()), 8))
}

pub fn ht_comb() -> &'static TomComb {
    static T: OnceLock<TomComb> = OnceLock::new();
    T.get_or_init(|| TomComb::new(TomPoint::from(ht()), 8))
}

// ------------------------------------------------------------------ P-256
/// P-256 table with projective entries (p256 0.13 offers no slice batch
/// normalisation from outside the crate), so each step is a full projective
/// addition instead of a mixed one.  Still no doublings.
pub struct P256Comb {
    w: usize,
    table: Vec<p256::ProjectivePoint>,
}

impl P256Comb {
    pub fn new(p: p256::ProjectivePoint, w: usize) -> Self {
        P256Comb { w, table: build_projective(p, w) }
    }

    pub fn mul(&self, s: &p256::Scalar) -> p256::ProjectivePoint {
        let mut le: [u8; 32] = s.to_bytes().into();
        le.reverse();
        let (windows, per) = (256 / self.w, (1usize << self.w) - 1);
        let mut acc = p256::ProjectivePoint::IDENTITY;
        for i in 0..windows {
            let d = digit(&le, i, self.w);
            if d != 0 {
                acc += self.table[i * per + d - 1];
            }
        }
        acc
    }
}

// ------------------------------------------------------------- BLS12-381 G1
pub struct G1Comb {
    w: usize,
    table: Vec<bls12_381::G1Affine>,
}

impl G1Comb {
    pub fn new(p: bls12_381::G1Projective, w: usize) -> Self {
        let proj = build_projective(p, w);
        let mut table = vec![bls12_381::G1Affine::identity(); proj.len()];
        bls12_381::G1Projective::batch_normalize(&proj, &mut table);
        G1Comb { w, table }
    }

    pub fn mul(&self, s: &bls12_381::Scalar) -> bls12_381::G1Projective {
        let le = s.to_bytes();
        let (windows, per) = (256 / self.w, (1usize << self.w) - 1);
        let mut acc = bls12_381::G1Projective::identity();
        for i in 0..windows {
            let d = digit(&le, i, self.w);
            if d != 0 {
                acc += &self.table[i * per + d - 1];
            }
        }
        acc
    }
}

/// Tables for the ETSI commitment generators (Y0, Y1), built on first use.
/// Returns None if called with other generators (the caller then falls
/// back to generic multiplication).
pub fn y_combs(
    y0: &bls12_381::G1Projective,
    y1: &bls12_381::G1Projective,
) -> Option<(&'static G1Comb, &'static G1Comb)> {
    type YTables = (bls12_381::G1Projective, bls12_381::G1Projective, G1Comb, G1Comb);
    static T: OnceLock<YTables> = OnceLock::new();
    let t = T.get_or_init(|| (*y0, *y1, G1Comb::new(*y0, 4), G1Comb::new(*y1, 4)));
    (t.0 == *y0 && t.1 == *y1).then_some((&t.2, &t.3))
}
