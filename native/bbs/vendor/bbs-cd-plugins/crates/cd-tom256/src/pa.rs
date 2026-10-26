//! Committed point-addition proof (PA) over Tom-256 Pedersen commitments to
//! P-256 coordinates: A + B = T, with C1..C6 committing to (xA, yA, xB, yB, xT, yT).
//! Algebra: hpicrypto/ecdsa_pops@e051487 ec_point_add_protocol_opt.rs (Opt 1–3),
//! identical to check_relation.py and the Python prototype.
//!
//! What the PA proves.  It proves the chord-formula relation between the
//! committed coordinates, with x(A) ≠ x(B) (U1 ≠ O).  It does not prove that
//! any point is on the curve:
//!
//! * Inside the SM proof (A = the committed result, B = V, T = U, with B and
//!   T opened as curve points): the relation forces A = T − B onto the curve,
//!   except when B = −T (finding F-1).  Use it only where the committed A is
//!   known to be valid (on-curve proof, or the issuer's check).
//! * As a standalone link (hashed mode, A = committed key Q, B = Hpt public,
//!   T = committed W): T is the formula "sum" of A and B, which need not be
//!   a curve point when A is not one.  The on-curve proof for Q rules that
//!   out.
//!
//! Restricted variant (HPI Opt 3, finding H-5).  Like HPI's
//! `ec_point_add_protocol_opt.rs`, this PA omits the proof of knowledge of
//! C2's opening (the commitment to y_A).  Its responses open C1, C3, C5 and
//! only the combinations C4 − C2 and C2 + C6 on the y side, leaving one free
//! degree: an unknown C2 would still verify.  So every use must make C2's
//! opening known some other way:
//!
//! * in the SM proof, each round opens U or V (C6 or C4), and C2 follows
//!   from C2 + C6 or C4 − C2 (HPI's argument);
//! * in the hashed-mode link, B = Hpt is public with zero blinding, so the
//!   verifier computes C3, C4 itself and C2 = C4 − (C4 − C2); independently,
//!   C2 = the y part of C_Q, whose opening the transfers and the on-curve
//!   proof establish.
//!
//! A new use with a hidden B and no other proof for C2 needs the standalone
//! variant with the C2 opening proof (HPI `ec_point_add_protocol_opt_alone.rs`).
use ark_ff::{UniformRand, Zero};
use p256::ProjectivePoint;
use rand_core::{CryptoRng, RngCore};

use crate::p256x;
use crate::tom::{commit, gt_mul, ht_mul, mul, Fr, TomPoint};
use bbs_cd_plugin::error::{Error, Result};

pub const N_ANN: usize = 10;
pub const N_RESP: usize = 12;

pub fn derived(c: &[TomPoint; 6]) -> [TomPoint; 5] {
    let [c1, c2, c3, c4, c5, c6] = *c;
    [c3 - c1, c4 - c2, c1 + c3 + c5, c1 - c5, c2 + c6]
}

/// Secret prover state of one PA proof.  Not `Clone` in normal builds (L-3):
/// two responses for one first message reveal the witness.
#[cfg_attr(feature = "insecure-test-controls", derive(Clone))]
pub struct PaState {
    masks: [Fr; 12],
    slopes: [Fr; 12],
    /// [Ct, T1..T6, U1, U2, U3]
    pub ann: [TomPoint; 10],
}

impl PaState {
    #[allow(clippy::needless_range_loop)]
    pub fn respond(&self, e: Fr) -> [Fr; 12] {
        let mut z = [Fr::zero(); 12];
        for i in 0..12 {
            z[i] = self.masks[i] + e * self.slopes[i];
        }
        z
    }
}

/// Honest prepare from points: computes the chord slope.
pub fn pa_prepare<R: RngCore + CryptoRng>(
    a: &ProjectivePoint,
    b: &ProjectivePoint,
    t: &ProjectivePoint,
    blinds: &[Fr; 6],
    c: &[TomPoint; 6],
    rng: &mut R,
) -> Result<PaState> {
    use p256::elliptic_curve::Group;
    if bool::from(a.is_identity()) || bool::from(b.is_identity()) || bool::from(t.is_identity()) {
        return Err(Error::Prover("PA: identity input".into()));
    }
    if *a + *b != *t {
        return Err(Error::Prover("PA: A + B != T".into()));
    }
    let (ax, ay) = p256x::coords_fr(a);
    let (bx, by) = p256x::coords_fr(b);
    let (tx, ty) = p256x::coords_fr(t);
    let f = bx - ax;
    if f.is_zero() {
        return Err(Error::Prover("PA: x(B) == x(A), exceptional addition".into()));
    }
    let slope = (by - ay) * f.inverse_or_panic();
    pa_prepare_with_slope((ax, ay), (bx, by), (tx, ty), slope, blinds, c, rng)
}

trait InvOrPanic {
    fn inverse_or_panic(&self) -> Self;
}
impl InvOrPanic for Fr {
    fn inverse_or_panic(&self) -> Fr {
        use ark_ff::Field;
        self.inverse().expect("nonzero")
    }
}

/// Prepare from explicit coordinates and slope.  Used by the honest path and
/// by tests that construct the F-1 off-curve counterexample.
pub fn pa_prepare_with_slope<R: RngCore + CryptoRng>(
    a: (Fr, Fr),
    b: (Fr, Fr),
    t: (Fr, Fr),
    slope: Fr,
    blinds: &[Fr; 6],
    c: &[TomPoint; 6],
    rng: &mut R,
) -> Result<PaState> {
    let (ax, _ay) = a;
    let (bx, _by) = b;
    let (tx, _ty) = t;
    let [r1, r2, r3, r4, r5, r6] = *blinds;
    let f = bx - ax;
    if f.is_zero() {
        return Err(Error::Prover("PA: f == 0".into()));
    }
    let g = ax - tx;
    let rt = Fr::rand(rng);
    let ct = commit(slope, rt);
    let [f1, _p1, _p2, _f3, _p3] = derived(c);
    let m: [Fr; 9] = std::array::from_fn(|_| Fr::rand(rng));
    let [at, art, af, arf, ae1, ae2, ag, arg, ae3] = m;
    let beta = loop {
        let x = Fr::rand(rng);
        if !x.is_zero() {
            break x;
        }
    };
    let (b2, b3, b4) = (Fr::rand(rng), Fr::rand(rng), Fr::rand(rng));
    // GT/HT terms through the fixed-base tables (A3); the four
    // variable-base products (F1·at, Ct·at, Ct·ag, F1·b2) stay generic.
    let ann = [
        ct,
        commit(at, art),
        commit(af, arf),
        mul(&f1, &at) + ht_mul(&ae1),
        mul(&ct, &at) + ht_mul(&ae2),
        commit(ag, arg),
        mul(&ct, &ag) + ht_mul(&ae3),
        gt_mul(&(beta * f)),
        mul(&f1, &b2) + ht_mul(&b3),
        gt_mul(&b4),
    ];
    let masks = [at, art, af, arf, ae1, ae2, ag, arg, ae3, b2, b3, b4];
    let slopes = [
        slope,
        rt,
        f,
        r3 - r1,
        (r4 - r2) - (r3 - r1) * slope,
        (r1 + r3 + r5) - rt * slope,
        g,
        r1 - r5,
        (r2 + r6) - rt * g,
        beta,
        -(beta * (r3 - r1)),
        beta * f,
    ];
    Ok(PaState { masks, slopes, ann })
}

pub fn pa_verify(c: &[TomPoint; 6], ann: &[TomPoint; 10], e: Fr, z: &[Fr; 12]) -> bool {
    let [ct, t1, t2, t3, t4, t5, t6, u1, u2, u3] = *ann;
    let [zt, zrt, zf, zrf, ze1, ze2, zg, zrg, ze3, v1, v2, v3] = *z;
    let [f1, p1, p2, f3, p3] = derived(c);
    if u1.is_zero() {
        return false;
    }
    let me = -e;
    commit(zt, zrt) + mul(&ct, &me) == t1
        && commit(zf, zrf) + mul(&f1, &me) == t2
        && mul(&f1, &zt) + ht_mul(&ze1) + mul(&p1, &me) == t3
        && mul(&ct, &zt) + ht_mul(&ze2) + mul(&p2, &me) == t4
        && commit(zg, zrg) + mul(&f3, &me) == t5
        && mul(&ct, &zg) + ht_mul(&ze3) + mul(&p3, &me) == t6
        && gt_mul(&v3) + mul(&u1, &me) == u3
        && mul(&f1, &v1) + ht_mul(&v2) + mul(&u1, &me) == u2
}
