//! Batch verification of the linear group equations (optimization A5,
//! permitted by report §10.2).
//!
//! Every Tom-256 equation of the transfer, the on-curve proof and the SM
//! rounds (2 opening + 8 PA equations per round) has the form
//! `Σ_i s_i·P_i = O`.  The verifier draws an independent weight ρ_k < 2^128
//! per equation from its own randomness **after** all inputs are fixed and
//! checks the single combination `Σ_k ρ_k·(Σ_i s_ki·P_ki) = O` with one
//! multi-scalar multiplication.  Tom-256 has prime order p > 2^128, so if
//! some equation is false, at most one value of its weight (mod p) makes the
//! combination vanish: a false equation is accepted with probability
//! ≤ 2^-128 per batch.  If every equation holds, the batch always accepts.
//! The G1 side of the transfer is batched the same way in BLS12-381 G1
//! (prime order ℓ > 2^128; D_j and K1 come from subgroup-checked decoders).
//! A verification runs two batches (Tom-256 and G1), so the extra
//! acceptance probability of a false presentation is ≤ 2^-127 per
//! verification.  It is verifier randomness, so it is not multiplied by the
//! prover's random-oracle queries.
//!
//! The non-linear per-round checks stay individual: α ≠ 0, b ∈ {0, 1},
//! W = α·Q′ ≠ O and its affine coordinates, U1 ≠ O (parser), and the
//! transfer range checks.
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::Zero;
use bls12_381::{G1Projective, Scalar as BlsScalar};
use p256::elliptic_curve::Group as _;
use p256::{ProjectivePoint, Scalar};
use rand_core::RngCore;

use crate::oncurve;
use crate::p256x;
use crate::sm::SmResponse;
use crate::tom::{fr_from_biguint, gt, ht, Fr, TomPoint};
use crate::transfer::{bls_from_biguint, Bounds};
use bbs_cd_plugin::par::{self, Parallelism};

/// The ten weights of one SM round (2 opening + 8 PA equations).
pub fn sm_weights<R: RngCore + ?Sized>(rng: &mut R) -> [Fr; 10] {
    std::array::from_fn(|_| weight_fr(rng))
}

/// A 128-bit verifier weight as an Fr element.
fn weight_fr<R: RngCore + ?Sized>(rng: &mut R) -> Fr {
    let mut b = [0u8; 16];
    rng.fill_bytes(&mut b);
    Fr::from(u128::from_le_bytes(b))
}

fn weight_bls<R: RngCore + ?Sized>(rng: &mut R) -> BlsScalar {
    let mut b = [0u8; 16];
    rng.fill_bytes(&mut b);
    let mut le = [0u8; 32];
    le[..16].copy_from_slice(&b);
    Option::<BlsScalar>::from(BlsScalar::from_bytes(&le)).expect("< 2^128 < r")
}

/// Accumulator for one Tom-256 batch: coefficients of the shared bases
/// (GT, HT, C_x, C_y) plus a list of (base, coefficient) pairs.
pub struct TomBatch {
    gt: Fr,
    ht: Fr,
    cx: Fr,
    cy: Fr,
    bases: Vec<TomPoint>,
    scalars: Vec<Fr>,
}

impl TomBatch {
    pub fn with_capacity(n: usize) -> Self {
        TomBatch {
            gt: Fr::zero(),
            ht: Fr::zero(),
            cx: Fr::zero(),
            cy: Fr::zero(),
            bases: Vec::with_capacity(n),
            scalars: Vec::with_capacity(n),
        }
    }

    fn push(&mut self, p: TomPoint, s: Fr) {
        if !s.is_zero() {
            self.bases.push(p);
            self.scalars.push(s);
        }
    }

    /// Transfer, Tom side, one entry: z·GT + s2·HT − c·T − K2 = O.  Returns
    /// false (and adds nothing) if z or c is out of range: the range check is
    /// part of the transfer's soundness and must not be skipped.
    #[allow(clippy::too_many_arguments)]
    pub fn add_transfer<R: RngCore + ?Sized>(
        &mut self,
        rng: &mut R,
        bounds: &Bounds,
        t: &TomPoint,
        k2: &TomPoint,
        c: &num_bigint::BigUint,
        z: &num_bigint::BigUint,
        s2: &Fr,
    ) -> bool {
        if !bounds.in_range(z) || *c >= bounds.c_hi {
            return false;
        }
        let r = weight_fr(rng);
        self.gt += r * fr_from_biguint(z);
        self.ht += r * s2;
        self.push(*t, -(r * fr_from_biguint(c)));
        self.push(*k2, -r);
        true
    }

    /// On-curve proof (report §4.4) for (C_x, C_y) = the shared fold bases.
    ///   1  z0·GT + z1·HT − e·C_x − A1 = O
    ///   2  z2·GT + z3·HT − e·C_y − A2 = O
    ///   3  z0·C_x + z4·HT − e·C2 − A3 = O
    ///   4  z0·C2 + z5·HT − e·C3 − A4 = O
    ///   5  z2·C_y + z6·HT − e·C4 − A5 = O
    ///   6  z7·HT − e·L − A6 = O,  L = C4 − C3 + 3·C_x − b·GT
    pub fn add_oncurve<R: RngCore + ?Sized>(
        &mut self,
        rng: &mut R,
        first: &[TomPoint; oncurve::N_FIRST],
        e: Fr,
        z: &[Fr; oncurve::N_RESP],
    ) {
        let [c2, c3, c4, a1, a2, a3, a4, a5, a6] = *first;
        // equation k (1-based, as listed above) has weight r[k - 1]
        let r: [Fr; 6] = std::array::from_fn(|_| weight_fr(rng));
        let b = oncurve::p256_b();
        // 1
        self.gt += r[0] * z[0];
        self.ht += r[0] * z[1];
        self.cx -= r[0] * e;
        // 2
        self.gt += r[1] * z[2];
        self.ht += r[1] * z[3];
        self.cy -= r[1] * e;
        // 3
        self.cx += r[2] * z[0];
        self.ht += r[2] * z[4];
        // 6 contributes to C_x, C3, C4 and GT
        self.cx -= r[5] * e * Fr::from(3u64);
        self.gt += r[5] * e * b;
        self.ht += r[5] * z[7];
        // 5
        self.cy += r[4] * z[2];
        self.ht += r[4] * z[6];
        // 4
        self.ht += r[3] * z[5];
        // C2: −e·r[2] (eq 3) + z0·r[3] (eq 4)
        self.push(c2, r[3] * z[0] - r[2] * e);
        // C3: −e·r[3] (eq 4) + e·r[5] (eq 6: −e·L contains +e·C3)
        self.push(c3, r[5] * e - r[3] * e);
        // C4: −e·r[4] (eq 5) − e·r[5] (eq 6)
        self.push(c4, -(r[4] * e) - r[5] * e);
        self.push(a1, -r[0]);
        self.push(a2, -r[1]);
        self.push(a3, -r[2]);
        self.push(a4, -r[3]);
        self.push(a5, -r[4]);
        self.push(a6, -r[5]);
    }

    /// One SM round (report §4.1.5): the two opening equations of the opened
    /// commitment pair and the 8 PA equations (pa::pa_verify) with
    /// C = [C_x, C_y, CVx, CVy, CUx, CUy].  Returns false if a non-linear
    /// check fails (then nothing is added).
    pub fn add_sm_round<R: RngCore + ?Sized>(
        &mut self,
        rng: &mut R,
        qp: &ProjectivePoint,
        first: &[TomPoint; 14],
        resp: &SmResponse,
        b: u8,
        e: Fr,
    ) -> bool {
        if resp.alpha == Scalar::ZERO || b > 1 {
            return false;
        }
        let w = *qp * resp.alpha;
        self.add_sm_round_at(rng, &w, first, resp, b, e)
    }

    /// As `add_sm_round`, with W = α·Q′ supplied by the caller (who computes
    /// it, e.g. with a fixed-base table for Q′).  `w` MUST equal
    /// `resp.alpha`·Q′; the opening equations are checked against it.
    /// Crate-internal for that reason.
    pub fn add_sm_round_at<R: RngCore + ?Sized>(
        &mut self,
        rng: &mut R,
        w: &ProjectivePoint,
        first: &[TomPoint; 14],
        resp: &SmResponse,
        b: u8,
        e: Fr,
    ) -> bool {
        let r = sm_weights(rng);
        self.add_sm_round_weighted(&r, w, first, resp, b, e)
    }

    /// As `add_sm_round_at`, with the ten weights drawn beforehand by the
    /// caller (A6: all weights are drawn before the parallel accumulation).
    pub fn add_sm_round_weighted(
        &mut self,
        r: &[Fr; 10],
        w: &ProjectivePoint,
        first: &[TomPoint; 14],
        resp: &SmResponse,
        b: u8,
        e: Fr,
    ) -> bool {
        if resp.alpha == Scalar::ZERO || b > 1 {
            return false;
        }
        let w = *w;
        if bool::from(w.is_identity()) {
            return false;
        }
        let [cux, cuy, cvx, cvy, ct, t1, t2, t3, t4, t5, t6, u1, u2, u3] = *first;
        if u1.is_zero() {
            return false;
        }
        let [zt, zrt, zf, zrf, ze1, ze2, zg, zrg, ze3, v1, v2, v3] = resp.z;
        // coefficients of the round-local bases
        let (mut k_ct, mut k_u1) = (Fr::zero(), Fr::zero());
        let (mut k_cux, mut k_cuy, mut k_cvx, mut k_cvy) = (Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero());
        // derived points, in pa::derived order [F1, P1, P2, F3, P3]:
        // F1 = CVx − C_x, P1 = CVy − C_y, P2 = C_x + CVx + CUx,
        // F3 = C_x − CUx, P3 = C_y + CUy
        let mut k_f1 = Fr::zero();
        let (mut k_p1, mut k_f3, mut k_p2, mut k_p3) = (Fr::zero(), Fr::zero(), Fr::zero(), Fr::zero());
        // opening: x(W)·GT + rr0·HT − C.x = O,  y(W)·GT + rr1·HT − C.y = O
        let (xw, yw) = p256x::coords_fr(&w);
        self.gt += r[8] * xw + r[9] * yw;
        self.ht += r[8] * resp.rr.0 + r[9] * resp.rr.1;
        if b == 0 {
            k_cux -= r[8];
            k_cuy -= r[9];
        } else {
            k_cvx -= r[8];
            k_cvy -= r[9];
        }
        // PA 1: zt·GT + zrt·HT − e·Ct − T1
        self.gt += r[0] * zt;
        self.ht += r[0] * zrt;
        k_ct -= r[0] * e;
        // PA 2: zf·GT + zrf·HT − e·F1 − T2
        self.gt += r[1] * zf;
        self.ht += r[1] * zrf;
        k_f1 -= r[1] * e;
        // PA 3: zt·F1 + ze1·HT − e·P1 − T3
        k_f1 += r[2] * zt;
        self.ht += r[2] * ze1;
        k_p1 -= r[2] * e;
        // PA 4: zt·Ct + ze2·HT − e·P2 − T4
        k_ct += r[3] * zt;
        self.ht += r[3] * ze2;
        k_p2 -= r[3] * e;
        // PA 5: zg·GT + zrg·HT − e·F3 − T5
        self.gt += r[4] * zg;
        self.ht += r[4] * zrg;
        k_f3 -= r[4] * e;
        // PA 6: zg·Ct + ze3·HT − e·P3 − T6
        k_ct += r[5] * zg;
        self.ht += r[5] * ze3;
        k_p3 -= r[5] * e;
        // PA 7: v3·GT − e·U1 − U3
        self.gt += r[6] * v3;
        k_u1 -= r[6] * e;
        // PA 8: v1·F1 + v2·HT − e·U1 − U2
        k_f1 += r[7] * v1;
        self.ht += r[7] * v2;
        k_u1 -= r[7] * e;
        // expand the derived points
        k_cvx += k_f1 + k_p2;
        self.cx += -k_f1 + k_p2 + k_f3;
        k_cvy += k_p1;
        self.cy += -k_p1 + k_p3;
        k_cux += k_p2 - k_f3;
        k_cuy += k_p3;
        self.push(ct, k_ct);
        self.push(u1, k_u1);
        self.push(cux, k_cux);
        self.push(cuy, k_cuy);
        self.push(cvx, k_cvx);
        self.push(cvy, k_cvy);
        self.push(t1, -r[0]);
        self.push(t2, -r[1]);
        self.push(t3, -r[2]);
        self.push(t4, -r[3]);
        self.push(t5, -r[4]);
        self.push(t6, -r[5]);
        self.push(u3, -r[6]);
        self.push(u2, -r[7]);
        true
    }

    /// Move the shared C_x/C_y coefficients onto explicit bases, so that two
    /// accumulators with different shared points can be merged (used by the
    /// experimental hashed-ECDSA mode, whose SM result is not the fold).
    pub fn absorb_shared(&mut self, cx: &TomPoint, cy: &TomPoint) {
        let (a, b) = (self.cx, self.cy);
        self.cx = Fr::zero();
        self.cy = Fr::zero();
        self.push(*cx, a);
        self.push(*cy, b);
    }

    /// Evaluate the combination with one MSM; true iff it is the identity.
    pub fn check(self, cx: &TomPoint, cy: &TomPoint) -> bool {
        self.check_par(cx, cy, Parallelism::Off)
    }

    /// Append another accumulator (coefficients add; bases are concatenated).
    pub fn merge(&mut self, other: TomBatch) {
        self.gt += other.gt;
        self.ht += other.ht;
        self.cx += other.cx;
        self.cy += other.cy;
        self.bases.extend(other.bases);
        self.scalars.extend(other.scalars);
    }

    /// `check` with the normalisation and the MSM split into contiguous
    /// chunks, one per worker, and the partial sums added (A6).  The sum is
    /// the same group element for every chunking.
    pub fn check_par(mut self, cx: &TomPoint, cy: &TomPoint, par: Parallelism) -> bool {
        let (g, h) = (TomPoint::from(gt()), TomPoint::from(ht()));
        let shared = [(g, self.gt), (h, self.ht), (*cx, self.cx), (*cy, self.cy)];
        for (p, s) in shared {
            self.push(p, s);
        }
        if self.bases.is_empty() {
            return true;
        }
        if self.bases.len() != self.scalars.len() {
            return false;
        }
        let ranges = par::chunks(par, self.bases.len());
        let (bases, scalars) = (&self.bases, &self.scalars);
        let partial = par::map(par, ranges, |rg| {
            let affine = TomPoint::normalize_batch(&bases[rg.clone()]);
            TomPoint::msm(&affine, &scalars[rg]).ok()
        });
        let mut acc = TomPoint::zero();
        for p in partial {
            match p {
                Some(x) => acc += x,
                None => return false,
            }
        }
        acc.is_zero()
    }
}

/// G1 side of the transfer, all entries: Σ ρ_i·(z_i·Y0 + s1_i·Y1 − c_i·D_j − K1_i) = O.
pub struct G1Entry<'a> {
    pub d: &'a G1Projective,
    pub k1: &'a G1Projective,
    pub c: &'a num_bigint::BigUint,
    pub z: &'a num_bigint::BigUint,
    pub s1: &'a BlsScalar,
}

pub fn g1_transfer_batch<R: RngCore + ?Sized>(
    rng: &mut R,
    entries: &[G1Entry],
    bounds: &Bounds,
    y0: &G1Projective,
    y1: &G1Projective,
) -> bool {
    let mut cy0 = BlsScalar::zero();
    let mut cy1 = BlsScalar::zero();
    let mut acc = G1Projective::identity();
    // coefficients per distinct D (entries of one limb share D)
    let mut d_coeffs: Vec<(&G1Projective, BlsScalar)> = Vec::new();
    for e in entries {
        if !bounds.in_range(e.z) || *e.c >= bounds.c_hi {
            return false;
        }
        let r = weight_bls(rng);
        cy0 += r * bls_from_biguint(e.z);
        cy1 += r * e.s1;
        let cd = r * bls_from_biguint(e.c);
        match d_coeffs.iter_mut().find(|(d, _)| std::ptr::eq(*d, e.d)) {
            Some((_, k)) => *k += cd,
            None => d_coeffs.push((e.d, cd)),
        }
        acc -= e.k1 * r;
    }
    acc += y0 * cy0 + y1 * cy1;
    for (d, k) in d_coeffs {
        acc -= d * k;
    }
    bool::from(acc.is_identity())
}
