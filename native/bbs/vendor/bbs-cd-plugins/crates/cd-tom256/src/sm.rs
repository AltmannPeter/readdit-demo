//! Tom-256 committed scalar multiplication with public base: Q = c * Q'.
//! Per round: omega <- Z_n \ {0, c, 2c}; U = omega*Q', V = (omega - c)*Q';
//! commit coordinates of U, V; PA proof of Q + V = U.  Bit 0 opens U (alpha =
//! omega), bit 1 opens V (alpha = omega - c).
//!
//! Profiles: `draft00-shared-bit` (PA challenge = bit, both branches
//! precomputed) and `separate-pa` (PA challenge in Z_p per round).
use ark_ff::{UniformRand, Zero};
use p256::{elliptic_curve::Field as _, ProjectivePoint, Scalar};
use rand_core::{CryptoRng, RngCore};

use crate::p256x;
use crate::pa::{pa_prepare_with_slope, pa_verify, PaState};
use crate::tom::{commit, Fr, TomPoint};
use bbs_cd_plugin::error::{Error, Result};
use bbs_cd_plugin::par::{self, Parallelism};

pub fn commit_point(p: &ProjectivePoint, blinds: (Fr, Fr)) -> (TomPoint, TomPoint) {
    let (x, y) = p256x::coords_fr(p);
    (commit(x, blinds.0), commit(y, blinds.1))
}

#[derive(Clone)]
pub struct SmResponse {
    pub alpha: Scalar,
    pub rr: (Fr, Fr),
    pub z: [Fr; 12],
}

/// Secret prover state of one SM round.  Single use (L-3): `respond`
/// consumes it, and it is not `Clone` in normal builds, because answering
/// both bits reveals c = alpha0 - alpha1.
#[cfg_attr(feature = "insecure-test-controls", derive(Clone))]
pub struct SmRound {
    pub(crate) omega: Scalar,
    pub(crate) alpha1: Scalar,
    pub(crate) ru: (Fr, Fr),
    pub(crate) rv: (Fr, Fr),
    pub cu: (TomPoint, TomPoint),
    pub cv: (TomPoint, TomPoint),
    pub(crate) pa: PaState,
    z0: Option<[Fr; 12]>,
    z1: Option<[Fr; 12]>,
}

impl SmRound {
    pub fn new(
        omega: Scalar,
        alpha1: Scalar,
        ru: (Fr, Fr),
        rv: (Fr, Fr),
        cu: (TomPoint, TomPoint),
        cv: (TomPoint, TomPoint),
        pa: PaState,
    ) -> Self {
        SmRound { omega, alpha1, ru, rv, cu, cv, pa, z0: None, z1: None }
    }

    /// (CUx, CUy, CVx, CVy, Ct, T1..T6, U1, U2, U3)
    pub fn first_message(&self) -> [TomPoint; 14] {
        let mut out = [TomPoint::zero(); 14];
        out[0] = self.cu.0;
        out[1] = self.cu.1;
        out[2] = self.cv.0;
        out[3] = self.cv.1;
        out[4..].copy_from_slice(&self.pa.ann);
        out
    }

    /// Consumes the round: one first message, one response.
    pub fn respond(self, b: u8, e: Fr) -> SmResponse {
        let (alpha, rr) = if b == 0 { (self.omega, self.ru) } else { (self.alpha1, self.rv) };
        let pre = if b == 0 { &self.z0 } else { &self.z1 };
        let z = match pre {
            Some(z) if e == Fr::from(b as u64) => *z,
            _ => self.pa.respond(e),
        };
        SmResponse { alpha, rr, z }
    }
}

pub fn sm_prepare_round<R: RngCore + CryptoRng>(
    q: &ProjectivePoint,
    c: &Scalar,
    qp: &ProjectivePoint,
    cq: (TomPoint, TomPoint),
    rq: (Fr, Fr),
    shared_bit: bool,
    rng: &mut R,
) -> Result<SmRound> {
    let mut v = sm_prepare_rounds(q, c, qp, cq, rq, shared_bit, 1, rng)?;
    Ok(v.pop().expect("one round"))
}

/// Prepare `n` SM rounds for the same (Q, c, Q′) (A3/A6/A7).
///
/// - U_i = ω_i·Q′ through a per-slot fixed-base table for Q′, and
///   V_i = (ω_i − c)·Q′ computed as U_i − Q (Q = c·Q′), which is the same point.
/// - The coordinates of Q are computed once; those of U_i and V_i once each.
/// - The PA slope denominators x(V_i) − x(Q) are inverted in one batch.
/// - Each round draws its randomness from its own ChaCha20 stream, seeded
///   sequentially from `rng` (`par::child_rngs`), so the rounds can run on
///   several threads (A6) and the output does not depend on `par`.
///
/// ω_i is uniform on Z_n \ {0, c, 2c}.  These exclusions rule out every
/// exceptional case: U = O ⇔ ω = 0, V = O ⇔ ω = c, and
/// x(V) = x(Q) ⇔ V = ±Q ⇔ ω ∈ {2c, 0}.  The checks below are kept anyway.
#[allow(clippy::too_many_arguments)]
pub fn sm_prepare_rounds<R: RngCore + CryptoRng>(
    q: &ProjectivePoint,
    c: &Scalar,
    qp: &ProjectivePoint,
    cq: (TomPoint, TomPoint),
    rq: (Fr, Fr),
    shared_bit: bool,
    n: usize,
    rng: &mut R,
) -> Result<Vec<SmRound>> {
    sm_prepare_rounds_with(q, c, qp, cq, rq, shared_bit, n, Parallelism::Off, rng)
}

/// `sm_prepare_rounds` with a parallelism setting (A6); same output for every setting.
#[allow(clippy::too_many_arguments)]
pub fn sm_prepare_rounds_with<R: RngCore + CryptoRng>(
    q: &ProjectivePoint,
    c: &Scalar,
    qp: &ProjectivePoint,
    cq: (TomPoint, TomPoint),
    rq: (Fr, Fr),
    shared_bit: bool,
    n: usize,
    par: Parallelism,
    rng: &mut R,
) -> Result<Vec<SmRound>> {
    use p256::elliptic_curve::Group;
    // A table pays off from a handful of multiplications on (960 additions
    // to build, 64 per multiplication instead of about 320).
    let table = (n >= 8).then(|| crate::comb::P256Comb::new(*qp, 4));
    let mul_qp = |s: &Scalar| match &table {
        Some(t) => t.mul(s),
        None => *qp * s,
    };
    // V = U − Q below relies on Q = c·Q′; refuse inconsistent inputs early.
    if bool::from(q.is_identity()) || mul_qp(c) != *q {
        return Err(Error::Prover("SM: inputs must satisfy Q = c*Q' with Q != O".into()));
    }
    let (qx, qy) = p256x::coords_fr(q);
    let c = *c;
    // phase 1 (parallel): ω, U, V, coordinates, slope denominator
    let phase1 = par::map(par, par::child_rngs(rng, n), |mut r| -> Result<_> {
        let omega = loop {
            let w = Scalar::random(&mut r);
            if w != Scalar::ZERO && w != c && w != c.double() {
                break w;
            }
        };
        let u = mul_qp(&omega);
        let v = u - *q;
        if bool::from(u.is_identity()) || bool::from(v.is_identity()) {
            return Err(Error::Prover("SM: identity point (excluded omega)".into()));
        }
        let (ux, uy) = p256x::coords_fr(&u);
        let (vx, vy) = p256x::coords_fr(&v);
        let f = vx - qx;
        if f.is_zero() {
            return Err(Error::Prover("SM: x(V) == x(Q), exceptional addition".into()));
        }
        Ok((r, omega, (ux, uy), (vx, vy), f))
    })
    .into_iter()
    .collect::<Result<Vec<_>>>()?;
    // one batch inversion of the slope denominators (sequential, cheap)
    let mut finv: Vec<Fr> = phase1.iter().map(|x| x.4).collect();
    ark_ff::batch_inversion(&mut finv);
    // phase 2 (parallel): commitments and the PA first message
    par::map(par, phase1.into_iter().zip(finv).collect(), |((mut r, omega, (ux, uy), (vx, vy), _), fi)| {
        let alpha1 = omega - c;
        let ru = (Fr::rand(&mut r), Fr::rand(&mut r));
        let rv = (Fr::rand(&mut r), Fr::rand(&mut r));
        let cu = (commit(ux, ru.0), commit(uy, ru.1));
        let cv = (commit(vx, rv.0), commit(vy, rv.1));
        let cc = [cq.0, cq.1, cv.0, cv.1, cu.0, cu.1];
        let blinds = [rq.0, rq.1, rv.0, rv.1, ru.0, ru.1];
        let slope = (vy - qy) * fi;
        let st = pa_prepare_with_slope((qx, qy), (vx, vy), (ux, uy), slope, &blinds, &cc, &mut r)?;
        let mut rnd = SmRound::new(omega, alpha1, ru, rv, cu, cv, st);
        if shared_bit {
            rnd.z0 = Some(rnd.pa.respond(Fr::from(0u64)));
            rnd.z1 = Some(rnd.pa.respond(Fr::from(1u64)));
        }
        Ok(rnd)
    })
    .into_iter()
    .collect()
}

pub fn sm_verify_round(
    qp: &ProjectivePoint,
    cq: (TomPoint, TomPoint),
    first: &[TomPoint; 14],
    resp: &SmResponse,
    b: u8,
    e: Fr,
) -> bool {
    use p256::elliptic_curve::Group;
    if resp.alpha == Scalar::ZERO || b > 1 {
        return false;
    }
    let w = *qp * resp.alpha;
    if bool::from(w.is_identity()) {
        return false;
    }
    let opened = commit_point(&w, resp.rr);
    let (cu, cv) = ((first[0], first[1]), (first[2], first[3]));
    if opened != if b == 0 { cu } else { cv } {
        return false;
    }
    let c = [cq.0, cq.1, cv.0, cv.1, cu.0, cu.1];
    let ann: [TomPoint; 10] = first[4..].try_into().unwrap();
    pa_verify(&c, &ann, e, &resp.z)
}

// --------------------------------------------------------------- encodings
/// Bytes of one SM first message (14 compressed Tom-256 points).
pub const SM_FIRST_BYTES: usize = 14 * 33;
/// Bytes of one SM round: first message, α (32), two blinds (64), 12 PA responses.
pub const SM_ROUND_BYTES: usize = SM_FIRST_BYTES + 32 + 2 * 32 + 12 * 32;
/// Index of U1 inside an SM first message (must be non-identity).
pub const U1_INDEX: usize = 4 + 7;

/// Encode all SM first messages with one shared field inversion.
pub fn encode_sm_first(rounds: &[SmRound]) -> Vec<u8> {
    let pts: Vec<TomPoint> = rounds.iter().flat_map(|rd| rd.first_message()).collect();
    let enc = crate::tom::encode_batch(&pts, |i| i % 14 != U1_INDEX);
    let mut out = Vec::with_capacity(rounds.len() * SM_FIRST_BYTES);
    for e in enc {
        out.extend_from_slice(&e);
    }
    out
}

/// Decode `rounds` SM first messages (U1 must be non-identity), optionally
/// on several workers.  On malformed input the error of the first malformed
/// round is returned.
pub fn decode_sm_points(ann: &[u8], rounds: usize, par: Parallelism) -> Result<Vec<[TomPoint; 14]>> {
    if ann.len() != rounds * SM_FIRST_BYTES {
        return bbs_cd_plugin::error::decode("SM section length");
    }
    par::map(par, ann.chunks(SM_FIRST_BYTES).collect(), |fb| {
        let mut out = [TomPoint::default(); 14];
        for i in 0..14 {
            out[i] = crate::tom::decode_point(&fb[i * 33..(i + 1) * 33], i != U1_INDEX)?;
        }
        Ok(out)
    })
    .into_iter()
    .collect()
}
