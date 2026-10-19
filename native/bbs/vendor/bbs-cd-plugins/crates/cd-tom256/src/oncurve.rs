//! On-curve proof for the committed device key (decision D5 (b), closes
//! finding F-1 independently of the issuer's on-curve check).
//!
//! Statement: Tom-256 commitments C_x = x·GT + ρx·HT and C_y = y·GT + ρy·HT
//! (the fold of the limb commitments) open to (x, y) with
//!     y² = x³ − 3x + b   (mod p, P-256 curve equation).
//! Tom-256's scalar field is exactly F_p, so the relation is native.
//!
//! Auxiliary commitments C2 = x²·GT + r2·HT, C3 = x³·GT + r3·HT,
//! C4 = y²·GT + r4·HT.  Witness w (order fixed):
//!     (x, ρx, y, ρy, σ1 = r2 − x·ρx, σ2 = r3 − x·r2, σ3 = r4 − y·ρy,
//!      τ = r4 − r3 + 3ρx)
//! Relations (all linear in w given the public points):
//!     C_x = x·GT + ρx·HT           C_y = y·GT + ρy·HT
//!     C2  = x·C_x + σ1·HT          C3  = x·C2 + σ2·HT
//!     C4  = y·C_y + σ3·HT          L   = τ·HT,  L = C4 − C3 + 3·C_x − b·GT
//! Special soundness: two accepting transcripts give w; then C2, C3, C4 open
//! to x², x³, y² and L = (y² − x³ + 3x − b)·GT + τ·HT = τ·HT, so by binding
//! (unknown log_GT HT, open item G-1) y² = x³ − 3x + b.
use rand_core::{CryptoRng, RngCore};

use crate::params::P256_B_HEX;
use crate::tom::{commit, fr_from_biguint, gt_mul, ht_mul, mul, Fr, TomPoint};

pub const N_FIRST: usize = 9; // C2, C3, C4, A1..A6
pub const N_RESP: usize = 8;

pub fn p256_b() -> Fr {
    fr_from_biguint(&num_bigint::BigUint::parse_bytes(P256_B_HEX.as_bytes(), 16).unwrap())
}

fn linear_point(cx: &TomPoint, c3: &TomPoint, c4: &TomPoint) -> TomPoint {
    *c4 - *c3 + *cx * Fr::from(3u64) - gt_mul(&p256_b())
}

/// Secret prover state of the on-curve proof.  Single use (L-3): `respond`
/// consumes it, and it is not `Clone` in normal builds, because two
/// responses give x = (z0 - z0')/(e - e') and y = (z2 - z2')/(e - e').
///
/// ```compile_fail
/// # use cd_tom256::oncurve::oncurve_prepare;
/// # use cd_tom256::tom::{commit, Fr};
/// # use rand_core::OsRng;
/// let (x, y, rx, ry) = (Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64));
/// let (cx, cy) = (commit(x, rx), commit(y, ry));
/// let st = oncurve_prepare(x, y, rx, ry, &cx, &cy, &mut OsRng);
/// let _a = st.respond(Fr::from(5u64));
/// let _b = st.respond(Fr::from(6u64)); // error: use of moved value
/// ```
#[cfg_attr(feature = "insecure-test-controls", derive(Clone))]
pub struct OnCurveState {
    w: [Fr; N_RESP],
    a: [Fr; N_RESP],
    /// C2, C3, C4, A1..A6
    pub first: [TomPoint; N_FIRST],
}

/// Prepare (offline).  (x, y) must be the coordinates of a P-256 point for
/// the proof to verify; nothing is checked here (tests use off-curve inputs).
pub fn oncurve_prepare<R: RngCore + CryptoRng>(
    x: Fr,
    y: Fr,
    rho_x: Fr,
    rho_y: Fr,
    cx: &TomPoint,
    cy: &TomPoint,
    rng: &mut R,
) -> OnCurveState {
    use ark_ff::UniformRand;
    let (r2, r3, r4) = (Fr::rand(rng), Fr::rand(rng), Fr::rand(rng));
    let x2 = x * x;
    let c2 = commit(x2, r2);
    let c3 = commit(x2 * x, r3);
    let c4 = commit(y * y, r4);
    let w = [x, rho_x, y, rho_y, r2 - x * rho_x, r3 - x * r2, r4 - y * rho_y, r4 - r3 + Fr::from(3u64) * rho_x];
    let a: [Fr; N_RESP] = std::array::from_fn(|_| Fr::rand(rng));
    let first = [
        c2,
        c3,
        c4,
        commit(a[0], a[1]),
        commit(a[2], a[3]),
        mul(cx, &a[0]) + ht_mul(&a[4]),
        mul(&c2, &a[0]) + ht_mul(&a[5]),
        mul(cy, &a[2]) + ht_mul(&a[6]),
        ht_mul(&a[7]),
    ];
    OnCurveState { w, a, first }
}

impl OnCurveState {
    /// Consumes the state: one first message, one response.
    pub fn respond(self, e: Fr) -> [Fr; N_RESP] {
        std::array::from_fn(|i| self.a[i] + e * self.w[i])
    }
}

pub fn oncurve_verify(cx: &TomPoint, cy: &TomPoint, first: &[TomPoint; N_FIRST], e: Fr, z: &[Fr; N_RESP]) -> bool {
    let [c2, c3, c4, a1, a2, a3, a4, a5, a6] = *first;
    let l = linear_point(cx, &c3, &c4);
    commit(z[0], z[1]) == a1 + mul(cx, &e)
        && commit(z[2], z[3]) == a2 + mul(cy, &e)
        && mul(cx, &z[0]) + ht_mul(&z[4]) == a3 + mul(&c2, &e)
        && mul(&c2, &z[0]) + ht_mul(&z[5]) == a4 + mul(&c3, &e)
        && mul(cy, &z[2]) + ht_mul(&z[6]) == a5 + mul(&c4, &e)
        && ht_mul(&z[7]) == a6 + mul(&l, &e)
}

/// Bytes of an encoded on-curve proof (first message and responses).
pub const OC_BYTES: usize = N_FIRST * 33 + N_RESP * 32;
