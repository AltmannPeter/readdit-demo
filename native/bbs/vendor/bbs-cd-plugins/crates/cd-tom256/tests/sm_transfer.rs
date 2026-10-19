//! Tom-256 SM/PA (incl. extraction and finding F-1) and the BLS -> Tom transfer.
use bbs_cd::interface::PrecomputeCommitment;
use bbs_cd::types::{Index, Message, OCTETS, SCALAR};
use bbs_cd::utils::commitment_generators;
use bbs_cd_plugin::issuer::{scalar_from_u128 as limb_scalar, SUITE};
use cd_tom256::config::TransferConfig;
use cd_tom256::oncurve;
use cd_tom256::p256x;
use cd_tom256::pa::pa_prepare_with_slope;
use cd_tom256::sm::{commit_point, sm_prepare_round, sm_verify_round, SmRound};
use cd_tom256::tom::{self, fr_from_be, fr_rand, Fr};
use cd_tom256::transfer::{self, bls_rand, dleq_prepare, dleq_respond, dleq_verify, Bounds};
use num_bigint::BigUint;
use p256::elliptic_curve::Field;
use p256::{ProjectivePoint, Scalar};
use rand_core::{OsRng, RngCore};

struct Rel {
    q: ProjectivePoint,
    c: Scalar,
    qp: ProjectivePoint,
    rq: (Fr, Fr),
    cq: (cd_tom256::tom::TomPoint, cd_tom256::tom::TomPoint),
}

fn relation() -> Rel {
    let d = Scalar::random(&mut OsRng);
    let q = ProjectivePoint::GENERATOR * d;
    let a = Scalar::random(&mut OsRng);
    let c = a.invert().unwrap();
    let qp = q * a;
    let rq = (fr_rand(&mut OsRng), fr_rand(&mut OsRng));
    let cq = commit_point(&q, rq);
    Rel { q, c, qp, rq, cq }
}

#[test]
fn honest_rounds_and_special_soundness_extraction() {
    let r = relation();
    for shared in [true, false] {
        for _ in 0..4 {
            let rd = sm_prepare_round(&r.q, &r.c, &r.qp, r.cq, r.rq, shared, &mut OsRng).unwrap();
            let fm = rd.first_message();
            let e0 = if shared { Fr::from(0u64) } else { fr_rand(&mut OsRng) };
            let e1 = if shared { Fr::from(1u64) } else { fr_rand(&mut OsRng) };
            // two answers from one state: only possible with the test-only Clone (L-3)
            let r0 = rd.clone().respond(0, e0);
            let r1 = rd.respond(1, e1);
            assert!(sm_verify_round(&r.qp, r.cq, &fm, &r0, 0, e0));
            assert!(sm_verify_round(&r.qp, r.cq, &fm, &r1, 1, e1));
            // extractor: alpha0 - alpha1 = c, and c*Q' = Q
            let c = r0.alpha - r1.alpha;
            assert_eq!(c, r.c);
            assert_eq!(r.qp * c, r.q);
        }
    }
}

#[test]
fn tampering_rejected() {
    let r = relation();
    let rd = sm_prepare_round(&r.q, &r.c, &r.qp, r.cq, r.rq, true, &mut OsRng).unwrap();
    let fm = rd.first_message();
    let e = Fr::from(1u64);
    let good = rd.respond(1, e);
    assert!(sm_verify_round(&r.qp, r.cq, &fm, &good, 1, e));
    let mut x = good.clone();
    x.alpha += Scalar::ONE;
    assert!(!sm_verify_round(&r.qp, r.cq, &fm, &x, 1, e));
    let mut x = good.clone();
    x.rr.0 += Fr::from(1u64);
    assert!(!sm_verify_round(&r.qp, r.cq, &fm, &x, 1, e));
    for k in 0..12 {
        let mut x = good.clone();
        x.z[k] += Fr::from(1u64);
        assert!(!sm_verify_round(&r.qp, r.cq, &fm, &x, 1, e), "z[{k}]");
    }
    assert!(!sm_verify_round(&r.qp, r.cq, &fm, &good, 0, e), "wrong bit");
    assert!(!sm_verify_round(&r.qp, r.cq, &fm, &good, 1, Fr::from(0u64)), "wrong e");
    let other = relation();
    assert!(!sm_verify_round(&r.qp, other.cq, &fm, &good, 1, e), "other commitment");
    let mut x = good.clone();
    x.alpha = Scalar::ZERO;
    assert!(!sm_verify_round(&r.qp, r.cq, &fm, &x, 1, e), "alpha = 0");
}

/// F-1: with omega = c/2 (U = -V) the PA constraints do not force the
/// committed result onto the curve; a prover knowing c commits to an
/// OFF-CURVE pair and passes every round.  Closed in the composed protocol
/// by D-1 (issuer-validated key) + the transfer (see presentation tests).
#[test]
fn finding_f1_offcurve_result_accepted_by_standalone_sm() {
    let r = relation();
    let two_inv = Scalar::from(2u64).invert().unwrap();
    let omega = r.c * two_inv;
    let u = r.qp * omega;
    let v = r.qp * (omega - r.c);
    assert_eq!(v, -u);
    let (vx, vy) = p256x::coords_fr(&v);
    let t = fr_rand(&mut OsRng);
    let xq = t * t - vx - vx;
    let yq = vy + t * (xq - vx);
    // off curve: y^2 != x^3 - 3x + b (mod p)
    let b = fr_from_be(
        &BigUint::parse_bytes(b"5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
            .unwrap()
            .to_bytes_be(),
    );
    assert_ne!(yq * yq, xq * xq * xq - Fr::from(3u64) * xq + b);
    let rq = (fr_rand(&mut OsRng), fr_rand(&mut OsRng));
    let cq = (tom::commit(xq, rq.0), tom::commit(yq, rq.1));
    let mut accepted = 0;
    for _ in 0..4 {
        let ru = (fr_rand(&mut OsRng), fr_rand(&mut OsRng));
        let rv = (fr_rand(&mut OsRng), fr_rand(&mut OsRng));
        let cu = commit_point(&u, ru);
        let cv = commit_point(&v, rv);
        let cc = [cq.0, cq.1, cv.0, cv.1, cu.0, cu.1];
        let blinds = [rq.0, rq.1, rv.0, rv.1, ru.0, ru.1];
        let st = pa_prepare_with_slope((xq, yq), (vx, vy), p256x::coords_fr(&u), t, &blinds, &cc, &mut OsRng).unwrap();
        let rd = SmRound::new(omega, omega - r.c, ru, rv, cu, cv, st);
        for b in 0..2u8 {
            for e in [Fr::from(b as u64), fr_rand(&mut OsRng)] {
                accepted += sm_verify_round(&r.qp, cq, &rd.first_message(), &rd.clone().respond(b, e), b, e) as usize;
            }
        }
    }
    assert_eq!(accepted, 4 * 4);
}

#[test]
fn omega_exclusions_and_exceptional_addition() {
    // pa_prepare refuses A + B != T and x(A) == x(B)
    let r = relation();
    let blinds = [Fr::from(1u64); 6];
    let cc = [tom::commit(Fr::from(1u64), Fr::from(1u64)); 6];
    assert!(cd_tom256::pa::pa_prepare(&r.q, &r.q, &(r.q + r.q), &blinds, &cc, &mut OsRng).is_err(), "doubling");
    assert!(cd_tom256::pa::pa_prepare(&r.q, &r.qp, &r.q, &blinds, &cc, &mut OsRng).is_err(), "A+B != T");
}

fn y0y1() -> (bls12_381::G1Projective, bls12_381::G1Projective) {
    commitment_generators(SUITE, &SUITE.api_id()).unwrap()
}

#[test]
fn etsi_commitment_roles_match_transfer() {
    // E-2: ETSI C = Y0*m + Y1*s
    let (y0, y1) = y0y1();
    let m = 0x0123_4567_89ab_cdef_0011_2233_4455_6677u128;
    let types = vec![SCALAR, OCTETS];
    let (d, rands) =
        PrecomputeCommitment(SUITE, &[Message::Scalar(limb_scalar(m))], &[Index::Integer(0)], &types, None).unwrap();
    let s = rands[0].to_scalar().unwrap();
    assert_eq!(d[0], y0 * transfer::bls_from_biguint(&BigUint::from(m)) + y1 * s);
}

/// Configurations under test: (limb bits, transfer config).
fn configs() -> Vec<(u8, TransferConfig)> {
    vec![(96, TransferConfig::DEFAULT), (128, TransferConfig::L128_R2), (64, TransferConfig::DEFAULT)]
}

fn rand_below_bits(bits: u32) -> BigUint {
    let mut b = vec![0u8; (bits as usize).div_ceil(8)];
    OsRng.fill_bytes(&mut b);
    BigUint::from_bytes_be(&b) % (BigUint::from(1u8) << bits)
}

fn rand_limb(bits: u8) -> u128 {
    let v = rand_below_bits(bits as u32).to_bytes_le();
    let mut a = [0u8; 16];
    a[..v.len()].copy_from_slice(&v);
    u128::from_le_bytes(a)
}

#[test]
fn transfer_configs_validate() {
    for (lb, cfg) in configs() {
        cfg.validate(lb).unwrap();
    }
    // 128-bit limbs cannot use b_c = 128, b_f = 16 (272 > 254)
    assert!(TransferConfig::DEFAULT.validate(128).is_err());
    // one repetition at b_c = 112 is below the 128-bit floor
    assert!(TransferConfig { reps: 1, b_c: 112, b_f: 8 }.validate(128).is_err());
    assert!(TransferConfig { reps: 1, b_c: 120, b_f: 8 }.validate(96).is_err());
    assert!(TransferConfig { reps: 1, b_c: 128, b_f: 4 }.validate(96).is_err(), "b_f too small");
    assert!(TransferConfig { reps: 1, b_c: 128, b_f: 16 }.validate(80).is_err(), "unsupported limb size");
}

#[test]
fn transfer_honest_and_extraction() {
    let (y0, y1) = y0y1();
    for (lb, cfg) in configs() {
        let bounds = Bounds::new(lb, &cfg);
        for _ in 0..6 {
            let m = rand_limb(lb);
            let s = bls_rand(&mut OsRng);
            let rho = fr_rand(&mut OsRng);
            let d = y0 * transfer::bls_from_biguint(&BigUint::from(m)) + y1 * s;
            let t = tom::commit(Fr::from(m), rho);
            let p = dleq_prepare(&y0, &y1, &bounds, &mut OsRng);
            let c1 = rand_below_bits(cfg.b_c as u32);
            let c2 = rand_below_bits(cfg.b_c as u32);
            let (Some(a), Some(b)) =
                (dleq_respond(&p, m, &s, &rho, &c1, &bounds), dleq_respond(&p, m, &s, &rho, &c2, &bounds))
            else {
                continue; // abort (rare)
            };
            assert!(dleq_verify(&d, &t, &p.big_k1, &p.big_k2, &c1, &a.0, &a.1, &a.2, &y0, &y1, &bounds));
            assert!(dleq_verify(&d, &t, &p.big_k1, &p.big_k2, &c2, &b.0, &b.1, &b.2, &y0, &y1, &bounds));
            assert!(a.0.bits() as usize <= bounds.z_bytes * 8);
            if c1 != c2 {
                use num_bigint::BigInt;
                let num = BigInt::from(a.0.clone()) - BigInt::from(b.0.clone());
                let den = BigInt::from(c1.clone()) - BigInt::from(c2.clone());
                assert_eq!(&num % &den, BigInt::from(0));
                assert_eq!(num / den, BigInt::from(m));
            }
        }
    }
}

#[test]
fn transfer_rejects_bad_ranges_and_mismatch() {
    let (y0, y1) = y0y1();
    for (lb, cfg) in configs() {
        let bounds = Bounds::new(lb, &cfg);
        let m = 12345u128;
        let s = bls_rand(&mut OsRng);
        let rho = fr_rand(&mut OsRng);
        let d = y0 * transfer::bls_from_biguint(&BigUint::from(m)) + y1 * s;
        let t = tom::commit(Fr::from(m), rho);
        let c = BigUint::from(777u32);
        let (p, (z, s1, s2)) = loop {
            let p = dleq_prepare(&y0, &y1, &bounds, &mut OsRng);
            if let Some(r) = dleq_respond(&p, m, &s, &rho, &c, &bounds) {
                break (p, r);
            }
        };
        assert!(dleq_verify(&d, &t, &p.big_k1, &p.big_k2, &c, &z, &s1, &s2, &y0, &y1, &bounds));
        let t_other = tom::commit(Fr::from(m + 1), rho);
        assert!(!dleq_verify(&d, &t_other, &p.big_k1, &p.big_k2, &c, &z, &s1, &s2, &y0, &y1, &bounds));
        assert!(!dleq_verify(&d, &t, &p.big_k1, &p.big_k2, &bounds.c_hi, &z, &s1, &s2, &y0, &y1, &bounds));
        assert!(!dleq_verify(&d, &t, &p.big_k1, &p.big_k2, &c, &bounds.z_hi, &s1, &s2, &y0, &y1, &bounds));
        let low = &bounds.z_lo - 1u32;
        assert!(!dleq_verify(&d, &t, &p.big_k1, &p.big_k2, &c, &low, &s1, &s2, &y0, &y1, &bounds));
        // roles swapped (Blind-BBS convention) must fail
        let d_swapped = y1 * transfer::bls_from_biguint(&BigUint::from(m)) + y0 * s;
        assert!(!dleq_verify(&d_swapped, &t, &p.big_k1, &p.big_k2, &c, &z, &s1, &s2, &y0, &y1, &bounds));
    }
}

#[test]
fn transfer_abort_rate() {
    // b_f = 8 (128-bit limbs, HPI parameters): abort probability exactly 2^-8
    let (y0, y1) = y0y1();
    let bounds = Bounds::new(128, &TransferConfig::L128_R2);
    let mut aborts = 0;
    let n = 1500;
    let s = bls_rand(&mut OsRng);
    let rho = fr_rand(&mut OsRng);
    for _ in 0..n {
        let p = dleq_prepare(&y0, &y1, &bounds, &mut OsRng);
        let c = rand_below_bits(112);
        aborts += dleq_respond(&p, u128::MAX, &s, &rho, &c, &bounds).is_none() as usize;
    }
    assert!(aborts < n * 3 / 100, "abort rate {aborts}/{n}");
    // b_f = 16 (default): abort probability 2^-16, essentially never
    let bounds = Bounds::new(96, &TransferConfig::DEFAULT);
    let mut aborts = 0;
    for _ in 0..300 {
        let p = dleq_prepare(&y0, &y1, &bounds, &mut OsRng);
        let c = rand_below_bits(128);
        aborts += dleq_respond(&p, (1u128 << 96) - 1, &s, &rho, &c, &bounds).is_none() as usize;
    }
    assert!(aborts <= 1, "abort rate {aborts}/300");
}

// ------------------------------------------------------------ on-curve proof
fn p256_b_ok(x: Fr, y: Fr) -> bool {
    y * y == x * x * x - Fr::from(3u64) * x + oncurve::p256_b()
}

#[test]
fn oncurve_honest_extraction_and_offcurve_rejected() {
    use cd_tom256::oncurve::{oncurve_prepare, oncurve_verify};
    let q = ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng);
    let (x, y) = p256x::coords_fr(&q);
    assert!(p256_b_ok(x, y));
    let (rx, ry) = (fr_rand(&mut OsRng), fr_rand(&mut OsRng));
    let (cx, cy) = (tom::commit(x, rx), tom::commit(y, ry));
    let st = oncurve_prepare(x, y, rx, ry, &cx, &cy, &mut OsRng);
    let (e1, e2) = (fr_rand(&mut OsRng), fr_rand(&mut OsRng));
    let first = st.first;
    let (z1, z2) = (st.clone().respond(e1), st.respond(e2));
    assert!(oncurve_verify(&cx, &cy, &first, e1, &z1));
    assert!(oncurve_verify(&cx, &cy, &first, e2, &z2));
    // special soundness: x and y extracted from two transcripts
    use ark_ff::Field;
    let inv = (e1 - e2).inverse().unwrap();
    assert_eq!((z1[0] - z2[0]) * inv, x);
    assert_eq!((z1[2] - z2[2]) * inv, y);
    // tampering
    for k in 0..8 {
        let mut z = z1;
        z[k] += Fr::from(1u64);
        assert!(!oncurve_verify(&cx, &cy, &first, e1, &z), "z[{k}]");
    }
    assert!(!oncurve_verify(&cy, &cx, &first, e1, &z1), "swapped coordinates");
    // the F-1 off-curve pair cannot pass: honest algorithm on (xq, yq) fails
    let r = relation();
    let omega = r.c * Scalar::from(2u64).invert().unwrap();
    let v = r.qp * (omega - r.c);
    let (vx, vy) = p256x::coords_fr(&v);
    let t = fr_rand(&mut OsRng);
    let xq = t * t - vx - vx;
    let yq = vy + t * (xq - vx);
    assert!(!p256_b_ok(xq, yq));
    let (cxq, cyq) = (tom::commit(xq, rx), tom::commit(yq, ry));
    let st = oncurve_prepare(xq, yq, rx, ry, &cxq, &cyq, &mut OsRng);
    let e = fr_rand(&mut OsRng);
    let first = st.first;
    assert!(!oncurve_verify(&cxq, &cyq, &first, e, &st.respond(e)));
}
