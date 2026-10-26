//! Unit tests of the A5 batch accumulator (`cd_tom256::batch::TomBatch`)
//! against the individual checks, and of the arkworks MSM it relies on.
//! Contributed by the adversarial review of the A5 change: besides single
//! perturbations, they include **compensating pairs** (+1 on one response,
//! −1 on another with the same base), which only an independent weight per
//! equation detects.
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{BigInteger, One, PrimeField, UniformRand, Zero};
use cd_tom256::batch::TomBatch;
use cd_tom256::oncurve;
use cd_tom256::p256x;
use cd_tom256::sm::{commit_point, sm_prepare_round, sm_verify_round};
use cd_tom256::tom::{fr_from_biguint, gt, ht, Fr, TomPoint};
use num_bigint::BigUint;
use p256::elliptic_curve::Field as _;
use p256::{ProjectivePoint, Scalar};
use rand_core::OsRng;

fn naive(b: &[TomPoint], s: &[Fr]) -> TomPoint {
    b.iter().zip(s).fold(TomPoint::zero(), |a, (p, k)| a + *p * k)
}

fn edge_scalars() -> Vec<Fr> {
    let p = BigUint::from_bytes_be(&Fr::MODULUS.to_bytes_be());
    let one = BigUint::from(1u8);
    let mut v = vec![Fr::zero(), Fr::one(), -Fr::one(), -Fr::from(2u64), Fr::from(2u64)];
    for e in [127u32, 128, 224, 254, 255] {
        v.push(fr_from_biguint(&(&one << e)));
        v.push(fr_from_biguint(&((&one << e) - &one)));
    }
    v.push(fr_from_biguint(&((&p - &one) >> 1)));
    v.push(fr_from_biguint(&((&p + &one) >> 1)));
    v.push(fr_from_biguint(&(&p - (&one << 224u32))));
    v.push(fr_from_biguint(&(&p - (&one << 96u32))));
    v
}

#[test]
fn msm_matches_naive() {
    let mut rng = OsRng;
    let edges = edge_scalars();
    for &n in &[0usize, 1, 2, 3, 5, 17, 31, 32, 33, 64, 100, 500, 1900, 2100] {
        for trial in 0..4 {
            let mut b: Vec<TomPoint> = (0..n).map(|_| TomPoint::rand(&mut rng)).collect();
            let mut s: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            for i in 0..n {
                match (i + trial) % 5 {
                    0 => s[i] = edges[(i / 5) % edges.len()],
                    1 if trial >= 2 => b[i] = TomPoint::zero(),
                    2 if trial == 3 => b[i] = b[0],
                    _ => {}
                }
            }
            let a = TomPoint::normalize_batch(&b);
            let m = TomPoint::msm(&a, &s).unwrap();
            assert_eq!(m, naive(&b, &s), "n={n} trial={trial}");
        }
        // all-edge scalars against generator, and all-identity bases
        if n > 0 {
            let b: Vec<TomPoint> = (0..n)
                .map(|i| if i % 3 == 0 { TomPoint::zero() } else { TomPoint::from(gt()) * Fr::from(i as u64 + 1) })
                .collect();
            let s: Vec<Fr> = (0..n).map(|i| edges[i % edges.len()]).collect();
            let a = TomPoint::normalize_batch(&b);
            assert_eq!(TomPoint::msm(&a, &s).unwrap(), naive(&b, &s));
            let z = vec![TomPoint::zero(); n];
            let a = TomPoint::normalize_batch(&z);
            assert!(TomPoint::msm(&a, &s).unwrap().is_zero());
        }
    }
    // cancellation: P*k + P*(-k) == 0
    for k in edge_scalars() {
        let p = TomPoint::rand(&mut rng);
        let a = TomPoint::normalize_batch(&[p, p]);
        assert!(TomPoint::msm(&a, &[k, -k]).unwrap().is_zero());
    }
}

struct Round {
    qp: ProjectivePoint,
    cq: (TomPoint, TomPoint),
    first: [TomPoint; 14],
    resp: cd_tom256::sm::SmResponse,
    b: u8,
    e: Fr,
}

fn mk_round(b: u8, e: Fr) -> Round {
    let mut rng = OsRng;
    let c = Scalar::random(&mut rng);
    let qp = ProjectivePoint::GENERATOR * Scalar::random(&mut rng);
    let q = qp * c;
    let rq = (Fr::rand(&mut rng), Fr::rand(&mut rng));
    let cq = commit_point(&q, rq);
    let rnd = sm_prepare_round(&q, &c, &qp, cq, rq, false, &mut rng).unwrap();
    let first = rnd.first_message();
    let resp = rnd.respond(b, e);
    Round { qp, cq, first, resp, b, e }
}

fn batch_ok(r: &Round) -> bool {
    let mut rng = OsRng;
    let mut tb = TomBatch::with_capacity(32);
    if !tb.add_sm_round(&mut rng, &r.qp, &r.first, &r.resp, r.b, r.e) {
        return false;
    }
    tb.check(&r.cq.0, &r.cq.1)
}

fn ind_ok(r: &Round) -> bool {
    sm_verify_round(&r.qp, r.cq, &r.first, &r.resp, r.b, r.e)
}

#[test]
fn sm_round_batch_equals_individual_under_single_perturbations() {
    let mut rng = OsRng;
    for (b, e) in [(0u8, Fr::zero()), (1, Fr::one()), (0, Fr::rand(&mut rng)), (1, Fr::rand(&mut rng))] {
        let r = mk_round(b, e);
        assert!(ind_ok(&r) && batch_ok(&r), "honest b={b}");
        // each of the 14 first-message points (cq is separate)
        for i in 0..14 {
            let mut x = mk_round(b, e);
            if i == 11 {
                x.first[i] += TomPoint::from(gt());
            } else {
                x.first[i] += TomPoint::from(ht());
            }
            let (a, bb) = (ind_ok(&x), batch_ok(&x));
            assert_eq!(a, bb, "point {i} b={b}");
            // (with e = 0 some points are unconstrained in that round; both
            // paths then accept identically, which is the profile's design)
        }
        // cq
        for j in 0..2 {
            let mut x = mk_round(b, e);
            if j == 0 {
                x.cq.0 += TomPoint::from(gt());
            } else {
                x.cq.1 += TomPoint::from(gt());
            }
            assert_eq!(ind_ok(&x), batch_ok(&x), "cq {j}");
        }
        // each response field
        for k in 0..14 {
            let mut x = mk_round(b, e);
            if k < 2 {
                if k == 0 {
                    x.resp.rr.0 += Fr::one()
                } else {
                    x.resp.rr.1 += Fr::one()
                }
            } else {
                x.resp.z[k - 2] += Fr::one();
            }
            assert_eq!(ind_ok(&x), batch_ok(&x), "resp {k} b={b}");
            assert!(!ind_ok(&x));
        }
        // compensating pairs on HT: equal weight would cancel
        let ht_only = [0usize, 1, 3, 5, 6, 7, 9, 10, 12];
        let mut pairs = vec![];
        for a in 0..ht_only.len() {
            for c in a + 1..ht_only.len() {
                pairs.push((ht_only[a], ht_only[c]));
            }
        }
        for (u, v) in pairs {
            let mut x = mk_round(b, e);
            // indices into the 14-field response vector [rr0, rr1, z0..z11]
            let mut f: Vec<Fr> = vec![x.resp.rr.0, x.resp.rr.1];
            f.extend_from_slice(&x.resp.z);
            f[u] += Fr::one();
            f[v] -= Fr::one();
            x.resp.rr = (f[0], f[1]);
            x.resp.z.copy_from_slice(&f[2..]);
            assert!(!batch_ok(&x), "pair {u},{v}");
        }
        // opening with b swapped: shift both CU and CV
        let mut x = mk_round(b, e);
        x.b = 1 - b;
        assert_eq!(ind_ok(&x), batch_ok(&x));
    }
}

#[test]
fn oncurve_batch_equals_individual() {
    let mut rng = OsRng;
    let p = ProjectivePoint::GENERATOR * Scalar::random(&mut rng);
    let (x, y) = p256x::coords_fr(&p);
    let (rx, ry) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
    let (cx, cy) = (cd_tom256::tom::commit(x, rx), cd_tom256::tom::commit(y, ry));
    let st = oncurve::oncurve_prepare(x, y, rx, ry, &cx, &cy, &mut rng);
    let first = st.first;
    let e = Fr::rand(&mut rng);
    let z = st.respond(e);
    let run = |f: &[TomPoint; 9], z: &[Fr; 8], cx: &TomPoint, cy: &TomPoint| {
        let mut tb = TomBatch::with_capacity(16);
        tb.add_oncurve(&mut OsRng, f, e, z);
        (oncurve::oncurve_verify(cx, cy, f, e, z), tb.check(cx, cy))
    };
    assert_eq!(run(&first, &z, &cx, &cy), (true, true));
    for i in 0..9 {
        let mut f = first;
        f[i] += TomPoint::from(ht());
        assert_eq!(run(&f, &z, &cx, &cy), (false, false), "point {i}");
    }
    for k in 0..8 {
        let mut zz = z;
        zz[k] += Fr::one();
        assert_eq!(run(&first, &zz, &cx, &cy), (false, false), "z {k}");
    }
    for (u, v) in [(1, 4), (4, 5), (5, 6), (6, 7), (3, 7)] {
        let mut zz = z;
        zz[u] += Fr::one();
        zz[v] -= Fr::one();
        assert_eq!(run(&first, &zz, &cx, &cy), (false, false), "pair {u},{v}");
    }
    // off-curve witness: individual and batch must both reject
    let st = oncurve::oncurve_prepare(x, y + Fr::one(), rx, ry, &cx, &(cy + TomPoint::from(gt())), &mut rng);
    let f = st.first;
    let z = st.respond(e);
    let cy2 = cy + TomPoint::from(gt());
    assert_eq!(run(&f, &z, &cx, &cy2), (false, false));
}
