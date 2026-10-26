//! Arithmetic, encodings, transcript and codec.
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField};
use cd_tom256::p256x;
use cd_tom256::params::*;
use cd_tom256::sm::commit_point;
use cd_tom256::tom::{self, Fq, Fr, TomPoint};
use cd_tom256::transfer::fold;
use num_bigint::BigUint;
use p256::elliptic_curve::Field;
use p256::{ProjectivePoint, Scalar};
use rand_core::OsRng;

fn big_hex(h: &str) -> BigUint {
    BigUint::parse_bytes(h.as_bytes(), 16).unwrap()
}

#[test]
fn moduli_distinct_and_tom_order() {
    let p = big_hex(P256_P_HEX);
    let pt = BigUint::parse_bytes(TOM_P_DEC.as_bytes(), 10).unwrap();
    let n = big_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    let r = big_hex(BLS_R_HEX);
    let fr_mod = BigUint::from_bytes_be(&Fr::MODULUS.to_bytes_be());
    let fq_mod = BigUint::from_bytes_be(&Fq::MODULUS.to_bytes_be());
    assert_eq!(fr_mod, p, "Tom group order = P-256 base prime");
    assert_eq!(fq_mod, pt);
    let all = [&p, &pt, &n, &r];
    for i in 0..4 {
        for j in i + 1..4 {
            assert_ne!(all[i], all[j]);
        }
    }
    // GT and HT on the curve, prime order p
    let g = TomPoint::generator();
    let h: TomPoint = tom::ht().into_group();
    assert!(tom::gt().is_on_curve() && tom::ht().is_on_curve());
    assert!(g.mul_bigint(Fr::MODULUS).into_affine().is_zero());
    assert!(h.mul_bigint(Fr::MODULUS).into_affine().is_zero());
    assert_ne!(g, h);
}

#[test]
fn tom_encoding_roundtrip_and_rejections() {
    for _ in 0..32 {
        let x = tom::fr_rand(&mut OsRng);
        let p = tom::commit(x, tom::fr_rand(&mut OsRng));
        let e = tom::encode(&p, false);
        assert_eq!(tom::decode_point(&e, false).unwrap(), p);
    }
    let id = [0u8; 33];
    assert!(tom::decode_point(&id, true).is_ok());
    assert!(tom::decode_point(&id, false).is_err());
    let mut e = tom::encode(&TomPoint::generator(), false);
    e[0] = 4;
    assert!(tom::decode_point(&e, false).is_err(), "prefix");
    // x >= pT
    let mut big = [0xffu8; 33];
    big[0] = 2;
    assert!(tom::decode_point(&big, false).is_err());
    // some x not on the curve (x = 0 or 1 or 2 ... at least one fails)
    let bad = (0u8..20).filter(|&x| {
        let mut b = [0u8; 33];
        b[0] = 2;
        b[32] = x;
        tom::decode_point(&b, false).is_err()
    });
    assert!(bad.count() > 0);
    assert!(tom::decode_point(&[2u8; 32], false).is_err(), "length");
}

#[test]
fn p256_decode_strict_and_limbs() {
    let q = ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng);
    let e = p256x::encode(&q);
    assert_eq!(p256x::decode_point(&e).unwrap(), q);
    let mut u = e;
    u[0] = 4;
    assert!(p256x::decode_point(&u).is_err());
    assert!(p256x::decode_point(&[0u8; 33]).is_err(), "identity");
    let mut big = [0xffu8; 33];
    big[0] = 2;
    assert!(p256x::decode_point(&big).is_err(), "x >= p");
    let (x, y) = p256x::coords(&q);
    for lb in [64u8, 96, 128] {
        let l = p256x::limbs(&q, lb);
        let k = l.len() / 2;
        assert_eq!(k, 256usize.div_ceil(lb as usize));
        let join = |ls: &[u128]| {
            ls.iter().enumerate().fold(BigUint::from(0u8), |acc, (i, v)| acc + (BigUint::from(*v) << (lb as usize * i)))
        };
        assert_eq!(join(&l[..k]), BigUint::from_bytes_be(&x));
        assert_eq!(join(&l[k..]), BigUint::from_bytes_be(&y));
        assert!(l.iter().all(|v| lb == 128 || *v < (1u128 << lb)));
        assert_eq!(p256x::limbs_of_coords(&x, &y, lb), l);
    }
}

#[test]
fn scalar_canonical_and_low_s() {
    let n = hex_n();
    assert!(p256x::scalar_from_canonical(&n).is_err());
    let half = p256x::half_n_be();
    let hs = p256x::scalar_from_canonical(&half).unwrap();
    assert!(!p256x::is_high_s(&hs));
    assert!(p256x::is_high_s(&(hs + Scalar::ONE)));
    // Tom scalar canonical: p rejected
    let p: [u8; 32] = big_hex(P256_P_HEX).to_bytes_be().try_into().unwrap();
    assert!(tom::fr_from_canonical(&p).is_err());
}

fn hex_n() -> [u8; 32] {
    big_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551").to_bytes_be().try_into().unwrap()
}

#[test]
fn fold_matches_point_commitment() {
    let q = ProjectivePoint::GENERATOR * Scalar::random(&mut OsRng);
    for lb in [64u8, 96, 128] {
        let l = p256x::limbs(&q, lb);
        let rho: Vec<Fr> = l.iter().map(|_| tom::fr_rand(&mut OsRng)).collect();
        let t: Vec<TomPoint> = l.iter().zip(&rho).map(|(m, r)| tom::commit(Fr::from(*m), *r)).collect();
        let rq = cd_tom256::transfer::fold_fr(&rho, lb);
        assert_eq!(fold(&t, lb), commit_point(&q, rq));
    }
}

/// GT and HT follow their documented rule (findings G-1/H-3): the curve
/// points with x = 3 and x = 5, each with the smaller y root.
#[test]
fn generators_follow_documented_rule() {
    use ark_ec::short_weierstrass::SWCurveConfig;
    use ark_ff::Field as _;
    use cd_tom256::tom::{TomAffine, TomConfig};
    let derive = |x: u64| -> TomAffine {
        let x = Fq::from(x);
        let rhs = x * x * x + TomConfig::COEFF_A * x + TomConfig::COEFF_B;
        let y = rhs.sqrt().expect("x is on the curve");
        let y = if y.into_bigint() < (-y).into_bigint() { y } else { -y };
        TomAffine::new(x, y)
    };
    assert_eq!(tom::gt(), derive(3));
    assert_eq!(tom::ht(), derive(5));
    let (g, h) = (tom::gt(), tom::ht());
    assert!(g.is_on_curve() && h.is_on_curve() && !g.is_zero() && !h.is_zero());
    assert!(h != g && h != -g);
    // x = 0, 1, 2 are not on the curve, x = 4 is: the rule is stated as is
    for x in [0u64, 1, 2] {
        let x = Fq::from(x);
        assert!((x * x * x + TomConfig::COEFF_A * x + TomConfig::COEFF_B).sqrt().is_none());
    }
    let x4 = Fq::from(4u64);
    assert!((x4 * x4 * x4 + TomConfig::COEFF_A * x4 + TomConfig::COEFF_B).sqrt().is_some());
}
