//! A3: every fixed-base table multiplication equals the generic one,
//! including edge scalars (0, 1, −1, group order − 1, powers of two,
//! all-ones digits).
use ark_ff::{BigInteger, One, PrimeField, UniformRand, Zero};
use cd_tom256::comb::{gt_comb, ht_comb, y_combs, G1Comb, P256Comb, TomComb};
use cd_tom256::tom::{fr_from_biguint, gt, ht, Fr, TomPoint};
use num_bigint::BigUint;
use p256::elliptic_curve::{Field, PrimeField as _};
use rand_core::OsRng;

fn fr_edges() -> Vec<Fr> {
    let p = BigUint::from_bytes_be(&Fr::MODULUS.to_bytes_be());
    let one = BigUint::from(1u8);
    let mut v = vec![Fr::zero(), Fr::one(), -Fr::one(), Fr::from(255u64), Fr::from(256u64), Fr::from(0xffffu64)];
    for e in [4u32, 7, 8, 63, 64, 127, 128, 224, 248, 252, 255] {
        v.push(fr_from_biguint(&(&one << e)));
        v.push(fr_from_biguint(&((&one << e) - &one)));
    }
    v.push(fr_from_biguint(&(&p - &one)));
    v.push(fr_from_biguint(&((&p - &one) >> 1)));
    for _ in 0..64 {
        v.push(Fr::rand(&mut OsRng));
    }
    v
}

#[test]
fn tom_tables_match_generic_multiplication() {
    let g = TomPoint::from(gt());
    let h = TomPoint::from(ht());
    let r = TomPoint::rand(&mut OsRng);
    let (c4, c8) = (TomComb::new(r, 4), TomComb::new(r, 8));
    for s in fr_edges() {
        assert_eq!(gt_comb().mul(&s), g * s);
        assert_eq!(ht_comb().mul(&s), h * s);
        assert_eq!(c4.mul(&s), r * s);
        assert_eq!(c8.mul(&s), r * s);
    }
    // commit uses the tables
    let (v, b) = (Fr::rand(&mut OsRng), Fr::rand(&mut OsRng));
    assert_eq!(cd_tom256::tom::commit(v, b), g * v + h * b);
}

#[test]
fn p256_table_matches_generic_multiplication() {
    let p = p256::ProjectivePoint::GENERATOR * p256::Scalar::random(&mut OsRng);
    let t = P256Comb::new(p, 4);
    let n_minus_1 = -p256::Scalar::ONE;
    let mut scalars =
        vec![p256::Scalar::ZERO, p256::Scalar::ONE, n_minus_1, p256::Scalar::from(15u64), p256::Scalar::from(16u64)];
    let mut x = p256::Scalar::ONE;
    for _ in 0..256 {
        scalars.push(x);
        scalars.push(x - p256::Scalar::ONE);
        x = x.double();
    }
    // canonical scalar whose every nibble is in 8..f (all table rows used)
    scalars.push(p256::Scalar::from_repr([0xee; 32].into()).unwrap());
    scalars.push(p256::Scalar::from_repr([0x8f; 32].into()).unwrap());
    for _ in 0..64 {
        scalars.push(p256::Scalar::random(&mut OsRng));
    }
    for s in scalars {
        assert_eq!(t.mul(&s), p * s);
    }
}

#[test]
fn g1_tables_match_generic_multiplication() {
    use bls12_381::{G1Projective, Scalar};
    let (y0, y1) =
        bbs_cd::utils::commitment_generators(bbs_cd_plugin::issuer::SUITE, &bbs_cd_plugin::issuer::SUITE.api_id())
            .unwrap();
    let (t0, t1) = y_combs(&y0, &y1).expect("suite generators");
    assert!(y_combs(&y1, &y0).is_none(), "other generators are refused");
    let mut scalars = vec![Scalar::zero(), Scalar::one(), -Scalar::one()];
    let mut x = Scalar::one();
    for _ in 0..255 {
        scalars.push(x);
        x = x.double();
    }
    for _ in 0..64 {
        let mut w = [0u8; 64];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut w);
        scalars.push(Scalar::from_bytes_wide(&w));
    }
    for s in &scalars {
        assert_eq!(t0.mul(s), y0 * s);
        assert_eq!(t1.mul(s), y1 * s);
    }
    let r = G1Projective::generator() * Scalar::from(12345u64);
    let t = G1Comb::new(r, 8);
    for s in &scalars {
        assert_eq!(t.mul(s), r * s);
    }
}

/// `tom::mul` (width-4 wNAF for generic scalars, shortcuts for 0 and ±1)
/// equals plain double-and-add.
#[test]
fn tom_mul_wnaf_matches_plain_multiplication() {
    use ark_ec::PrimeGroup;
    let r = TomPoint::rand(&mut OsRng);
    let mut scalars = fr_edges();
    for k in 0..300u64 {
        scalars.push(Fr::from(k));
        scalars.push(-Fr::from(k));
    }
    for s in scalars {
        assert_eq!(cd_tom256::tom::mul(&r, &s), r.mul_bigint(s.into_bigint()));
    }
}

/// `y_combs` refuses other generators and keeps serving the suite's.
#[test]
fn y_tables_are_keyed_by_generators() {
    let (y0, y1) =
        bbs_cd::utils::commitment_generators(bbs_cd_plugin::issuer::SUITE, &bbs_cd_plugin::issuer::SUITE.api_id())
            .unwrap();
    // every caller in this process uses the suite generators first
    assert!(y_combs(&y0, &y1).is_some());
    let g = bls12_381::G1Projective::generator();
    assert!(y_combs(&g, &y1).is_none());
    assert!(y_combs(&y0, &g).is_none());
    assert!(y_combs(&y0, &y1).is_some());
}
