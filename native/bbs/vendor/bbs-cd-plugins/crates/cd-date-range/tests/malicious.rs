//! A malicious holder builds `date-range` proofs by hand (feature
//! `insecure-test-controls`).  Every attempt must be rejected.
mod common;

use bbs_cd_plugin::plugin::{CommittedInput, CryptoRngCore, EnvContext, PluginProver, PluginVerifier};
use bbs_cd_plugin::Error;
use bls12_381::Scalar;
use cd_date_range::insecure_test_controls::{prove_forged, Forge};
use cd_date_range::range::Bases;
use cd_date_range::{DateRangeParams, DateRangeProver, DateRangeVerifier, Ymd};
use common::*;
use rand_core::OsRng;

/// Forge a proof for `born` against `p` and check it at plugin level and
/// through the envelope.  Returns the plugin-level error.
fn forge_rejected(born: &str, p: DateRangeParams, forge: impl Fn() -> Forge) -> Error {
    let w = world(born);
    let params = p.encode();
    // plugin level
    let (env, input) = w.plugin_input();
    let proof = prove_forged(&env, &input, &params, forge(), &mut OsRng).unwrap();
    let err = DateRangeVerifier.verify(&env, &input.view(), &params, &proof, &mut OsRng).expect_err("must reject");
    // envelope level
    let req = w.request(&p);
    let b = w
        .present_with(
            &req,
            Box::new(FnProver(
                |env: &EnvContext, input: &CommittedInput, params: &[u8], rng: &mut dyn CryptoRngCore| {
                    prove_forged(env, input, params, forge(), rng)
                },
            )),
        )
        .unwrap();
    assert!(w.verify(&req, &b).is_err());
    err
}

fn digits_for(bases: &Bases, v: u64) -> Vec<Scalar> {
    bases.digits(v).unwrap().into_iter().map(Scalar::from).collect()
}

const LE18: u32 = 20081018;

#[test]
fn too_young_with_low_bits() {
    // m − lo exceeds N but fits k bits: the digit commitments then commit to
    // Σ β_i·d_i ≠ m − lo
    let e = forge_rejected("2010-01-01", DateRangeParams::le(LE18), Forge::default);
    assert!(e.to_string().contains("sum"), "{e}");
}

#[test]
fn too_young_with_all_ones() {
    let n = DateRangeParams::le(LE18).bounds(17).unwrap().1;
    let k = Bases::new(n).k();
    forge_rejected("2010-01-01", DateRangeParams::le(LE18), || Forge {
        digits: Some(vec![Scalar::one(); k]),
        ..Forge::default()
    });
}

#[test]
fn too_young_with_a_non_bit_digit() {
    // digits that do sum to m − lo: the last one is not a bit
    let (lo, hi) = DateRangeParams::le(LE18).bounds(17).unwrap();
    let b = Bases::new(hi - lo);
    let k = b.k();
    let v = Ymd::from_yyyymmdd(20100101).unwrap().pack() - lo;
    let low = (1u64 << (k - 1)) - 1;
    let last = Scalar::from(v - low) * Scalar::from(b.beta[k - 1]).invert().unwrap();
    let mut d = vec![Scalar::one(); k - 1];
    d.push(last);
    let e = forge_rejected("2010-01-01", DateRangeParams::le(LE18), || Forge {
        digits: Some(d.clone()),
        ..Forge::default()
    });
    assert!(e.to_string().contains("bit proofs"), "{e}");
}

#[test]
fn too_old_for_a_ge_request() {
    // m − lo is negative: wraps modulo r
    forge_rejected("1990-05-17", DateRangeParams::ge(20011019), Forge::default);
}

#[test]
fn digit_two_or_minus_one_even_in_range() {
    // an in-range date, but digits 0,1 at positions 0,1 replaced by 2,0 or
    // a (−1, +1) pair with the same sum
    let p = DateRangeParams::le(LE18);
    let (lo, hi) = p.bounds(17).unwrap();
    let b = Bases::new(hi - lo);
    let v = Ymd::from_yyyymmdd(19900517).unwrap().pack() - lo;
    let honest = digits_for(&b, v);
    let mut two = honest.clone();
    // β_0 = 1, β_1 = 2: +2 at position 0 and −1 at position 1 keep the sum
    two[0] += Scalar::from(2u64);
    two[1] -= Scalar::one();
    let e = forge_rejected("1990-05-17", p, || Forge { digits: Some(two.clone()), ..Forge::default() });
    assert!(e.to_string().contains("bit proofs"), "{e}");
}

#[test]
fn wrong_opening() {
    let e = forge_rejected("1990-05-17", DateRangeParams::le(LE18), || Forge {
        opening_offset: Scalar::one(),
        ..Forge::default()
    });
    assert!(e.to_string().contains("sum"), "{e}");
}

#[test]
fn proof_for_other_bounds_with_the_same_k() {
    // too young for 2008-10-18; prove against hi = pack(2010-01-01) instead
    let born = Ymd::from_yyyymmdd(20100101).unwrap().pack();
    forge_rejected("2010-01-01", DateRangeParams::le(LE18), || Forge { bounds: Some((0, born)), ..Forge::default() });
}

/// An honest proof moved to another context or other parameters.
#[test]
fn proof_is_bound_to_its_context() {
    let w = world("1990-05-17");
    let p = DateRangeParams::le(LE18).encode();
    let (env, input) = w.plugin_input();
    let view = input.view();
    let proof = Box::new(DateRangeProver::new()).prove(&env, &input, &p, &mut OsRng).unwrap();
    let v =
        |env: &EnvContext, params: &[u8], proof: &[u8]| DateRangeVerifier.verify(env, &view, params, proof, &mut OsRng);
    v(&env, &p, &proof).unwrap();
    // another nonce, env, position
    let mut e2 = env.clone();
    e2.nonce[0] ^= 1;
    assert!(v(&e2, &p, &proof).is_err());
    let mut e3 = env.clone();
    e3.env[100] ^= 1;
    assert!(v(&e3, &p, &proof).is_err());
    let e4 = EnvContext { plugin_index: 1, ..env.clone() };
    assert!(v(&e4, &p, &proof).is_err());
    // other parameters with the same proof length (k = 16)
    for other in [DateRangeParams::le(20081017), DateRangeParams::le(20081019), DateRangeParams::le(20040101)] {
        assert!(v(&env, &other.encode(), &proof).is_err(), "{other}");
    }
    // another commitment
    let (_, other_input) = w.plugin_input();
    assert!(DateRangeVerifier.verify(&env, &other_input.view(), &p, &proof, &mut OsRng).is_err());
}

#[test]
fn tampering_is_rejected() {
    let w = world("1990-05-17");
    let p = DateRangeParams::le(LE18).encode();
    let (env, input) = w.plugin_input();
    let view = input.view();
    let proof = Box::new(DateRangeProver::new()).prove(&env, &input, &p, &mut OsRng).unwrap();
    let v = |b: &[u8]| DateRangeVerifier.verify(&env, &view, &p, b, &mut OsRng);
    // length
    assert!(matches!(v(&proof[..proof.len() - 1]), Err(Error::Decode(_))));
    assert!(matches!(v(&[&proof[..], &[0]].concat()), Err(Error::Decode(_))));
    // non-canonical scalar: c = r (and all-ones)
    let mut b = proof.clone();
    b[4..36].copy_from_slice(&[0xff; 32]);
    assert!(matches!(v(&b), Err(Error::Decode(_))));
    // bit flips: magic, c, the whole first and last digit, and every 5th byte
    let n = proof.len();
    let positions: Vec<usize> = (0..36 + 144).chain(n - 144..n).chain((0..n).step_by(5)).collect();
    for i in positions {
        let mut b = proof.clone();
        b[i] ^= 1 << (i % 8);
        assert!(v(&b).is_err(), "flip at {i}");
    }
}

#[test]
fn swapping_digit_records_is_rejected() {
    // digits 0 and 1 have different bases; swapping their records keeps every
    // bit proof well-formed but breaks the sum (and the challenge)
    let w = world("1990-05-17");
    let p = DateRangeParams::le(LE18).encode();
    let (env, input) = w.plugin_input();
    let view = input.view();
    let proof = Box::new(DateRangeProver::new()).prove(&env, &input, &p, &mut OsRng).unwrap();
    let mut b = proof.clone();
    let (r0, r1) = (36..180, 180..324);
    let d0 = proof[r0.clone()].to_vec();
    b[r0].copy_from_slice(&proof[r1.clone()]);
    b[r1].copy_from_slice(&d0);
    if b != proof {
        assert!(DateRangeVerifier.verify(&env, &view, &p, &b, &mut OsRng).is_err());
    }
}

/// Control: the forging path with honest digits and opening gives a valid
/// proof, so the rejections above come from the forged values.
#[test]
fn forge_control_with_honest_values_verifies() {
    let w = world("1990-05-17");
    let p = DateRangeParams::le(LE18);
    let (lo, hi) = p.bounds(17).unwrap();
    let d = digits_for(&Bases::new(hi - lo), Ymd::from_yyyymmdd(19900517).unwrap().pack() - lo);
    let (env, input) = w.plugin_input();
    let proof =
        prove_forged(&env, &input, &p.encode(), Forge { digits: Some(d), ..Forge::default() }, &mut OsRng).unwrap();
    DateRangeVerifier.verify(&env, &input.view(), &p.encode(), &proof, &mut OsRng).unwrap();
}
