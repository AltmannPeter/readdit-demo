//! A malicious holder builds pseudonym proofs by hand (feature
//! `insecure-test-controls`).  Every attempt must be rejected.
mod common;

use bbs_cd_plugin::plugin::{CommittedInput, CryptoRngCore, EnvContext, PluginProver, PluginVerifier};
use bbs_cd_plugin::Error;
use bls12_381::Scalar;
use cd_pseudonym::insecure_test_controls::{prove_forged, Forge};
use cd_pseudonym::{PseudonymParams, PseudonymProver, PseudonymVerifier};
use common::*;
use rand_core::{OsRng, RngCore};

fn rand_scalar() -> Scalar {
    let mut w = [0u8; 64];
    OsRng.fill_bytes(&mut w);
    Scalar::from_bytes_wide(&w)
}

/// Forge at plugin level and through the envelope; returns the plugin-level error.
fn rejected(forge: impl Fn() -> Forge) -> Error {
    let w = world();
    let params = PseudonymParams::known_offender_matching(RP_A).encode();
    let (env, input) = w.plugin_input();
    let proof = prove_forged(&env, &input, &params, forge(), &mut OsRng).unwrap();
    let err =
        PseudonymVerifier::any().verify(&env, &input.view(), &params, &proof, &mut OsRng).expect_err("must reject");
    let req = w.request(RP_A);
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

#[test]
fn control_honest_values_through_the_forge_path_verify() {
    let w = world();
    let params = PseudonymParams::known_offender_matching(RP_A).encode();
    let (env, input) = w.plugin_input();
    let proof = prove_forged(&env, &input, &params, Forge::default(), &mut OsRng).unwrap();
    PseudonymVerifier::any().verify(&env, &input.view(), &params, &proof, &mut OsRng).unwrap();
}

#[test]
fn pseudonym_from_another_seed() {
    let e = rejected(|| Forge { nym_seed: Some(rand_scalar()), ..Forge::default() });
    assert!(matches!(e, Error::Reject(_)), "{e}");
}

#[test]
fn another_seed_used_consistently() {
    // pseudonym and responses from a seed the credential does not hold
    let s = rand_scalar();
    let e = rejected(|| Forge { witness_seed: Some(s), ..Forge::default() });
    assert!(matches!(e, Error::Reject(_)), "{e}");
}

#[test]
fn pseudonym_for_another_relying_party() {
    let e = rejected(|| Forge { verifier_input: Some(RP_B.to_vec()), ..Forge::default() });
    assert!(matches!(e, Error::Reject(_)), "{e}");
}

#[test]
fn identity_pseudonym() {
    let e = rejected(|| Forge { identity_nym: true, ..Forge::default() });
    assert!(matches!(e, Error::Decode(_)), "{e}");
}

#[test]
fn proof_is_bound_to_its_context() {
    let w = world();
    let p = PseudonymParams::known_offender_matching(RP_A).encode();
    let (env, input) = w.plugin_input();
    let view = input.view();
    let proof = Box::new(PseudonymProver::new(RP_A)).prove(&env, &input, &p, &mut OsRng).unwrap();
    let v = |env: &EnvContext, params: &[u8], proof: &[u8]| {
        PseudonymVerifier::any().verify(env, &view, params, proof, &mut OsRng)
    };
    v(&env, &p, &proof).unwrap();
    let mut e = env.clone();
    e.nonce[0] ^= 1;
    assert!(v(&e, &p, &proof).is_err());
    let mut e = env.clone();
    e.env[100] ^= 1;
    assert!(v(&e, &p, &proof).is_err());
    assert!(v(&EnvContext { plugin_index: 1, ..env.clone() }, &p, &proof).is_err());
    // the same proof presented as another relying party's pseudonym
    let other = PseudonymParams::known_offender_matching(RP_B).encode();
    assert!(v(&env, &other, &proof).is_err());
    // another commitment
    let (_, other_input) = w.plugin_input();
    assert!(PseudonymVerifier::any().verify(&env, &other_input.view(), &p, &proof, &mut OsRng).is_err());
}

#[test]
fn tampering_is_rejected() {
    let w = world();
    let p = PseudonymParams::known_offender_matching(RP_A).encode();
    let (env, input) = w.plugin_input();
    let view = input.view();
    let proof = Box::new(PseudonymProver::new(RP_A)).prove(&env, &input, &p, &mut OsRng).unwrap();
    let v = |b: &[u8]| PseudonymVerifier::any().verify(&env, &view, &p, b, &mut OsRng);
    assert!(matches!(v(&proof[..proof.len() - 1]), Err(Error::Decode(_))));
    assert!(matches!(v(&[&proof[..], &[0]].concat()), Err(Error::Decode(_))));
    for i in 0..proof.len() {
        for bit in [0, 3, 7] {
            let mut b = proof.clone();
            b[i] ^= 1 << bit;
            assert!(v(&b).is_err(), "flip at {i}.{bit}");
        }
    }
}
