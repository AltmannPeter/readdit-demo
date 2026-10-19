//! Raw mode: fresh device participation (multiplicative attacks against the
//! INTENTIONALLY VULNERABLE control vs. the candidate), device loss,
//! concurrency and cloned-state exposure.
//!
//! Failing attack searches are evidence about the tested attacks only, not a
//! proof of fresh device participation.
mod common;
use common::*;

use std::sync::Mutex;

use bbs_cd_plugin::envelope::{holder_statements, present, Verifier};
use bbs_cd_plugin::plugin::{EnvContext, PluginProver};
use bbs_cd_plugin::Error;
use cd_ecdsa_pop::common::{plugin_statement, prepare_link};
use cd_ecdsa_pop::device::{ecdsa_verify_prehashed, RawSigner};
use cd_ecdsa_pop::raw::insecure_test_controls::{MaliciousRawProver, Variant, VariantVerifier};
use cd_ecdsa_pop::raw::{self, h_input, rep_hash};
use cd_ecdsa_pop::{EcdsaPopProver, EcdsaSlot, Mode, Signer};
use cd_tom256::p256x;
use p256::elliptic_curve::Field;
use p256::{ProjectivePoint, Scalar};
use rand_core::{OsRng, RngCore};

fn variant_verifier(v: Variant) -> Verifier {
    Verifier::new().register(Box::new(VariantVerifier(v)))
}

/// Build a presentation for a fresh nonce from ONE signature (r, s0) on
/// representative e0 under Q, choosing a = h / e0 where h is computed
/// WITHOUT Q′ (only possible when the hash omits Q′).
fn scaling_attack(
    w: &World,
    e0: Scalar,
    sig0: (Scalar, Scalar),
    v: Variant,
) -> (bbs_cd_plugin::request::Request, Vec<u8>, bool) {
    let req = w.request(Mode::Raw);
    let params = w.params(Mode::Raw);
    let (cslot, input) = slot_and_input(&w.cred);
    let link = prepare_link(&input, &params, 4, Default::default(), &mut OsRng).unwrap();
    let (ctx, env, _) = holder_statements(&req, &[&w.cred], std::slice::from_ref(&cslot)).unwrap();
    let ectx = EnvContext { nonce: req.nonce.clone(), ctx, env, plugin_index: 0 };
    let mut nh = [0u8; 32];
    OsRng.fill_bytes(&mut nh);
    let pstmt = plugin_statement(&ectx, KEY, &req.plugins[0].params, None, &link.t_bytes);
    let h = rep_hash(&h_input(&pstmt, &req.nonce, &nh));
    let a = h * e0.invert().unwrap();
    let slot = raw::prepare_with_link(link, Some(a), Default::default(), &mut OsRng).unwrap();
    let signer = ReplaySigner { sig: sig0, pubkey: w.dev.public_key().unwrap(), seen: Mutex::new(vec![]) };
    // A malicious holder is not bound by the honest prover's device checks.
    let prover = MaliciousRawProver { slot, signer: &signer, variant: v, nh: Some(nh) };
    let out = present(&req, &[&w.cred], vec![cslot], vec![Box::new(prover) as Box<dyn PluginProver>], &mut OsRng, None)
        .unwrap();
    let matched = signer.seen.lock().unwrap()[0] == p256x::scalar_to_be(&e0);
    (req, out, matched)
}

/// Phase 1: holder retains one raw signature, then loses the device.
fn retained() -> (World, Scalar, (Scalar, Scalar)) {
    let w = world_for(Mode::Raw);
    let e0 = Scalar::random(&mut OsRng);
    let sig0 = w.dev.sign_representative(&p256x::scalar_to_be(&e0)).unwrap();
    w.dev.revoke();
    assert_eq!(w.dev.sign_representative(&[1u8; 32]), Err(Error::DeviceUnavailable));
    (w, e0, sig0)
}

#[test]
fn retained_signature_scaling_breaks_control_but_not_candidate() {
    let (w, e0, sig0) = retained();
    let (req, out, matched) = scaling_attack(&w, e0, sig0, Variant::VulnerableControlNoQprime);
    assert!(matched);
    variant_verifier(Variant::VulnerableControlNoQprime)
        .verify(&w.issuers(), &req, &out, None, None)
        .expect("control is broken");
    let (req, out, matched) = scaling_attack(&w, e0, sig0, Variant::Candidate);
    assert!(!matched, "c*h(Q') != e0: fixed-point condition fails");
    let e = verifier().verify(&w.issuers(), &req, &out, None, None).unwrap_err();
    assert_eq!(e.to_string(), "ecdsa");
}

/// Zero-query existential forgery for RAW-representative ECDSA under Q:
/// R = uG + vQ, r = x(R), s = r/v, e = u*s (valid on an e the forger can't choose).
fn forge_raw_signature(q: &ProjectivePoint) -> (Scalar, Scalar, Scalar) {
    loop {
        let (u, v) = (Scalar::random(&mut OsRng), Scalar::random(&mut OsRng));
        let rr = ProjectivePoint::GENERATOR * u + *q * v;
        if rr == ProjectivePoint::IDENTITY {
            continue;
        }
        let r = p256x::scalar_reduce(&p256x::x_coord(&rr));
        if r == Scalar::ZERO {
            continue;
        }
        let s = r * v.invert().unwrap();
        let e = u * s;
        if e != Scalar::ZERO {
            return (e, r, s);
        }
    }
}

#[test]
fn zero_query_forgery_breaks_control_only() {
    let (w, _, _) = retained();
    let q = p256x::decode_point(&w.dev.public_key().unwrap()).unwrap();
    let (e0, r, s) = forge_raw_signature(&q);
    assert!(ecdsa_verify_prehashed(&w.dev.public_key().unwrap(), &p256x::scalar_to_be(&e0), &r, &s));
    let (req, out, _) = scaling_attack(&w, e0, (r, s), Variant::VulnerableControlNoQprime);
    assert!(variant_verifier(Variant::VulnerableControlNoQprime).verify(&w.issuers(), &req, &out, None, None).is_ok());
    let (req, out, _) = scaling_attack(&w, e0, (r, s), Variant::Candidate);
    assert!(verifier().verify(&w.issuers(), &req, &out, None, None).is_err());
}

#[test]
fn many_retained_signatures_fixed_point_search() {
    let (w, e0, _) = retained();
    let mut reps: Vec<Scalar> = (0..63).map(|_| Scalar::random(&mut OsRng)).collect();
    reps.push(e0);
    let req = w.request(Mode::Raw);
    let (cslot, input) = slot_and_input(&w.cred);
    let link = prepare_link(&input, &w.params(Mode::Raw), 0, Default::default(), &mut OsRng).unwrap();
    let (ctx, env, _) = holder_statements(&req, &[&w.cred], std::slice::from_ref(&cslot)).unwrap();
    let ectx = EnvContext { nonce: req.nonce.clone(), ctx, env, plugin_index: 0 };
    let mut hits = 0;
    for _ in 0..300 {
        let a = Scalar::random(&mut OsRng);
        let qp = p256x::encode(&(link.q * a));
        let pstmt = plugin_statement(&ectx, KEY, &req.plugins[0].params, Some(&qp), &link.t_bytes);
        let mut nh = [0u8; 32];
        OsRng.fill_bytes(&mut nh);
        let h = rep_hash(&h_input(&pstmt, &req.nonce, &nh));
        hits += reps.contains(&(a.invert().unwrap() * h)) as usize;
    }
    assert_eq!(hits, 0);
}

#[test]
fn deterministic_signer_concurrency() {
    let w = world_with(Mode::Raw, 96, true);
    let n = 4;
    let reqs: Vec<_> = (0..n).map(|_| w.request(Mode::Raw)).collect();
    let outs: Vec<Vec<u8>> = std::thread::scope(|sc| {
        let hs: Vec<_> = reqs
            .iter()
            .map(|req| {
                let w = &w;
                sc.spawn(move || present_with(req, &w.cred, &w.dev, Mode::Raw, None).unwrap())
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for (req, out) in reqs.iter().zip(&outs) {
        assert!(w.ok(req, out));
    }
    let log = w.dev.log();
    let mut l2 = log.clone();
    l2.sort();
    l2.dedup();
    assert_eq!(l2.len(), log.len(), "distinct sessions -> distinct representatives");
}

/// A cloned slot is as sensitive as the credential: c and Q′ give Q = c·Q′,
/// and the limbs/openings open the BBS commitments.
#[test]
fn slot_state_exposes_device_key() {
    let w = world_for(Mode::Raw);
    let (_, input) = slot_and_input(&w.cred);
    let slot = raw::prepare(&input, &w.params(Mode::Raw), 4, None, Default::default(), &mut OsRng).unwrap();
    assert_eq!(p256x::encode(&(slot.qp * slot.c)), w.dev.public_key().unwrap());
}

#[test]
fn device_log_links_if_shared_with_verifier() {
    // the representative c*h is device-side only; if the device log leaked to
    // the verifier, rep / h = c would link Q′ to Q.  Demonstrate the algebra.
    let w = world_for(Mode::Raw);
    let (req, out) = w.honest(Mode::Raw);
    let (pe, env, view) = env_and_view(&w, &req, &out);
    let params = w.params(Mode::Raw);
    let pr = raw::parse(&pe.plugin_proofs[0], &view, &params).unwrap();
    let rep = p256x::scalar_from_canonical(&w.dev.log()[0]).unwrap();
    let pstmt = plugin_statement(&env, KEY, &req.plugins[0].params, Some(&pr.qp33), &pr.common.t_bytes);
    let h = rep_hash(&h_input(&pstmt, &req.nonce, &pr.nh));
    let c = rep * h.invert().unwrap();
    assert_eq!(p256x::encode(&(pr.qp * c)), w.dev.public_key().unwrap());
}

#[test]
fn honest_prover_and_candidate_variant_agree() {
    let w = world_for(Mode::Raw);
    let (req, out) = w.honest(Mode::Raw);
    variant_verifier(Variant::Candidate).verify(&w.issuers(), &req, &out, None, None).unwrap();
    assert!(variant_verifier(Variant::VulnerableControlNoQprime).verify(&w.issuers(), &req, &out, None, None).is_err());
    // the honest prover type works with an explicit raw slot too
    let (cslot, input) = slot_and_input(&w.cred);
    let slot = raw::prepare(&input, &w.params(Mode::Raw), 2, None, Default::default(), &mut OsRng).unwrap();
    let prover = EcdsaPopProver::new(EcdsaSlot::Raw(slot), Signer::Raw(&w.dev));
    let out = present(&req, &[&w.cred], vec![cslot], vec![Box::new(prover) as Box<dyn PluginProver>], &mut OsRng, None)
        .unwrap();
    assert!(w.ok(&req, &out));
}
