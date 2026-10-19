//! Hashed mode against malicious provers (review finding H-4).
//!
//! Each test builds an `ecdsa-pop` proof by hand through the
//! `hashed::insecure_test_controls::assemble` hook, bypassing every check of
//! the honest prover, and runs the real verifier on it.  The first test
//! shows the hook reproduces honest proofs, so a rejection below is the
//! verifier's doing and not a broken hook.
//!
//! Failing attacks are evidence about these attacks only, not a proof.
mod common;
use common::*;

use bbs_cd_plugin::envelope::present;
use bbs_cd_plugin::plugin::{CommittedInput, CryptoRngCore, EnvContext, PluginProver};
use bbs_cd_plugin::request::Request;
use bbs_cd_plugin::Error;
use cd_ecdsa_pop::common::{oc_challenge, plugin_statement, prepare_link, KeyLink};
use cd_ecdsa_pop::device::{HashSigner, SoftwareDevice};
use cd_ecdsa_pop::hashed::{
    self, device_message, insecure_test_controls::assemble, link_challenge, msg_hash, r_of, LINK_U1,
};
use cd_ecdsa_pop::params::PROFILE_SHARED_BIT;
use cd_ecdsa_pop::{EcdsaParams, Mode};
use cd_tom256::p256x;
use cd_tom256::pa::{pa_prepare, pa_prepare_with_slope, pa_verify, PaState};
use cd_tom256::params::SM_ROUNDS;
use cd_tom256::sm::{commit_point, sm_prepare_rounds_with, SmRound};
use cd_tom256::tom::{self, fr_rand, fr_to_be, Fr, TomPoint};
use cd_tom256::transfer::{fold, fold_fr};
use p256::elliptic_curve::Field;
use p256::{ProjectivePoint, Scalar};
use rand_core::{OsRng, RngCore};

const G: ProjectivePoint = ProjectivePoint::GENERATOR;

fn zero() -> Fr {
    Fr::from(0u64)
}

/// The device's answer, unpacked the way the holder does it.
struct Signed {
    m: Vec<u8>,
    nh: [u8; 32],
    k: ProjectivePoint,
    z: Scalar,
    hpt: ProjectivePoint,
}

/// Sign the device message for `link`'s T_j with `dev` (any key).
fn sign_with(dev: &SoftwareDevice, link: &KeyLink, env: &EnvContext, params: &[u8]) -> Signed {
    let pstmt = plugin_statement(env, KEY, params, None, &link.t_bytes);
    let mut nh = [0u8; 32];
    OsRng.fill_bytes(&mut nh);
    let m = device_message(&pstmt, &env.nonce, &nh);
    let h = msg_hash(&m);
    let (r, s) = dev.sign_message(&m).unwrap();
    let q = p256x::decode_point(&dev.hash_public_key().unwrap()).unwrap();
    let rinv = r.invert().unwrap();
    let k = (G * h + q * r) * s.invert().unwrap();
    assert_eq!(r_of(&k), r);
    Signed { m, nh, k, z: s * rinv, hpt: G * (h * rinv) }
}

/// Link PA proving "committed key + Hpt = committed W" with witness `a` for
/// the key slot (honest only if `a` is the committed key).
fn link_pa(
    a: &ProjectivePoint,
    hpt: &ProjectivePoint,
    w: &ProjectivePoint,
    link: &KeyLink,
    cw: (TomPoint, TomPoint),
    rw: (Fr, Fr),
) -> PaState {
    let ch = commit_point(hpt, (zero(), zero()));
    pa_prepare(
        a,
        hpt,
        w,
        &[link.rq.0, link.rq.1, zero(), zero(), rw.0, rw.1],
        &[link.cq.0, link.cq.1, ch.0, ch.1, cw.0, cw.1],
        &mut OsRng,
    )
    .unwrap()
}

/// SM rounds proving "committed W = z·K", with witness point `w`.
fn sm_rounds(
    w: &ProjectivePoint,
    z: &Scalar,
    k: &ProjectivePoint,
    cw: (TomPoint, TomPoint),
    rw: (Fr, Fr),
    p: &EcdsaParams,
) -> Vec<SmRound> {
    let shared = p.profile == PROFILE_SHARED_BIT;
    sm_prepare_rounds_with(w, z, k, cw, rw, shared, SM_ROUNDS, Default::default(), &mut OsRng).unwrap()
}

/// Run the envelope with a hand-built plugin proof for a hashed request.
fn forge<F>(w: &World, build: F) -> (Request, Vec<u8>)
where
    F: FnOnce(&EnvContext, &CommittedInput, &[u8]) -> Vec<u8>,
{
    let req = w.request(Mode::Hashed);
    let (cslot, _) = slot_and_input(&w.cred);
    let prover = FnProver(move |env: &EnvContext, input: &CommittedInput, params: &[u8], _: &mut dyn CryptoRngCore| {
        Ok(build(env, input, params))
    });
    let out = present(&req, &[&w.cred], vec![cslot], vec![Box::new(prover) as Box<dyn PluginProver>], &mut OsRng, None)
        .unwrap();
    (req, out)
}

fn new_link(input: &CommittedInput, params: &[u8]) -> (EcdsaParams, KeyLink) {
    let p = EcdsaParams::decode(params).unwrap();
    let link = prepare_link(input, &p, 4, Default::default(), &mut OsRng).unwrap();
    (p, link)
}

fn rand_blinds() -> (Fr, Fr) {
    (fr_rand(&mut OsRng), fr_rand(&mut OsRng))
}

/// The hook rebuilds an accepted proof from honest parts.
#[test]
fn hook_reproduces_honest_proof() {
    let w = world_for(Mode::Hashed);
    let (req, out) = forge(&w, |env, input, params| {
        let (p, link) = new_link(input, params);
        let sg = sign_with(&w.dev, &link, env, params);
        let wpt = link.q + sg.hpt;
        let rw = rand_blinds();
        let cw = commit_point(&wpt, rw);
        let pa = link_pa(&link.q, &sg.hpt, &wpt, &link, cw, rw);
        let rounds = sm_rounds(&wpt, &sg.z, &sg.k, cw, rw, &p);
        assemble(link, &sg.m, &sg.nh, &sg.k, cw, pa, rounds).unwrap()
    });
    assert!(w.ok(&req, &out));
}

/// (r, s) and (r, −s) are both valid ECDSA signatures, with nonce points K
/// and −K.  A holder who re-proves with −K and z′ = −z is accepted, and that
/// is correct: it still needed a signature by the committed key on this
/// request.  Swapping K for −K without re-proving is rejected.
#[test]
fn negated_nonce_point_is_ecdsa_malleability() {
    let w = world_for(Mode::Hashed);
    let (req, out) = forge(&w, |env, input, params| {
        let (p, link) = new_link(input, params);
        let sg = sign_with(&w.dev, &link, env, params);
        let (k, z) = (-sg.k, -sg.z);
        let wpt = link.q + sg.hpt;
        assert_eq!(k * z, wpt);
        let rw = rand_blinds();
        let cw = commit_point(&wpt, rw);
        let pa = link_pa(&link.q, &sg.hpt, &wpt, &link, cw, rw);
        let rounds = sm_rounds(&wpt, &z, &k, cw, rw, &p);
        assemble(link, &sg.m, &sg.nh, &k, cw, pa, rounds).unwrap()
    });
    assert!(w.ok(&req, &out), "re-proved −K is a proof of the valid signature (r, −s)");
    // without re-proving: flip the sign byte of K in an honest proof
    let (req, out) = w.honest(Mode::Hashed);
    let sg = plugin_segments(&w, &req, &out);
    let mut x = out.clone();
    x[sg.point.0] ^= 1; // 0x02 <-> 0x03
    assert!(!w.ok(&req, &x));
}

/// A holder who bypasses the device-key check and signs with another key
/// Q2 (everything else honest for Q2) fails the link: the key commitments
/// hold Q, not Q2.
#[test]
fn other_device_key_fails_link() {
    let w = world_for(Mode::Hashed);
    let dev2 = SoftwareDevice::new(Mode::Hashed, false);
    let q2 = p256x::decode_point(&dev2.hash_public_key().unwrap()).unwrap();
    let (req, out) = forge(&w, |env, input, params| {
        let (p, link) = new_link(input, params);
        let sg = sign_with(&dev2, &link, env, params);
        let w2 = q2 + sg.hpt;
        let rw = rand_blinds();
        let cw = commit_point(&w2, rw);
        let pa = link_pa(&q2, &sg.hpt, &w2, &link, cw, rw); // witness Q2 against C_Q
        let rounds = sm_rounds(&w2, &sg.z, &sg.k, cw, rw, &p);
        assemble(link, &sg.m, &sg.nh, &sg.k, cw, pa, rounds).unwrap()
    });
    let e = w.reject(&req, &out);
    assert_eq!(e, Error::Reject("link".into()));
}

/// The link is honest for W = Q + Hpt, but the SM proves the other key's
/// W2 = z2·K2 against C_W: the SM fails.
#[test]
fn sm_for_other_point_fails() {
    let w = world_for(Mode::Hashed);
    let dev2 = SoftwareDevice::new(Mode::Hashed, false);
    let (req, out) = forge(&w, |env, input, params| {
        let (p, link) = new_link(input, params);
        let sg = sign_with(&dev2, &link, env, params);
        let wpt = link.q + sg.hpt;
        let w2 = sg.k * sg.z;
        assert_ne!(wpt, w2);
        let rw = rand_blinds();
        let cw = commit_point(&wpt, rw);
        let pa = link_pa(&link.q, &sg.hpt, &wpt, &link, cw, rw);
        let rounds = sm_rounds(&w2, &sg.z, &sg.k, cw, rw, &p); // witness W2 against C_W
        assemble(link, &sg.m, &sg.nh, &sg.k, cw, pa, rounds).unwrap()
    });
    let e = w.reject(&req, &out).to_string();
    assert!(e.starts_with("sm["), "{e}");
}

/// F-1 in hashed mode.  The holder commits (Tom side) to an OFF-CURVE pair
/// A for the key.  The restricted PA does not force A onto the curve: with
/// the chord slope through A and Hpt it accepts the formula "sum" W.  What
/// stops the attack is the on-curve proof (and, in the full presentation,
/// the transfer, because the D_j hold the issuer-checked real key).
#[test]
fn offcurve_key_passes_link_but_not_on_curve() {
    let w = world_for(Mode::Hashed);
    let lb = w.limb_bits;
    let (req, out) = forge(&w, |env, input, params| {
        let (p, mut link) = new_link(input, params);
        // an off-curve pair A, committed through fake limbs
        let (xa, ya) = loop {
            let (x, y) = (fr_rand(&mut OsRng), fr_rand(&mut OsRng));
            if p256x::point_from_limbs(&p256x::limbs_of_coords(&fr_to_be(&x), &fr_to_be(&y), lb), lb).is_err() {
                break (x, y);
            }
        };
        let fake = p256x::limbs_of_coords(&fr_to_be(&xa), &fr_to_be(&ya), lb);
        let tpts: Vec<_> = fake.iter().zip(&link.rho).map(|(m, r)| tom::commit(Fr::from(*m), *r)).collect();
        link.t_bytes = tpts.iter().map(|p| tom::encode(p, true)).collect();
        link.limbs = fake;
        link.rq = fold_fr(&link.rho, lb);
        link.cq = (tom::commit(xa, link.rq.0), tom::commit(ya, link.rq.1));
        assert_eq!(link.cq, fold(&tpts, lb));
        link.oncurve =
            cd_tom256::oncurve::oncurve_prepare(xa, ya, link.rq.0, link.rq.1, &link.cq.0, &link.cq.1, &mut OsRng);
        link.oc_first_bytes = link.oncurve.first.iter().flat_map(|p| tom::encode(p, true)).collect();
        // the device signs (T_j are fixed now); Hpt is public
        let sg = sign_with(&w.dev, &link, env, params);
        let (xb, yb) = p256x::coords_fr(&sg.hpt);
        // formula "sum" T = A + Hpt along the chord through A and Hpt
        let t = (yb - ya) * ark_ff::Field::inverse(&(xb - xa)).unwrap();
        let xt = t * t - xa - xb;
        let yt = t * (xa - xt) - ya;
        let rw = rand_blinds();
        let cw = (tom::commit(xt, rw.0), tom::commit(yt, rw.1));
        let ch = commit_point(&sg.hpt, (zero(), zero()));
        let pa = pa_prepare_with_slope(
            (xa, ya),
            (xb, yb),
            (xt, yt),
            t,
            &[link.rq.0, link.rq.1, zero(), zero(), rw.0, rw.1],
            &[link.cq.0, link.cq.1, ch.0, ch.1, cw.0, cw.1],
            &mut OsRng,
        )
        .unwrap();
        // the SM cannot be honest for an off-curve W; prove the real W instead
        let wreal = sg.k * sg.z;
        let rounds = sm_rounds(&wreal, &sg.z, &sg.k, cw, rw, &p);
        assemble(link, &sg.m, &sg.nh, &sg.k, cw, pa, rounds).unwrap()
    });
    let e = w.reject(&req, &out).to_string();
    assert!(e.starts_with("transfer"), "{e}");
    // the sections on their own
    let (pe, env, view) = env_and_view(&w, &req, &out);
    let proof = &pe.plugin_proofs[0];
    let params = EcdsaParams::decode(&req.plugins[0].params).unwrap();
    let pr = hashed::parse(proof, &view, &params).unwrap();
    let (mm, _) = hashed::recompute_challenges(&env, &view, &req.plugins[0].params, proof).unwrap();
    let cq = fold(&pr.common.t, lb);
    let pstmt = plugin_statement(&env, KEY, &req.plugins[0].params, None, &pr.common.t_bytes);
    let h = msg_hash(&device_message(&pstmt, &env.nonce, &pr.nh));
    let hpt = G * (h * r_of(&pr.k).invert().unwrap());
    let ch = commit_point(&hpt, (zero(), zero()));
    let c6 = [cq.0, cq.1, ch.0, ch.1, pr.link_first[0], pr.link_first[1]];
    let ann: [TomPoint; 10] = pr.link_first[2..].try_into().unwrap();
    assert!(pa_verify(&c6, &ann, link_challenge(&mm).unwrap(), &pr.link_z), "link alone accepts the off-curve A");
    assert!(
        !cd_tom256::oncurve::oncurve_verify(
            &cq.0,
            &cq.1,
            &pr.common.oc_first,
            oc_challenge(&mm).unwrap(),
            &pr.common.oc_z
        ),
        "the on-curve proof rejects it"
    );
}

/// U1 = O in the link (the case x(Hpt) = x(Q)) is refused by the parser.
#[test]
fn identity_u1_in_link_rejected() {
    let w = world_for(Mode::Hashed);
    let (req, out) = w.honest(Mode::Hashed);
    let sg = plugin_segments(&w, &req, &out);
    let at = sg.link.0 + LINK_U1 * 33;
    let x = put(&out, (at, at + 33), &[0u8; 33]);
    assert!(matches!(w.reject(&req, &x), Error::Decode(_)));
}

#[test]
fn no_signature_random_nonce_point_fails_sm() {
    // A holder without any signature: random K and z cannot pass the SM for
    // W = Q + Hpt (the SM is sound; this is the "no device" baseline).
    let w = world_for(Mode::Hashed);
    let (req, out) = forge(&w, |env, input, params| {
        let (p, link) = new_link(input, params);
        let pstmt = plugin_statement(env, KEY, params, None, &link.t_bytes);
        let mut nh = [0u8; 32];
        OsRng.fill_bytes(&mut nh);
        let m = device_message(&pstmt, &env.nonce, &nh);
        let k = G * Scalar::random(&mut OsRng);
        let z = Scalar::random(&mut OsRng);
        let hpt = G * (msg_hash(&m) * r_of(&k).invert().unwrap());
        let wpt = link.q + hpt;
        let rw = rand_blinds();
        let cw = commit_point(&wpt, rw);
        let pa = link_pa(&link.q, &hpt, &wpt, &link, cw, rw);
        let rounds = sm_rounds(&(k * z), &z, &k, cw, rw, &p);
        assemble(link, &m, &nh, &k, cw, pa, rounds).unwrap()
    });
    let e = w.reject(&req, &out).to_string();
    assert!(e.starts_with("sm["), "{e}");
}
