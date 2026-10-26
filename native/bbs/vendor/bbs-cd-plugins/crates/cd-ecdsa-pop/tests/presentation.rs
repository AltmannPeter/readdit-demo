//! End-to-end presentations in both modes: honest runs, binding, tampering,
//! splicing, parse ranges, issuance checks and the F-1 composition
//! counterpart.
mod common;
use common::*;

use std::cell::RefCell;

use bbs_cd::utils::{octets_to_proof, proof_to_octets};
use bbs_cd_plugin::envelope::parse;
use bbs_cd_plugin::issuer::Issuer;
use bbs_cd_plugin::Error;
use cd_ecdsa_pop::attestation::{Manufacturer, P256KeyHandler};
use cd_ecdsa_pop::common::{oc_challenge, KeyLink};
use cd_ecdsa_pop::device::RawSigner;
use cd_ecdsa_pop::params::{PROFILE_SEPARATE_PA, PROFILE_SHARED_BIT};
use cd_ecdsa_pop::raw::{self, RawSlot};
use cd_ecdsa_pop::{EcdsaParams, EcdsaPopProver, EcdsaSlot, Mode, ProveStats, Signer, VerifyMode};
use cd_tom256::p256x;
use cd_tom256::pa::pa_prepare_with_slope;
use cd_tom256::params::{BLS_R_HEX, P256_P_HEX, SM_ROUNDS};
use cd_tom256::sm::{
    commit_point, decode_sm_points, encode_sm_first, sm_verify_round, SmRound, SM_FIRST_BYTES, SM_ROUND_BYTES,
};
use cd_tom256::tom::{self, fr_rand, fr_to_be, Fr};
use cd_tom256::transfer::{fold, fold_fr, Bounds};
use p256::elliptic_curve::Field;
use p256::Scalar;
use rand_core::OsRng;

fn n_bytes() -> [u8; 32] {
    num_bigint::BigUint::parse_bytes(b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
        .unwrap()
        .to_bytes_be()
        .try_into()
        .unwrap()
}

#[test]
fn honest_both_modes_profiles_and_stats() {
    for mode in MODES {
        let w = world_for(mode);
        for profile in [PROFILE_SHARED_BIT, PROFILE_SEPARATE_PA] {
            let mut p = w.params(mode);
            p.profile = profile.to_vec();
            let req = w.request_with(&p);
            let st = RefCell::new(ProveStats::default());
            let out = present_with(&req, &w.cred, &w.dev, mode, Some(&st)).unwrap();
            assert!(st.borrow().transfer_attempts >= 1);
            plugin_segments(&w, &req, &out); // asserts the exact proof size
            let v = verifier().verify(&w.issuers(), &req, &out, None, None).unwrap();
            assert_eq!(v.disclosed[0], vec![(DISCLOSE.to_string(), b"SE".to_vec())]);
            verifier_mode(VerifyMode::Individual).verify(&w.issuers(), &req, &out, None, None).unwrap();
            // the same proof under other parameters is rejected
            let mut q = p.clone();
            q.profile = if profile == PROFILE_SHARED_BIT { PROFILE_SEPARATE_PA } else { PROFILE_SHARED_BIT }.to_vec();
            let mut req2 = req.clone();
            req2.plugins[0].params = q.encode();
            assert!(!w.ok(&req2, &out), "{mode:?} {profile:?}: other profile");
            let mut q = p.clone();
            q.mode = if mode == Mode::Hashed { Mode::Raw } else { Mode::Hashed };
            let mut req2 = req.clone();
            req2.plugins[0].params = q.encode();
            assert!(!w.ok(&req2, &out), "{mode:?}: other mode");
        }
    }
}

#[test]
fn bound_to_nonce_audience_issuer_and_disclosure() {
    for mode in MODES {
        let w = world_for(mode);
        let (req, out) = w.honest(mode);
        assert!(w.ok(&req, &out));
        let mut r = req.clone();
        r.nonce[0] ^= 1;
        assert!(!w.ok(&r, &out));
        let mut r = req.clone();
        r.audience = b"evil.example".to_vec();
        assert!(!w.ok(&r, &out));
        let mut r = req.clone();
        r.credentials[0].disclose = vec![];
        assert!(!w.ok(&r, &out));
        let other =
            Issuer::new(schema(mode, 96), vec![Box::new(P256KeyHandler::new(vec![w.man.public_key()], mode))]).unwrap();
        let mut r = req.clone();
        r.credentials[0].issuer_pk = other.params.pk.clone();
        assert!(verifier().verify(std::slice::from_ref(&other.params), &r, &out, None, None).is_err());
        // disclosed attribute value changed (same length)
        let pe = parse(&out, &w.issuers(), &req).unwrap();
        let start = pe.credentials[0].bbs_range.0 - 4 - 2; // u32 len + the 2-byte value before the BBS proof
        let mut x = out.clone();
        x[start] ^= 1;
        assert!(!w.ok(&req, &x));
    }
}

#[test]
fn replace_qprime_signature_and_high_s() {
    let w = world_for(Mode::Raw);
    let (req, out) = w.honest(Mode::Raw);
    let sg = plugin_segments(&w, &req, &out);
    let q = p256x::decode_point(&cd_ecdsa_pop::device::RawSigner::public_key(&w.dev).unwrap()).unwrap();
    let other_q = p256x::encode(&(q * Scalar::random(&mut OsRng)));
    assert!(!w.ok(&req, &put(&out, sg.point, &other_q)));
    let r = p256x::scalar_from_canonical(out[sg.r.0..sg.r.1].try_into().unwrap()).unwrap();
    let s = p256x::scalar_from_canonical(out[sg.s.0..sg.s.1].try_into().unwrap()).unwrap();
    assert!(matches!(w.reject(&req, &put(&out, sg.r, &p256x::scalar_to_be(&(r + Scalar::ONE)))), Error::Reject(_)));
    assert!(matches!(w.reject(&req, &put(&out, sg.s, &p256x::scalar_to_be(&(-s)))), Error::Decode(_)), "high s");
    // hashed mode: another K
    let w = world_for(Mode::Hashed);
    let (req, out) = w.honest(Mode::Hashed);
    let sg = plugin_segments(&w, &req, &out);
    assert!(!w.ok(&req, &put(&out, sg.point, &other_q)));
}

#[test]
fn swap_limb_commitments() {
    for mode in MODES {
        let w = world_for(mode);
        let (req, out) = w.honest(mode);
        let sg = plugin_segments(&w, &req, &out);
        let t0 = out[sg.t[0].0..sg.t[0].1].to_vec();
        let t1 = out[sg.t[1].0..sg.t[1].1].to_vec();
        assert!(!w.ok(&req, &put(&put(&out, sg.t[0], &t1), sg.t[1], &t0)));
        // swap BLS commitments inside the BBS proof
        let pe = parse(&out, &w.issuers(), &req).unwrap();
        let mut p = octets_to_proof(&pe.credentials[0].bbs_proof).unwrap();
        p.commitments.swap(0, 1);
        let nb = proof_to_octets(&p).unwrap();
        assert!(!w.ok(&req, &put(&out, pe.credentials[0].bbs_range, &nb)));
    }
}

#[test]
fn splice_two_credentials() {
    for mode in MODES {
        let w = world_for(mode);
        let (dev_b, cred_b) = w.other_credential("Bobb"); // same attribute lengths as Alice
        cred_b.verify().unwrap();
        let req = w.request(mode);
        let out_a = present_with(&req, &w.cred, &w.dev, mode, None).unwrap();
        let out_b = present_with(&req, &cred_b, &dev_b, mode, None).unwrap();
        assert!(w.ok(&req, &out_b));
        let pa = parse(&out_a, &w.issuers(), &req).unwrap();
        let pb = parse(&out_b, &w.issuers(), &req).unwrap();
        // B's whole plugin proof inside A's presentation
        assert_eq!(out_a.len(), out_b.len());
        assert!(!w.ok(&req, &put(&out_a, pa.plugin_ranges[0], &out_b[pb.plugin_ranges[0].0..pb.plugin_ranges[0].1])));
        // B's BBS proof with A's plugin proof
        assert!(!w.ok(
            &req,
            &put(
                &out_a,
                pa.credentials[0].bbs_range,
                &out_b[pb.credentials[0].bbs_range.0..pb.credentials[0].bbs_range.1]
            )
        ));
        let (sa, sb) = (plugin_segments(&w, &req, &out_a), plugin_segments(&w, &req, &out_b));
        assert!(!w.ok(&req, &put(&out_a, sa.sm, &out_b[sb.sm.0..sb.sm.1])));
        assert!(!w.ok(&req, &put(&out_a, sa.point, &out_b[sb.point.0..sb.point.1])));
        let tr_a = (sa.tr[0].0, sa.tr.last().unwrap().1);
        assert!(!w.ok(&req, &put(&out_a, tr_a, &out_b[sb.tr[0].0..sb.tr.last().unwrap().1])));
        assert!(!w.ok(&req, &put(&out_a, sa.oc, &out_b[sb.oc.0..sb.oc.1])));
    }
}

#[test]
fn flip_each_section_rejected() {
    for mode in MODES {
        let w = world_for(mode);
        let (req, out) = w.honest(mode);
        let sg = plugin_segments(&w, &req, &out);
        let pe = parse(&out, &w.issuers(), &req).unwrap();
        let mut secs: Vec<(String, (usize, usize))> = vec![
            ("envelope magic".into(), (0, 5)),
            ("bbs".into(), pe.credentials[0].bbs_range),
            ("plugin magic".into(), sg.magic),
            ("nh".into(), sg.nh),
            ("point".into(), sg.point),
            ("oc".into(), sg.oc),
            ("sm".into(), sg.sm),
        ];
        if mode == Mode::Raw {
            secs.push(("r".into(), sg.r));
            secs.push(("s".into(), sg.s));
        } else {
            secs.push(("link".into(), sg.link));
        }
        for (j, t) in sg.t.iter().enumerate() {
            secs.push((format!("t{j}"), *t));
        }
        for (j, t) in sg.tr.iter().enumerate() {
            secs.push((format!("tr{j}"), *t));
        }
        for (name, (a, b)) in secs {
            for pos in [a, (a + b) / 2, b - 1] {
                let mut x = out.clone();
                x[pos] ^= 0x01;
                assert!(!w.ok(&req, &x), "{mode:?}: flip in {name} at {pos} accepted");
            }
        }
        for k in (0..SM_ROUNDS).step_by(8) {
            let mut x = out.clone();
            x[sg.sm.0 + k * SM_ROUND_BYTES + SM_FIRST_BYTES + 40] ^= 1;
            assert!(!w.ok(&req, &x), "{mode:?}: sm round {k}");
        }
    }
}

#[test]
fn parse_range_rejections() {
    let w = world_for(Mode::Raw);
    let (req, out) = w.honest(Mode::Raw);
    let sg = plugin_segments(&w, &req, &out);
    let p: [u8; 32] =
        num_bigint::BigUint::parse_bytes(P256_P_HEX.as_bytes(), 16).unwrap().to_bytes_be().try_into().unwrap();
    let r_bls: [u8; 32] =
        num_bigint::BigUint::parse_bytes(BLS_R_HEX.as_bytes(), 16).unwrap().to_bytes_be().try_into().unwrap();
    let params = EcdsaParams::decode(&req.plugins[0].params).unwrap();
    let z = sg.tr_z[0];
    let zb = z.1 - z.0;
    let s1 = (z.1, z.1 + 32);
    let s2 = (s1.1, s1.1 + 32);
    let r0 = sg.sm.0;
    let alpha = (r0 + SM_FIRST_BYTES, r0 + SM_FIRST_BYTES + 32);
    let rr0 = (alpha.1, alpha.1 + 32);
    let z0 = (alpha.1 + 64, alpha.1 + 96);
    let mut big_x = [0xffu8; 33];
    big_x[0] = 2;
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("r=0", put(&out, sg.r, &[0u8; 32])),
        ("r=n", put(&out, sg.r, &n_bytes())),
        ("s=0", put(&out, sg.s, &[0u8; 32])),
        ("z=0", put(&out, z, &vec![0u8; zb])),
        (
            "z=z_lo-1",
            put(&out, z, &{
                let b = Bounds::new(w.limb_bits, &params.transfer);
                let v = (b.z_lo - 1u32).to_bytes_be();
                let mut o = vec![0u8; zb - v.len()];
                o.extend(v);
                o
            }),
        ),
        ("oc z=p", put(&out, (sg.oc.0 + 9 * 33, sg.oc.0 + 9 * 33 + 32), &p)),
        ("oc C2 x>=pT", put(&out, (sg.oc.0, sg.oc.0 + 33), &big_x)),
        ("s1=r", put(&out, s1, &r_bls)),
        ("s2=p", put(&out, s2, &p)),
        ("alpha=0", put(&out, alpha, &[0u8; 32])),
        ("alpha=n", put(&out, alpha, &n_bytes())),
        ("rr=p", put(&out, rr0, &p)),
        ("z0=p", put(&out, z0, &p)),
        ("T x>=pT", put(&out, sg.t[0], &big_x)),
        ("Q' identity", put(&out, sg.point, &[0u8; 33])),
        ("trailing", [out.as_slice(), &[0u8]].concat()),
        ("truncated", out[..out.len() - 1].to_vec()),
    ];
    for (name, b) in cases {
        let e = w.reject(&req, &b);
        assert!(matches!(e, Error::Decode(_)), "{name}: {e}");
    }
    // U1 = identity: SM points are decoded after the cheaper checks, so the
    // full verifier rejects earlier (M′ changes); the decoder rejects it too.
    let x = put(&out, (r0 + 11 * 33, r0 + 12 * 33), &[0u8; 33]);
    assert!(!w.ok(&req, &x));
    let (pe, _, view) = env_and_view(&w, &req, &x);
    let pr = raw::parse(&pe.plugin_proofs[0], &view, &params).unwrap();
    assert!(matches!(decode_sm_points(&pr.common.sm_ann_bytes, SM_ROUNDS, Default::default()), Err(Error::Decode(_))));
    // SM round count != 128
    let mut x = out.clone();
    x[sg.sm.0 - 1] = 127;
    assert!(matches!(w.reject(&req, &x), Error::Decode(_)));
}

#[test]
fn issuance_checks() {
    let w = world_for(Mode::Hashed);
    w.cred.verify().unwrap();
    let pubk = w.dev.public_key().unwrap();
    let (dev_b, att_b) = w.man.provision(Mode::Hashed, false);
    // attestation for another key
    assert!(w.iss.issue(&values(&pubk, &att_b, "A")).is_err());
    // off-curve key (if the flipped encoding is not a point)
    let mut off = dev_b.public_key().unwrap();
    off[32] ^= 1;
    if p256x::decode_point(&off).is_err() {
        assert!(w.iss.issue(&values(&off, &att_b, "A")).is_err());
    }
    // untrusted manufacturer
    let other_man = Manufacturer::new();
    let (dev_c, att_c) = other_man.provision(Mode::Hashed, false);
    assert!(w.iss.issue(&values(&dev_c.public_key().unwrap(), &att_c, "A")).is_err(), "untrusted manufacturer");
    // the committed key is the device key
    let (_, input) = slot_and_input(&w.cred);
    let limbs: Vec<u128> =
        input.messages.iter().map(|m| bbs_cd_plugin::issuer::scalar_to_u128(&m.value).unwrap()).collect();
    assert_eq!(p256x::encode(&p256x::point_from_limbs(&limbs, 96).unwrap()), pubk);
}

#[test]
fn slot_and_signer_mismatch_refused() {
    let w = world_for(Mode::Hashed);
    let req = w.request(Mode::Hashed);
    // slot prepared for other parameters
    let (cslot, input) = slot_and_input(&w.cred);
    let other = EcdsaParams { profile: PROFILE_SEPARATE_PA.to_vec(), ..w.params(Mode::Hashed) };
    let pslot = cd_ecdsa_pop::prepare(&input, &other, 2, Default::default(), &mut OsRng).unwrap();
    let prover = EcdsaPopProver::new(pslot, Signer::Hash(&w.dev));
    assert!(bbs_cd_plugin::envelope::present(&req, &[&w.cred], vec![cslot], vec![Box::new(prover)], &mut OsRng, None)
        .is_err());
    // signer for the other mode
    let (cslot, input) = slot_and_input(&w.cred);
    let pslot = cd_ecdsa_pop::prepare(&input, &w.params(Mode::Hashed), 2, Default::default(), &mut OsRng).unwrap();
    let prover = EcdsaPopProver::new(pslot, Signer::Raw(&w.dev));
    assert!(bbs_cd_plugin::envelope::present(&req, &[&w.cred], vec![cslot], vec![Box::new(prover)], &mut OsRng, None)
        .is_err());
    // a plugin slot prepared for another credential slot's commitments
    let (cslot, _) = slot_and_input(&w.cred);
    let (_, input2) = slot_and_input(&w.cred);
    let pslot = cd_ecdsa_pop::prepare(&input2, &w.params(Mode::Hashed), 2, Default::default(), &mut OsRng).unwrap();
    let prover = EcdsaPopProver::new(pslot, Signer::Hash(&w.dev));
    let e = bbs_cd_plugin::envelope::present(&req, &[&w.cred], vec![cslot], vec![Box::new(prover)], &mut OsRng, None)
        .unwrap_err();
    assert!(e.to_string().contains("other commitments"), "{e}");
}

#[test]
fn raw_mode_can_be_refused_by_policy() {
    let w = world_for(Mode::Raw);
    let (req, out) = w.honest(Mode::Raw);
    let strict = bbs_cd_plugin::envelope::Verifier::new()
        .register(Box::new(cd_ecdsa_pop::EcdsaPopVerifier { allow_raw: false, ..Default::default() }));
    assert!(strict.verify(&w.issuers(), &req, &out, None, None).is_err());
    assert!(w.ok(&req, &out));
}

/// Composition counterpart of F-1, end to end (raw mode): a holder WITH
/// device access commits (Tom side) to an OFF-CURVE pair and answers all SM
/// rounds with F-1 forgeries.  The SM section verifies on its own; the
/// presentation is rejected at the transfer (the D_j bind the issuer-signed
/// real limbs), and the on-curve proof independently fails.
#[test]
fn offcurve_commitment_cannot_be_linked() {
    let w = world_for(Mode::Raw);
    let lb = w.limb_bits;
    let req = w.request(Mode::Raw);
    let params = w.params(Mode::Raw);
    let (cslot, input) = slot_and_input(&w.cred);
    let mut link: KeyLink =
        cd_ecdsa_pop::common::prepare_link(&input, &params, 4, Default::default(), &mut OsRng).unwrap();
    let a = Scalar::random(&mut OsRng);
    let c = a.invert().unwrap();
    let qp = link.q * a;
    let omega = c * Scalar::from(2u64).invert().unwrap();
    let u = qp * omega;
    let v = qp * (omega - c);
    let (vx, vy) = p256x::coords_fr(&v);
    let t = fr_rand(&mut OsRng);
    let xq = t * t - vx - vx;
    let yq = vy + t * (xq - vx);
    let fake = p256x::limbs_of_coords(&fr_to_be(&xq), &fr_to_be(&yq), lb);
    let tpts: Vec<_> = fake.iter().zip(&link.rho).map(|(m, r)| tom::commit(Fr::from(*m), *r)).collect();
    link.t_bytes = tpts.iter().map(|p| tom::encode(p, true)).collect();
    link.limbs = fake;
    let rq = fold_fr(&link.rho, lb);
    let cq = (tom::commit(xq, rq.0), tom::commit(yq, rq.1));
    assert_eq!(cq, fold(&tpts, lb));
    link.rq = rq;
    link.cq = cq;
    let rounds: Vec<SmRound> = (0..SM_ROUNDS)
        .map(|_| {
            let ru = (fr_rand(&mut OsRng), fr_rand(&mut OsRng));
            let rv = (fr_rand(&mut OsRng), fr_rand(&mut OsRng));
            let cu = commit_point(&u, ru);
            let cv = commit_point(&v, rv);
            let cc = [cq.0, cq.1, cv.0, cv.1, cu.0, cu.1];
            let blinds = [rq.0, rq.1, rv.0, rv.1, ru.0, ru.1];
            let st =
                pa_prepare_with_slope((xq, yq), (vx, vy), p256x::coords_fr(&u), t, &blinds, &cc, &mut OsRng).unwrap();
            SmRound::new(omega, omega - c, ru, rv, cu, cv, st)
        })
        .collect();
    link.oncurve = cd_tom256::oncurve::oncurve_prepare(xq, yq, rq.0, rq.1, &cq.0, &cq.1, &mut OsRng);
    link.oc_first_bytes = link.oncurve.first.iter().flat_map(|p| tom::encode(p, true)).collect();
    let sm_ann_bytes = encode_sm_first(&rounds);
    let slot = RawSlot { link, a, c, qp, qp33: p256x::encode(&qp), rounds, sm_ann_bytes };
    let prover = EcdsaPopProver::new(EcdsaSlot::Raw(slot), Signer::Raw(&w.dev));
    let out = bbs_cd_plugin::envelope::present(&req, &[&w.cred], vec![cslot], vec![Box::new(prover)], &mut OsRng, None)
        .unwrap();
    let e = w.reject(&req, &out);
    assert!(e.to_string().starts_with("transfer"), "{e}");
    let (pe, env, view) = env_and_view(&w, &req, &out);
    let proof = &pe.plugin_proofs[0];
    let pr = raw::parse(proof, &view, &params).unwrap();
    let (m, bits) = raw::recompute_challenges(&env, &view, &req.plugins[0].params, proof).unwrap();
    let cq_pub = fold(&pr.common.t, lb);
    // the on-curve proof for the off-curve pair fails on its own
    assert!(!cd_tom256::oncurve::oncurve_verify(
        &cq_pub.0,
        &cq_pub.1,
        &pr.common.oc_first,
        oc_challenge(&m).unwrap(),
        &pr.common.oc_z
    ));
    // the SM section alone is accepted (F-1)
    let first = decode_sm_points(&pr.common.sm_ann_bytes, SM_ROUNDS, Default::default()).unwrap();
    for i in 0..SM_ROUNDS {
        let e = Fr::from(bits[i] as u64);
        assert!(sm_verify_round(&pr.qp, cq_pub, &first[i], &pr.common.sm_resp[i], bits[i], e), "round {i}");
    }
}

#[test]
fn no_stable_fields_across_presentations() {
    for mode in MODES {
        let w = world_for(mode);
        let (r1, o1) = w.honest(mode);
        let (r2, o2) = w.honest(mode);
        let (s1, s2) = (plugin_segments(&w, &r1, &o1), plugin_segments(&w, &r2, &o2));
        assert_ne!(o1[s1.point.0..s1.point.1], o2[s2.point.0..s2.point.1]);
        for j in 0..s1.t.len() {
            assert_ne!(o1[s1.t[j].0..s1.t[j].1], o2[s2.t[j].0..s2.t[j].1]);
        }
        let p1 = parse(&o1, &w.issuers(), &r1).unwrap();
        let p2 = parse(&o2, &w.issuers(), &r2).unwrap();
        for j in 0..p1.credentials[0].bbs.commitments.len() {
            assert_ne!(p1.credentials[0].bbs.commitments[j], p2.credentials[0].bbs.commitments[j]);
        }
        // the device key itself never appears
        let q = w.dev.public_key().unwrap();
        assert!(!o1.windows(33).any(|x| x == q) && !o1.windows(32).any(|x| x == &q[1..]));
    }
}

#[test]
fn raw_signing_transformation() {
    // device signs c*h under Q; s' = a*s verifies on h under Q' = aQ
    use cd_ecdsa_pop::device::{ecdsa_verify_prehashed, SoftwareDevice};
    let dev = SoftwareDevice::new(Mode::Raw, false);
    let q = p256x::decode_point(&dev.public_key().unwrap()).unwrap();
    let a = Scalar::random(&mut OsRng);
    let c = a.invert().unwrap();
    let h = Scalar::random(&mut OsRng);
    let (r, s) = dev.sign_representative(&p256x::scalar_to_be(&(c * h))).unwrap();
    let mut s2 = a * s;
    if p256x::is_high_s(&s2) {
        s2 = -s2;
    }
    let qp = p256x::encode(&(q * a));
    assert!(ecdsa_verify_prehashed(&qp, &p256x::scalar_to_be(&h), &r, &s2));
    assert!(!ecdsa_verify_prehashed(&dev.public_key().unwrap(), &p256x::scalar_to_be(&h), &r, &s2));
    dev.revoke();
    assert!(dev.sign_representative(&[1u8; 32]).is_err());
}

#[test]
fn wrong_faulty_or_withdrawn_device_refused() {
    for mode in MODES {
        let w = world_for(mode);
        let req = w.request(mode);
        let other = cd_ecdsa_pop::SoftwareDevice::new(mode, false);
        let e = present_with(&req, &w.cred, &other, mode, None).unwrap_err();
        assert!(e.to_string().contains("does not match"), "{e}");
        assert!(other.log().is_empty(), "unrelated device must not be asked to sign");
    }
    // raw mode: a device returning an invalid raw signature is caught
    let w = world_for(Mode::Raw);
    let req = w.request(Mode::Raw);
    let faulty = ReplaySigner {
        sig: (Scalar::random(&mut OsRng), Scalar::random(&mut OsRng)),
        pubkey: w.dev.public_key().unwrap(),
        seen: std::sync::Mutex::new(vec![]),
    };
    let (cslot, input) = slot_and_input(&w.cred);
    let pslot = cd_ecdsa_pop::prepare(&input, &w.params(Mode::Raw), 2, Default::default(), &mut OsRng).unwrap();
    let prover = EcdsaPopProver::new(pslot, Signer::Raw(&faulty));
    let e = bbs_cd_plugin::envelope::present(&req, &[&w.cred], vec![cslot], vec![Box::new(prover)], &mut OsRng, None)
        .unwrap_err();
    assert!(matches!(e, Error::Prover(ref m) if m.contains("invalid signature")), "{e}");
    // withdrawn device
    for mode in MODES {
        let w = world_for(mode);
        let req = w.request(mode);
        w.dev.revoke();
        assert_eq!(present_with(&req, &w.cred, &w.dev, mode, None).unwrap_err(), Error::DeviceUnavailable);
    }
}
