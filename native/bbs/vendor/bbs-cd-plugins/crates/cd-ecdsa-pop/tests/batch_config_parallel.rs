//! Batch verification (rejects every single false linear equation with the
//! same reason as the individual verifier), verifier-controlled limb and
//! transfer configurations, and parallelism (same presentation and verdict
//! for every setting).
mod common;
use common::*;

use bbs_cd_plugin::envelope::{present, Verifier};
use bbs_cd_plugin::issuer::{Credential, Issuer};
use bbs_cd_plugin::par::{chunks, Parallelism};
use bbs_cd_plugin::plugin::PluginProver;
use bbs_cd_plugin::request::Request;
use cd_ecdsa_pop::attestation::P256KeyHandler;
use cd_ecdsa_pop::device::{HashSigner, SoftwareDevice};
use cd_ecdsa_pop::params::{PROFILE_SEPARATE_PA, PROFILE_SHARED_BIT};
use cd_ecdsa_pop::{hashed, raw, EcdsaParams, EcdsaPopProver, EcdsaPopVerifier, Mode, Signer, VerifyMode};
use cd_tom256::config::TransferConfig;
use cd_tom256::sm::{SM_FIRST_BYTES, SM_ROUND_BYTES};
use cd_tom256::tom::{self, fr_from_canonical, fr_to_be, gt, Fr, TomPoint};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn bump_fr(b: &mut [u8]) {
    let x: [u8; 32] = b[..32].try_into().unwrap();
    let v = fr_from_canonical(&x).unwrap() + Fr::from(1u64);
    b[..32].copy_from_slice(&fr_to_be(&v));
}

fn dec_fr(b: &mut [u8]) {
    let x: [u8; 32] = b[..32].try_into().unwrap();
    let v = fr_from_canonical(&x).unwrap() - Fr::from(1u64);
    b[..32].copy_from_slice(&fr_to_be(&v));
}

fn bump_point(b: &mut [u8]) {
    let p = tom::decode_point(&b[..33], true).unwrap() + TomPoint::from(gt());
    b[..33].copy_from_slice(&tom::encode(&p, true));
}

fn bump_bls(b: &mut [u8]) {
    let s = bbs_cd::primitives::scalar_from_octets(&b[..32]).unwrap() + bls12_381::Scalar::one();
    b[..32].copy_from_slice(&bbs_cd::primitives::scalar_to_octets(&s));
}

fn dec_bls(b: &mut [u8]) {
    let s = bbs_cd::primitives::scalar_from_octets(&b[..32]).unwrap() - bls12_381::Scalar::one();
    b[..32].copy_from_slice(&bbs_cd::primitives::scalar_to_octets(&s));
}

/// Both verifiers reject, with the same reason.
fn both_reject(w: &World, req: &Request, x: &[u8], what: &str) {
    let a = verifier_mode(VerifyMode::Batch).verify(&w.issuers(), req, x, None, None).expect_err(what).to_string();
    let b = verifier_mode(VerifyMode::Individual).verify(&w.issuers(), req, x, None, None).expect_err(what).to_string();
    assert_eq!(a, b, "{what}");
}

fn params(mode: Mode, cfg: TransferConfig, profile: &[u8]) -> EcdsaParams {
    EcdsaParams { mode, profile: profile.to_vec(), transfer: cfg }
}

fn run(w: &World, p: &EcdsaParams) -> (Request, Vec<u8>) {
    let req = w.request_with(p);
    let out = present_with(&req, &w.cred, &w.dev, p.mode, None).unwrap();
    plugin_segments(w, &req, &out); // exact size
    verifier().verify(&w.issuers(), &req, &out, None, None).unwrap();
    (req, out)
}

const CASES: [(u8, TransferConfig, &[u8]); 5] = [
    (96, TransferConfig::DEFAULT, PROFILE_SHARED_BIT),
    (96, TransferConfig::DEFAULT, PROFILE_SEPARATE_PA),
    (128, TransferConfig::L128_R2, PROFILE_SHARED_BIT),
    (64, TransferConfig::DEFAULT, PROFILE_SEPARATE_PA),
    (96, TransferConfig { reps: 2, b_c: 72, b_f: 16 }, PROFILE_SHARED_BIT),
];

#[test]
fn all_configurations_round_trip_batch_and_individual() {
    for (lb, cfg, prof) in CASES {
        for mode in MODES {
            let w = world_with(mode, lb, false);
            let (req, out) = run(&w, &params(mode, cfg, prof));
            for _ in 0..2 {
                verifier_mode(VerifyMode::Batch).verify(&w.issuers(), &req, &out, None, None).unwrap();
            }
            verifier_mode(VerifyMode::Individual).verify(&w.issuers(), &req, &out, None, None).unwrap();
        }
    }
}

/// Every SM response field, in rounds with b = 0 and b = 1, both profiles.
#[test]
fn single_sm_equation_tamper_rejected() {
    for mode in MODES {
        let w = world_for(mode);
        for prof in [PROFILE_SHARED_BIT, PROFILE_SEPARATE_PA] {
            let (req, out) = run(&w, &params(mode, TransferConfig::DEFAULT, prof));
            let sg = plugin_segments(&w, &req, &out);
            let (pe, env, view) = env_and_view(&w, &req, &out);
            let pb = &req.plugins[0].params;
            let (_, bits) = match mode {
                Mode::Raw => raw::recompute_challenges(&env, &view, pb, &pe.plugin_proofs[0]).unwrap(),
                Mode::Hashed => hashed::recompute_challenges(&env, &view, pb, &pe.plugin_proofs[0]).unwrap(),
            };
            let r0: Vec<usize> = (0..128).filter(|&i| bits[i] == 0).take(2).collect();
            let r1: Vec<usize> = (0..128).filter(|&i| bits[i] == 1).take(1).collect();
            for i in r0.into_iter().chain(r1) {
                let base = sg.sm.0 + i * SM_ROUND_BYTES;
                for k in 1..15 {
                    let mut x = out.clone();
                    bump_fr(&mut x[base + SM_FIRST_BYTES + 32 * k..]);
                    both_reject(&w, &req, &x, &format!("{mode:?} round {i} (b={}) field {k}", bits[i]));
                }
                let mut x = out.clone();
                let off = base + SM_FIRST_BYTES;
                let a = cd_tom256::p256x::scalar_from_canonical(&x[off..off + 32].try_into().unwrap()).unwrap()
                    + p256::Scalar::ONE;
                x[off..off + 32].copy_from_slice(&cd_tom256::p256x::scalar_to_be(&a));
                both_reject(&w, &req, &x, &format!("{mode:?} round {i} alpha"));
                let mut x = out.clone();
                bump_point(&mut x[base + 5 * 33..]);
                both_reject(&w, &req, &x, &format!("{mode:?} round {i} T1"));
            }
        }
    }
}

#[test]
fn single_oncurve_link_and_transfer_equation_tamper_rejected() {
    for (lb, cfg) in [(96, TransferConfig::DEFAULT), (128, TransferConfig::L128_R2)] {
        for mode in MODES {
            let w = world_with(mode, lb, false);
            let (req, out) = run(&w, &params(mode, cfg, PROFILE_SHARED_BIT));
            let sg = plugin_segments(&w, &req, &out);
            for k in 0..8 {
                let mut x = out.clone();
                bump_fr(&mut x[sg.oc.0 + 9 * 33 + 32 * k..]);
                both_reject(&w, &req, &x, &format!("{mode:?} on-curve z{k}"));
            }
            let zb = sg.tr_z[0].1 - sg.tr_z[0].0;
            for (e, (a, _)) in sg.tr.iter().enumerate() {
                let s1 = a + 81 + zb;
                let mut x = out.clone();
                bump_bls(&mut x[s1..]);
                both_reject(&w, &req, &x, &format!("{mode:?} transfer {e} s1"));
                let mut x = out.clone();
                bump_fr(&mut x[s1 + 32..]);
                both_reject(&w, &req, &x, &format!("{mode:?} transfer {e} s2"));
            }
            let mut x = out.clone();
            bump_point(&mut x[sg.t[0].0..]);
            both_reject(&w, &req, &x, &format!("{mode:?} T_0"));
            if mode == Mode::Hashed {
                // link responses (checked on their own in both paths)
                for k in 0..12 {
                    let mut x = out.clone();
                    bump_fr(&mut x[sg.link.0 + 12 * 33 + 32 * k..]);
                    both_reject(&w, &req, &x, &format!("link z{k}"));
                }
            }
        }
    }
}

/// Compensating pairs: two responses changed by +1 and −1 so that a batch
/// sharing one weight between the two equations would accept.
#[test]
fn compensating_pairs_across_equations_rejected() {
    for mode in MODES {
        let w = world_for(mode);
        let (req, out) = run(&w, &params(mode, TransferConfig { reps: 2, b_c: 72, b_f: 16 }, PROFILE_SHARED_BIT));
        let sg = plugin_segments(&w, &req, &out);
        let zb = sg.tr_z[0].1 - sg.tr_z[0].0;
        let s1 = |e: usize| sg.tr[e].0 + 81 + zb;
        for (a, b) in [(0usize, 1usize), (0, 2), (3, 5)] {
            let mut x = out.clone();
            bump_fr(&mut x[s1(a) + 32..]);
            dec_fr(&mut x[s1(b) + 32..]);
            both_reject(&w, &req, &x, &format!("{mode:?} s2 pair {a},{b}"));
            let mut x = out.clone();
            bump_bls(&mut x[s1(a)..]);
            dec_bls(&mut x[s1(b)..]);
            both_reject(&w, &req, &x, &format!("{mode:?} s1 pair {a},{b}"));
        }
        let mut x = out.clone();
        bump_fr(&mut x[s1(0) + 32..]);
        dec_fr(&mut x[sg.oc.0 + 9 * 33 + 32..]);
        both_reject(&w, &req, &x, &format!("{mode:?} transfer s2 vs on-curve z1"));
        for (i, j) in [(0usize, 1usize), (5, 100)] {
            let mut x = out.clone();
            bump_fr(&mut x[sg.sm.0 + i * SM_ROUND_BYTES + SM_FIRST_BYTES + 32..]);
            dec_fr(&mut x[sg.sm.0 + j * SM_ROUND_BYTES + SM_FIRST_BYTES + 32..]);
            both_reject(&w, &req, &x, &format!("{mode:?} rr0 rounds {i},{j}"));
        }
    }
}

/// The verdict does not depend on the verifier's RNG.
#[test]
fn verdict_is_rng_independent() {
    for mode in MODES {
        let w = world_for(mode);
        let (req, out) = w.honest(mode);
        let sg = plugin_segments(&w, &req, &out);
        let mut bad = out.clone();
        bump_fr(&mut bad[sg.oc.0 + 9 * 33..]);
        for seed in 0..3u64 {
            let mut r = ChaCha20Rng::seed_from_u64(seed);
            verifier().verify(&w.issuers(), &req, &out, Some(&mut r), None).unwrap();
            assert!(verifier().verify(&w.issuers(), &req, &bad, Some(&mut r), None).is_err());
        }
    }
}

/// The verifier fixes the transfer configuration; a proof made for another
/// configuration, or a weaker one, is rejected.
#[test]
fn transfer_configuration_is_verifier_controlled() {
    for mode in MODES {
        let w = world_with(mode, 128, false);
        let (req, out) = run(&w, &params(mode, TransferConfig::L128_R2, PROFILE_SHARED_BIT));
        let with = |cfg: TransferConfig| {
            let mut r = req.clone();
            r.plugins[0].params = params(mode, cfg, PROFILE_SHARED_BIT).encode();
            r
        };
        let e = verifier()
            .verify(&w.issuers(), &with(TransferConfig { reps: 1, b_c: 112, b_f: 8 }), &out, None, None)
            .unwrap_err();
        assert!(e.to_string().contains("transfer config"), "{e}");
        assert!(verifier()
            .verify(&w.issuers(), &with(TransferConfig { reps: 2, b_c: 120, b_f: 8 }), &out, None, None)
            .is_err());
        // incompatible with the limb size (128 + 128 + 16 > 254)
        assert!(verifier().verify(&w.issuers(), &with(TransferConfig::DEFAULT), &out, None, None).is_err());
    }
}

#[test]
fn schema_fixes_limb_size() {
    let w = world_for(Mode::Hashed);
    for lb in [64u8, 96, 128] {
        let s = schema(Mode::Hashed, lb);
        assert_eq!(s.range(KEY).unwrap().len(), 2 * 256usize.div_ceil(lb as usize));
    }
    // 80-bit limbs: the handler refuses to issue
    let bad = bbs_cd_plugin::schema::Schema::new(
        "pid-test",
        vec![bbs_cd_plugin::schema::AttributeSpec::scalars(KEY, cd_ecdsa_pop::TYPE_P256_KEY_HASHED, 8, 80)],
    )
    .unwrap();
    let iss = Issuer::new(bad, vec![Box::new(P256KeyHandler::new(vec![w.man.public_key()], Mode::Hashed))]).unwrap();
    let (dev, att) = w.man.provision(Mode::Hashed, false);
    assert!(iss
        .issue(&[bbs_cd_plugin::issuer::AttrValue::Input(cd_ecdsa_pop::attestation::key_input(
            &dev.hash_public_key().unwrap(),
            &att
        ))])
        .is_err());
    // the header (signed by the issuer) depends on the limb layout
    let a = Issuer::new(schema(Mode::Hashed, 96), vec![Box::new(P256KeyHandler::new(vec![], Mode::Hashed))]).unwrap();
    let mut b = a.params.clone();
    b.schema = schema(Mode::Hashed, 128);
    assert_ne!(a.params.header(), b.header());
}

const SETTINGS: [Parallelism; 5] =
    [Parallelism::Off, Parallelism::Max, Parallelism::Threads(1), Parallelism::Threads(3), Parallelism::Threads(64)];

#[test]
fn settings_and_chunking() {
    assert_eq!(Parallelism::parse("off"), Some(Parallelism::Off));
    assert_eq!(Parallelism::parse("max"), Some(Parallelism::Max));
    assert_eq!(Parallelism::parse("6"), Some(Parallelism::Threads(6)));
    assert_eq!(Parallelism::parse("x"), None);
    for p in SETTINGS {
        for len in [0usize, 1, 2, 5, 127, 128, 129] {
            let cs = chunks(p, len);
            let flat: Vec<usize> = cs.iter().flat_map(|r| r.clone()).collect();
            assert_eq!(flat, (0..len).collect::<Vec<_>>(), "{p:?} {len}");
        }
    }
}

/// Fixed seed and a deterministic (RFC 6979) device: the same presentation
/// for every prover setting, accepted for every verifier setting.
#[test]
fn identical_presentation_for_every_setting() {
    for (lb, cfg, prof) in
        [(96, TransferConfig::DEFAULT, PROFILE_SHARED_BIT), (128, TransferConfig::L128_R2, PROFILE_SEPARATE_PA)]
    {
        for mode in MODES {
            let w = world_with(mode, lb, true);
            let p = params(mode, cfg, prof);
            let req = w.request_with(&p);
            let mut outs = vec![];
            for par in SETTINGS {
                let mut rng = ChaCha20Rng::seed_from_u64(42);
                let cslot = bbs_cd_plugin::envelope::prepare_credential(&w.cred, &[KEY], &mut rng).unwrap();
                let input = cslot.committed_input(&w.cred, 0, KEY).unwrap();
                let pslot = cd_ecdsa_pop::prepare(&input, &p, 2, par, &mut rng).unwrap();
                let signer = if mode == Mode::Raw { Signer::Raw(&w.dev) } else { Signer::Hash(&w.dev) };
                let mut prover = EcdsaPopProver::new(pslot, signer);
                prover.parallelism = par;
                prover.nh = Some([7u8; 32]);
                let out = present(
                    &req,
                    &[&w.cred],
                    vec![cslot],
                    vec![Box::new(prover) as Box<dyn PluginProver>],
                    &mut rng,
                    None,
                )
                .unwrap();
                for vpar in SETTINGS {
                    let v = Verifier::new()
                        .register(Box::new(EcdsaPopVerifier { parallelism: vpar, ..Default::default() }));
                    v.verify(&w.issuers(), &req, &out, None, None).unwrap();
                }
                outs.push((par, out));
            }
            for (par, out) in &outs[1..] {
                assert_eq!(out, &outs[0].1, "{mode:?}: presentation differs for {par:?}");
            }
        }
    }
}

#[test]
fn same_verdict_for_every_setting() {
    for mode in MODES {
        let w = world_for(mode);
        let (req, out) = w.honest(mode);
        let sg = plugin_segments(&w, &req, &out);
        let mut cases: Vec<(String, Vec<u8>)> = vec![("honest".into(), out.clone())];
        for (name, at) in [
            ("on-curve z0", sg.oc.0 + 9 * 33),
            ("sm[0] rr0", sg.sm.0 + SM_FIRST_BYTES + 32),
            ("sm[64] z5", sg.sm.0 + 64 * SM_ROUND_BYTES + SM_FIRST_BYTES + 32 * 8),
            ("sm[127] z11", sg.sm.0 + 127 * SM_ROUND_BYTES + SM_FIRST_BYTES + 32 * 14),
        ] {
            let mut x = out.clone();
            bump_fr(&mut x[at..]);
            cases.push((name.into(), x));
        }
        let mut x = out.clone();
        bump_fr(&mut x[sg.sm.0 + 100 * SM_ROUND_BYTES + SM_FIRST_BYTES + 32 * 8..]);
        bump_fr(&mut x[sg.sm.0 + 5 * SM_ROUND_BYTES + SM_FIRST_BYTES + 32 * 8..]);
        cases.push(("sm[5] and sm[100]".into(), x));
        let mut x = out.clone();
        x[sg.sm.0 + 127 * SM_ROUND_BYTES + 5 * 33] = 0x05;
        cases.push(("sm[127] bad point".into(), x));
        for (name, x) in cases {
            let reference =
                verifier().verify(&w.issuers(), &req, &x, None, None).map(|_| ()).map_err(|e| e.to_string());
            for par in SETTINGS {
                let v = Verifier::new().register(Box::new(EcdsaPopVerifier { parallelism: par, ..Default::default() }));
                let got = v.verify(&w.issuers(), &req, &x, None, None).map(|_| ()).map_err(|e| e.to_string());
                assert_eq!(got, reference, "{mode:?} {name} with {par:?}");
            }
            let ind = verifier_mode(VerifyMode::Individual).verify(&w.issuers(), &req, &x, None, None).is_ok();
            assert_eq!(ind, reference.is_ok(), "{mode:?} {name}");
        }
    }
}

#[allow(dead_code)]
fn unused(_: &Credential, _: &SoftwareDevice) {}
