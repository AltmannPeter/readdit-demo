//! Honest presentations, the pseudonym's properties, parameters, the seed
//! handler and the verifier-input rules.
mod common;

use bbs_cd_plugin::envelope::Verifier;
use bbs_cd_plugin::issuer::AttrHandler;
use bbs_cd_plugin::schema::{AttributeSpec, ScalarsSpec};
use bbs_cd_plugin::Error;
use cd_pseudonym::{
    pseudonym_for, NymSeedHandler, PseudonymParams, PseudonymVerifier, CONFIG_KNOWN_OFFENDER_MATCHING_SSC, PROOF_LEN,
    TYPE_NYM_SEED_ISSUER_KNOWN,
};
use common::*;

fn nym(w: &World, rp: &[u8]) -> Vec<u8> {
    let req = w.request(rp);
    let b = w.present(&req, rp).unwrap();
    let v = w.verify(&req, &b).unwrap();
    assert_eq!(v.disclosed[0], vec![("nationality".to_string(), b"SE".to_vec())]);
    v.outputs[0].clone()
}

#[test]
fn stable_per_relying_party_and_different_across() {
    let w = world();
    let a1 = nym(&w, RP_A);
    let a2 = nym(&w, RP_A);
    let b = nym(&w, RP_B);
    assert_eq!(a1.len(), 48);
    assert_eq!(a1, a2, "same relying party, same pseudonym");
    assert_ne!(a1, b, "different relying parties, different pseudonyms");
    // another holder at the same relying party
    let other = issue(&w.iss, &cd_pseudonym::new_seed(&mut rand_core::OsRng));
    let req = w.request(RP_A);
    let bytes = present_cred(&other, &req, Box::new(cd_pseudonym::PseudonymProver::new(RP_A))).unwrap();
    assert_ne!(w.verify(&req, &bytes).unwrap().outputs[0], a1);
}

#[test]
fn issuer_can_recompute_the_pseudonym() {
    let w = world();
    for rp in [RP_A, RP_B] {
        let p = PseudonymParams::known_offender_matching(rp);
        assert_eq!(pseudonym_for(&w.seed, &p).unwrap().to_vec(), nym(&w, rp));
    }
}

#[test]
fn reissued_credential_with_the_same_seed_keeps_the_pseudonym() {
    let w = world();
    let again = issue(&w.iss, &w.seed);
    let req = w.request(RP_A);
    let b = present_cred(&again, &req, Box::new(cd_pseudonym::PseudonymProver::new(RP_A))).unwrap();
    assert_eq!(w.verify(&req, &b).unwrap().outputs[0], nym(&w, RP_A));
}

#[test]
fn holder_refuses_an_identifier_other_than_the_certificate() {
    let w = world();
    // the request asks for RP_B's pseudonym, the access certificate says RP_A
    let req = w.request(RP_B);
    assert!(matches!(w.present(&req, RP_A), Err(Error::Prover(_))));
}

#[test]
fn verifier_bound_to_its_own_identifier() {
    let w = world();
    let req = w.request(RP_A);
    let b = w.present(&req, RP_A).unwrap();
    let mine = Verifier::new().register(Box::new(PseudonymVerifier::for_verifier(RP_A)));
    mine.verify(&w.issuers(), &req, &b, None, None).unwrap();
    let other = Verifier::new().register(Box::new(PseudonymVerifier::for_verifier(RP_B)));
    assert!(other.check_request(&w.issuers(), &req).is_err());
    assert!(other.verify(&w.issuers(), &req, &b, None, None).is_err());
}

#[test]
fn proof_size() {
    let w = world();
    let req = w.request(RP_A);
    let b = w.present(&req, RP_A).unwrap();
    let pe = bbs_cd_plugin::envelope::parse(&b, &w.issuers(), &req).unwrap();
    let r = pe.plugin_ranges[0];
    assert_eq!(r.1 - r.0, PROOF_LEN);
    assert_eq!(PROOF_LEN, 148);
}

#[test]
fn params_encoding_and_checks() {
    let p = PseudonymParams::known_offender_matching(RP_A);
    let cfg = CONFIG_KNOWN_OFFENDER_MATCHING_SSC.as_bytes();
    assert_eq!(p.encode(), [&[cfg.len() as u8][..], cfg, &[RP_A.len() as u8], RP_A].concat());
    assert_eq!(PseudonymParams::decode(&p.encode()).unwrap(), p);
    let w = world();
    let enc = |c: &[u8], v: &[u8]| [&[c.len() as u8][..], c, &[v.len() as u8], v].concat();
    for bad in [
        vec![],
        enc(b"other-config", RP_A),
        enc(b"", RP_A),
        enc(cfg, b""),
        [&enc(cfg, RP_A)[..], &[0]].concat(),
        enc(cfg, RP_A)[..10].to_vec(),
    ] {
        assert!(PseudonymParams::decode(&bad).is_err(), "{bad:?}");
        let req = request_raw(&w.iss, bad.clone());
        assert!(verifier().check_request(&w.issuers(), &req).is_err(), "{bad:?}");
        assert!(w.present(&req, RP_A).is_err());
    }
    // the longest identifier
    let long = vec![b'x'; 255];
    let req = request_raw(&w.iss, enc(cfg, &long));
    let b = w.present(&req, &long).unwrap();
    w.verify(&req, &b).unwrap();
}

#[test]
fn seed_handler_and_attribute_type() {
    let h = NymSeedHandler;
    let spec = |count, bits| ScalarsSpec { type_id: TYPE_NYM_SEED_ISSUER_KNOWN.into(), count, bits, blind: false };
    let seed = cd_pseudonym::new_seed(&mut rand_core::OsRng);
    assert!(h.encode(&spec(1, 255), &seed).is_ok());
    assert!(h.encode(&spec(1, 255), &[0u8; 32]).is_err(), "zero seed");
    assert!(h.encode(&spec(1, 255), &[0xff; 32]).is_err(), "not below r");
    assert!(h.encode(&spec(1, 255), &seed[..31]).is_err());
    assert!(h.encode(&spec(2, 255), &seed).is_err());
    assert!(h.encode(&spec(1, 128), &seed).is_err());
    let p = PseudonymParams::known_offender_matching(RP_A).encode();
    let v = PseudonymVerifier::any();
    use bbs_cd_plugin::plugin::PluginVerifier;
    assert!(v.check_request(&AttributeSpec::scalars("s", TYPE_NYM_SEED_ISSUER_KNOWN, 1, 255), &p).is_ok());
    for bad in [
        AttributeSpec::octets("s"),
        AttributeSpec::scalars("s", "nym-seed.private", 1, 255),
        AttributeSpec::scalars("s", TYPE_NYM_SEED_ISSUER_KNOWN, 2, 255),
        AttributeSpec::scalars("s", TYPE_NYM_SEED_ISSUER_KNOWN, 1, 128),
    ] {
        assert!(v.check_request(&bad, &p).is_err(), "{bad:?}");
    }
}
