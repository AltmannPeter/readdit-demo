//! One device key, one signing mode (review finding H-2).
//!
//! The attribute type (signed into the credential through the schema) and
//! the key attestation fix the key's single permitted usage; the device
//! refuses the other signing interface; verifier and prover refuse a request
//! for the other mode.
mod common;
use common::*;

use bbs_cd_plugin::issuer::Issuer;
use bbs_cd_plugin::plugin::PluginVerifier;
use cd_ecdsa_pop::attestation::{verify_attestation, P256KeyHandler};
use cd_ecdsa_pop::device::{HashSigner, RawSigner, SoftwareDevice};
use cd_ecdsa_pop::{prepare, EcdsaParams, EcdsaPopVerifier, Mode, TYPE_P256_KEY_HASHED, TYPE_P256_KEY_RAW};
use rand_core::OsRng;

fn other(mode: Mode) -> Mode {
    match mode {
        Mode::Hashed => Mode::Raw,
        Mode::Raw => Mode::Hashed,
    }
}

#[test]
fn key_types_are_distinct_and_mapped() {
    assert_ne!(TYPE_P256_KEY_HASHED, TYPE_P256_KEY_RAW);
    for mode in MODES {
        assert_eq!(Mode::for_key_type(mode.key_type()), Some(mode));
    }
    assert_eq!(Mode::for_key_type("p256-point-xy"), None);
    // the type is part of the signed header: same layout, different schema
    assert_ne!(schema(Mode::Hashed, 96).digest(), schema(Mode::Raw, 96).digest());
}

#[test]
fn device_refuses_the_other_interface() {
    let dev = SoftwareDevice::new(Mode::Hashed, false);
    assert!(dev.sign_message(b"m").is_ok());
    assert!(dev.sign_representative(&[7u8; 32]).is_err());
    assert!(dev.log().is_empty());
    let dev = SoftwareDevice::new(Mode::Raw, false);
    assert!(dev.sign_representative(&[7u8; 32]).is_ok());
    assert!(dev.sign_message(b"m").is_err());
}

#[test]
fn request_for_the_other_mode_is_refused() {
    for mode in MODES {
        let w = world_for(mode);
        let (_, spec, _) = w.iss.params.schema.find(KEY).unwrap();
        let v = EcdsaPopVerifier::new();
        v.check_request(spec, &w.params(mode).encode()).unwrap();
        let wrong = w.params(other(mode));
        let e = v.check_request(spec, &wrong.encode()).unwrap_err();
        assert!(e.to_string().contains("mode only"), "{e}");
        // the envelope verifier refuses the request before reading a proof
        let req = w.request(other(mode));
        assert!(verifier().check_request(&w.issuers(), &req).is_err());
        // the prover refuses to prepare for it
        let (_, input) = slot_and_input(&w.cred);
        assert!(prepare(&input, &wrong, 2, Default::default(), &mut OsRng).is_err());
        // and the honest flow fails without ever reaching the device
        assert!(present_with(&req, &w.cred, &w.dev, other(mode), None).is_err());
        assert!(w.dev.log().is_empty());
    }
}

#[test]
fn a_mode_proof_cannot_be_relabelled() {
    // an honest proof for the key's mode, presented against a request that
    // names the other mode, is refused (by the request check)
    for mode in MODES {
        let w = world_for(mode);
        let (req, out) = w.honest(mode);
        assert!(w.ok(&req, &out));
        let mut r2 = req.clone();
        r2.plugins[0].params = EcdsaParams { mode: other(mode), ..w.params(mode) }.encode();
        assert!(!w.ok(&r2, &out));
    }
}

#[test]
fn attestation_binds_the_usage() {
    let w = world_for(Mode::Hashed);
    for usage in MODES {
        let (dev, att) = w.man.provision(usage, false);
        let pk = dev.hash_public_key().unwrap();
        assert!(verify_attestation(&w.man.public_key(), &pk, &att, usage));
        assert!(!verify_attestation(&w.man.public_key(), &pk, &att, other(usage)));
        // relabelling the usage byte breaks the manufacturer's signature
        let mut relabelled = att.clone();
        let at = cd_ecdsa_pop::attestation::POLICY_SOFTWARE.len();
        relabelled[at] = other(usage) as u8;
        assert!(!verify_attestation(&w.man.public_key(), &pk, &relabelled, other(usage)));
        // an issuer for the other usage refuses this key
        let iss = Issuer::new(
            schema(other(usage), 96),
            vec![Box::new(P256KeyHandler::new(vec![w.man.public_key()], other(usage)))],
        )
        .unwrap();
        assert!(iss.issue(&values(&pk, &att, "A")).is_err());
        assert!(iss.issue(&values(&pk, &relabelled, "A")).is_err());
        // the matching issuer accepts it
        let iss = Issuer::new(schema(usage, 96), vec![Box::new(P256KeyHandler::new(vec![w.man.public_key()], usage))])
            .unwrap();
        assert!(iss.issue(&values(&pk, &att, "A")).is_ok());
    }
}

#[test]
fn issuer_needs_the_handler_for_the_schema_type() {
    let w = world_for(Mode::Hashed);
    // a raw-key schema with only a hashed-key handler cannot be set up
    assert!(Issuer::new(
        schema(Mode::Raw, 96),
        vec![Box::new(P256KeyHandler::new(vec![w.man.public_key()], Mode::Hashed))]
    )
    .is_err());
}
