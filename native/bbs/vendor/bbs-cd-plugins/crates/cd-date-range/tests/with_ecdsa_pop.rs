//! `date-range` next to `ecdsa-pop` in one presentation, and two
//! `date-range` proofs whose positions are swapped.
mod common;

use bbs_cd_plugin::envelope::{parse, prepare_credential, present, Verifier};
use bbs_cd_plugin::issuer::{AttrValue, Issuer};
use bbs_cd_plugin::par::Parallelism;
use bbs_cd_plugin::plugin::PluginProver;
use bbs_cd_plugin::request::{CredentialRequest, PluginRequest, Request};
use bbs_cd_plugin::schema::{AttributeSpec, Schema};
use cd_date_range::{
    date_input, DateHandler, DateRangeParams, DateRangeProver, DateRangeVerifier, PLUGIN_ID, TYPE_DATE,
};
use cd_ecdsa_pop::attestation::{key_input, Manufacturer, P256KeyHandler};
use cd_ecdsa_pop::{prepare, EcdsaParams, EcdsaPopProver, EcdsaPopVerifier, HashSigner, Mode, Signer};
use cd_tom256::config::n_limbs;
use common::*;
use rand_core::OsRng;

#[test]
fn device_binding_and_age_in_one_presentation() {
    let limb_bits = 96u8;
    let schema = Schema::new(
        "pid-test",
        vec![
            AttributeSpec::scalars("device_key", Mode::Hashed.key_type(), n_limbs(limb_bits) as u16, limb_bits as u16),
            AttributeSpec::scalars(ATTR, TYPE_DATE, 1, 17),
            AttributeSpec::octets("nationality"),
        ],
    )
    .unwrap();
    let man = Manufacturer::new();
    let iss = Issuer::new(
        schema,
        vec![Box::new(P256KeyHandler::new(vec![man.public_key()], Mode::Hashed)), Box::new(DateHandler)],
    )
    .unwrap();
    let (dev, att) = man.provision(Mode::Hashed, false);
    let cred = iss
        .issue(&[
            AttrValue::Input(key_input(&dev.hash_public_key().unwrap(), &att)),
            AttrValue::Input(date_input("1990-05-17")),
            AttrValue::Octets(b"SE".to_vec()),
        ])
        .unwrap();
    let ecdsa = EcdsaParams::hashed(limb_bits);
    let age = DateRangeParams::le(20081018);
    let req = Request::new(
        b"rp.example",
        vec![CredentialRequest::new(&iss.params, &["nationality"])],
        vec![
            PluginRequest {
                plugin_id: cd_ecdsa_pop::PLUGIN_ID.to_vec(),
                credential: 0,
                attribute: "device_key".into(),
                params: ecdsa.encode(),
            },
            PluginRequest {
                plugin_id: PLUGIN_ID.to_vec(),
                credential: 0,
                attribute: ATTR.into(),
                params: age.encode(),
            },
        ],
        &mut OsRng,
    );
    let slot = prepare_credential(&cred, &["device_key", ATTR], &mut OsRng).unwrap();
    let key = slot.committed_input(&cred, 0, "device_key").unwrap();
    let pslot = prepare(&key, &ecdsa, 4, Parallelism::Off, &mut OsRng).unwrap();
    let provers: Vec<Box<dyn PluginProver>> =
        vec![Box::new(EcdsaPopProver::new(pslot, Signer::Hash(&dev))), Box::new(DateRangeProver::new())];
    let b = present(&req, &[&cred], vec![slot], provers, &mut OsRng, None).unwrap();
    let verifier = Verifier::new().register(Box::new(EcdsaPopVerifier::new())).register(Box::new(DateRangeVerifier));
    let v = verifier.verify(std::slice::from_ref(&iss.params), &req, &b, None, None).unwrap();
    assert_eq!(v.outputs[1], age.encode());
    // a verifier without the date-range plugin refuses the request
    let only_pop = Verifier::new().register(Box::new(EcdsaPopVerifier::new()));
    assert!(only_pop.verify(std::slice::from_ref(&iss.params), &req, &b, None, None).is_err());
}

#[test]
fn swapped_plugin_positions_are_rejected() {
    // two date attributes, one date-range request each, equal proof lengths
    let schema = Schema::new(
        "two-dates",
        vec![AttributeSpec::scalars(ATTR, TYPE_DATE, 1, 17), AttributeSpec::scalars("issued_on", TYPE_DATE, 1, 17)],
    )
    .unwrap();
    let iss = Issuer::new(schema, vec![Box::new(DateHandler)]).unwrap();
    let cred =
        iss.issue(&[AttrValue::Input(date_input("1990-05-17")), AttrValue::Input(date_input("2020-01-02"))]).unwrap();
    let pr = |attr: &str, p: DateRangeParams| PluginRequest {
        plugin_id: PLUGIN_ID.to_vec(),
        credential: 0,
        attribute: attr.into(),
        params: p.encode(),
    };
    let req = Request::new(
        b"rp.example",
        vec![CredentialRequest::new(&iss.params, &[])],
        vec![pr(ATTR, DateRangeParams::le(20081018)), pr("issued_on", DateRangeParams::le(20081018 + 120000))],
        &mut OsRng,
    );
    let slot = prepare_credential(&cred, &[ATTR, "issued_on"], &mut OsRng).unwrap();
    let b = present(
        &req,
        &[&cred],
        vec![slot],
        vec![Box::new(DateRangeProver::new()), Box::new(DateRangeProver::new())],
        &mut OsRng,
        None,
    )
    .unwrap();
    let verifier = Verifier::new().register(Box::new(DateRangeVerifier));
    let issuers = vec![iss.params.clone()];
    verifier.verify(&issuers, &req, &b, None, None).unwrap();
    let pe = parse(&b, &issuers, &req).unwrap();
    let (r0, r1) = (pe.plugin_ranges[0], pe.plugin_ranges[1]);
    assert_eq!(r0.1 - r0.0, r1.1 - r1.0);
    let mut s = b.clone();
    s[r0.0..r0.1].copy_from_slice(&b[r1.0..r1.1]);
    s[r1.0..r1.1].copy_from_slice(&b[r0.0..r0.1]);
    assert!(verifier.verify(&issuers, &req, &s, None, None).is_err());
}
