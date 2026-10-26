//! One presentation with the BBS proof, `ecdsa-pop`, `date-range` and the
//! pseudonym on one credential.
use bbs_cd_plugin::envelope::{prepare_credential, present, Verifier};
use bbs_cd_plugin::issuer::{AttrValue, Issuer};
use bbs_cd_plugin::par::Parallelism;
use bbs_cd_plugin::plugin::PluginProver;
use bbs_cd_plugin::request::{CredentialRequest, PluginRequest, Request};
use bbs_cd_plugin::schema::{AttributeSpec, Schema};
use cd_date_range::{date_input, DateHandler, DateRangeParams, DateRangeProver, DateRangeVerifier, TYPE_DATE};
use cd_ecdsa_pop::attestation::{key_input, Manufacturer, P256KeyHandler};
use cd_ecdsa_pop::{prepare, EcdsaParams, EcdsaPopProver, EcdsaPopVerifier, HashSigner, Mode, Signer};
use cd_pseudonym::{
    new_seed, pseudonym_for, NymSeedHandler, PseudonymParams, PseudonymProver, PseudonymVerifier,
    TYPE_NYM_SEED_ISSUER_KNOWN,
};
use cd_tom256::config::n_limbs;
use rand_core::OsRng;

const RP: &[u8] = b"https://rp.example";

#[test]
fn device_binding_age_and_pseudonym_in_one_presentation() {
    let limb_bits = 96u8;
    let schema = Schema::new(
        "pid-full",
        vec![
            AttributeSpec::scalars("device_key", Mode::Hashed.key_type(), n_limbs(limb_bits) as u16, limb_bits as u16),
            AttributeSpec::scalars("birth_date", TYPE_DATE, 1, 17),
            AttributeSpec::scalars("nym_seed", TYPE_NYM_SEED_ISSUER_KNOWN, 1, 255),
            AttributeSpec::octets("nationality"),
        ],
    )
    .unwrap();
    let man = Manufacturer::new();
    let iss = Issuer::new(
        schema,
        vec![
            Box::new(P256KeyHandler::new(vec![man.public_key()], Mode::Hashed)),
            Box::new(DateHandler),
            Box::new(NymSeedHandler),
        ],
    )
    .unwrap();
    let (dev, att) = man.provision(Mode::Hashed, false);
    let seed = new_seed(&mut OsRng);
    let cred = iss
        .issue(&[
            AttrValue::Input(key_input(&dev.hash_public_key().unwrap(), &att)),
            AttrValue::Input(date_input("1990-05-17")),
            AttrValue::Input(seed.to_vec()),
            AttrValue::Octets(b"SE".to_vec()),
        ])
        .unwrap();
    let ecdsa = EcdsaParams::hashed(limb_bits);
    let age = DateRangeParams::le(20081018);
    let nym = PseudonymParams::known_offender_matching(RP);
    let pr = |id: &[u8], attr: &str, params: Vec<u8>| PluginRequest {
        plugin_id: id.to_vec(),
        credential: 0,
        attribute: attr.into(),
        params,
    };
    let req = Request::new(
        b"rp.example",
        vec![CredentialRequest::new(&iss.params, &["nationality"])],
        vec![
            pr(cd_ecdsa_pop::PLUGIN_ID, "device_key", ecdsa.encode()),
            pr(cd_date_range::PLUGIN_ID, "birth_date", age.encode()),
            pr(cd_pseudonym::PLUGIN_ID, "nym_seed", nym.encode()),
        ],
        &mut OsRng,
    );
    let slot = prepare_credential(&cred, &["device_key", "birth_date", "nym_seed"], &mut OsRng).unwrap();
    let key = slot.committed_input(&cred, 0, "device_key").unwrap();
    let pslot = prepare(&key, &ecdsa, 4, Parallelism::Off, &mut OsRng).unwrap();
    let provers: Vec<Box<dyn PluginProver>> = vec![
        Box::new(EcdsaPopProver::new(pslot, Signer::Hash(&dev))),
        Box::new(DateRangeProver::new()),
        Box::new(PseudonymProver::new(RP)),
    ];
    let b = present(&req, &[&cred], vec![slot], provers, &mut OsRng, None).unwrap();
    let verifier = Verifier::new()
        .register(Box::new(EcdsaPopVerifier::new()))
        .register(Box::new(DateRangeVerifier))
        .register(Box::new(PseudonymVerifier::for_verifier(RP)));
    let v = verifier.verify(std::slice::from_ref(&iss.params), &req, &b, None, None).unwrap();
    assert_eq!(v.outputs[1], age.encode());
    assert_eq!(v.outputs[2], pseudonym_for(&seed, &nym).unwrap().to_vec());
}
