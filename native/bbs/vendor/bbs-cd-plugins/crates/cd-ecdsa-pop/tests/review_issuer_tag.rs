mod common;
use common::{present_with, schema, values, verifier, KEY};

use bbs_cd_plugin::issuer::Issuer;
use bbs_cd_plugin::request::{CredentialRequest, PluginRequest, Request};
use bbs_cd_plugin::schema::Schema;
use cd_ecdsa_pop::attestation::{Manufacturer, P256KeyHandler};
use cd_ecdsa_pop::device::HashSigner;
use cd_ecdsa_pop::{EcdsaParams, Mode, PLUGIN_ID};
use rand_core::OsRng;

#[test]
fn colluding_issuer_can_tag_holders_with_distinct_schema_ids() {
    let manufacturer = Manufacturer::new();
    let attrs = schema(Mode::Hashed, 96).attributes().to_vec();
    let make_issuer = |id: &str| {
        Issuer::from_seed(
            Schema::new(id, attrs.clone()).unwrap(),
            vec![Box::new(P256KeyHandler::new(vec![manufacturer.public_key()], Mode::Hashed))],
            &[23; 32],
        )
        .unwrap()
    };
    let issuer_a = make_issuer("pid-holder-a");
    let issuer_b = make_issuer("pid-holder-b");
    assert_eq!(issuer_a.params.pk, issuer_b.params.pk, "same named issuer key");
    assert_ne!(issuer_a.params.schema.digest(), issuer_b.params.schema.digest());

    let (device_a, attestation_a) = manufacturer.provision(Mode::Hashed, false);
    let (device_b, attestation_b) = manufacturer.provision(Mode::Hashed, false);
    let credential_a = issuer_a.issue(&values(&device_a.hash_public_key().unwrap(), &attestation_a, "Alice")).unwrap();
    let credential_b = issuer_b.issue(&values(&device_b.hash_public_key().unwrap(), &attestation_b, "Bob")).unwrap();
    let params = EcdsaParams::hashed(96).encode();
    let request_for = |issuer: &Issuer| {
        Request::new(
            b"rp.example",
            vec![CredentialRequest::new(&issuer.params, &[])],
            vec![PluginRequest {
                plugin_id: PLUGIN_ID.to_vec(),
                credential: 0,
                attribute: KEY.into(),
                params: params.clone(),
            }],
            &mut OsRng,
        )
    };
    let request_a = request_for(&issuer_a);
    let request_b = request_for(&issuer_b);
    assert_ne!(request_a.credentials[0].schema_digest, request_b.credentials[0].schema_digest);

    let presentation_a = present_with(&request_a, &credential_a, &device_a, Mode::Hashed, None).unwrap();
    let presentation_b = present_with(&request_b, &credential_b, &device_b, Mode::Hashed, None).unwrap();
    let v = verifier();
    assert!(v.verify(std::slice::from_ref(&issuer_a.params), &request_a, &presentation_a, None, None).is_ok());
    assert!(v.verify(std::slice::from_ref(&issuer_b.params), &request_b, &presentation_b, None, None).is_ok());

    // A wallet with A's credential cannot answer B's tagged request, despite
    // the common issuer public key and the presence of device binding.
    assert!(present_with(&request_b, &credential_a, &device_a, Mode::Hashed, None).is_err());
}
