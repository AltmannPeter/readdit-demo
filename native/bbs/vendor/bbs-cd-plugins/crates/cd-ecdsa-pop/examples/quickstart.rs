//! Issue a credential with a device key, request a presentation that
//! discloses one attribute and proves possession of the key (hashed mode),
//! present it and verify it.
//!
//! cargo run --release -p cd-ecdsa-pop --example quickstart
use bbs_cd_plugin::envelope::{prepare_credential, present, Verifier};
use bbs_cd_plugin::issuer::{AttrValue, Issuer};
use bbs_cd_plugin::par::Parallelism;
use bbs_cd_plugin::plugin::PluginProver;
use bbs_cd_plugin::request::{CredentialRequest, PluginRequest, Request};
use bbs_cd_plugin::schema::{AttributeSpec, Schema};
use cd_ecdsa_pop::attestation::{key_input, Manufacturer, P256KeyHandler};
use cd_ecdsa_pop::device::HashSigner;
use cd_ecdsa_pop::{
    prepare, EcdsaParams, EcdsaPopProver, EcdsaPopVerifier, Mode, Signer, PLUGIN_ID, TYPE_P256_KEY_HASHED,
};
use cd_tom256::config::n_limbs;
use rand_core::OsRng;

fn main() -> bbs_cd_plugin::Result<()> {
    // Issuer: a schema with a committed device key (96-bit limbs) and two
    // text attributes.  The key type fixes its one permitted use (hashed
    // ECDSA-P256-SHA256); the key handler checks the (simulated) attestation
    // of the key and of that usage.
    let limb_bits = 96;
    let schema = Schema::new(
        "pid-demo",
        vec![
            AttributeSpec::scalars("device_key", TYPE_P256_KEY_HASHED, n_limbs(limb_bits) as u16, limb_bits as u16),
            AttributeSpec::octets("name"),
            AttributeSpec::octets("nationality"),
        ],
    )?;
    let manufacturer = Manufacturer::new();
    let issuer =
        Issuer::new(schema, vec![Box::new(P256KeyHandler::new(vec![manufacturer.public_key()], Mode::Hashed))])?;

    // Holder's secure element (simulated) and credential.
    let (device, attestation) = manufacturer.provision(Mode::Hashed, false);
    let cred = issuer.issue(&[
        AttrValue::Input(key_input(&device.hash_public_key()?, &attestation)),
        AttrValue::Octets(b"Alice".to_vec()),
        AttrValue::Octets(b"SE".to_vec()),
    ])?;

    // Verifier: disclose nationality, prove possession of device_key.
    let params = EcdsaParams::hashed(limb_bits);
    let request = Request::new(
        b"rp.example",
        vec![CredentialRequest::new(&issuer.params, &["nationality"])],
        vec![PluginRequest {
            plugin_id: PLUGIN_ID.to_vec(),
            credential: 0,
            attribute: "device_key".into(),
            params: params.encode(),
        }],
        &mut OsRng,
    );

    // Holder, offline: commitments and the plugin's prepared state.
    let slot = prepare_credential(&cred, &["device_key"], &mut OsRng)?;
    let input = slot.committed_input(&cred, 0, "device_key")?;
    let plugin_slot = prepare(&input, &params, 4, Parallelism::Off, &mut OsRng)?;

    // Holder, online: BBS proof, one device signature, plugin proof.
    let prover = EcdsaPopProver::new(plugin_slot, Signer::Hash(&device));
    let presentation =
        present(&request, &[&cred], vec![slot], vec![Box::new(prover) as Box<dyn PluginProver>], &mut OsRng, None)?;

    // Verifier.
    let verifier = Verifier::new().register(Box::new(EcdsaPopVerifier::new()));
    let verified = verifier.verify(std::slice::from_ref(&issuer.params), &request, &presentation, None, None)?;
    for (name, value) in &verified.disclosed[0] {
        println!("disclosed {name} = {}", String::from_utf8_lossy(value));
    }
    println!("ecdsa-pop verified; presentation is {} bytes", presentation.len());
    Ok(())
}
