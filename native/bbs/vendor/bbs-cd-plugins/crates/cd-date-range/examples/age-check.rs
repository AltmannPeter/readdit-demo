//! Age check with device binding: one presentation that discloses the
//! nationality, proves possession of the device key (`ecdsa-pop`, hashed
//! mode) and proves "born on or before today minus 18 years" (`date-range`).
//!
//! cargo run --release -p cd-date-range --example age-check [-- YYYY-MM-DD]
//!
//! The optional argument is the holder's birth date (default 1990-05-17).
use std::time::{SystemTime, UNIX_EPOCH};

use bbs_cd_plugin::envelope::{prepare_credential, present, Verifier};
use bbs_cd_plugin::issuer::{AttrValue, Issuer};
use bbs_cd_plugin::par::Parallelism;
use bbs_cd_plugin::plugin::PluginProver;
use bbs_cd_plugin::request::{CredentialRequest, PluginRequest, Request};
use bbs_cd_plugin::schema::{AttributeSpec, Schema};
use cd_date_range::{
    date_input, DateHandler, DateRangeParams, DateRangeProver, DateRangeVerifier, Ymd, RECOMMENDED_BITS, TYPE_DATE,
};
use cd_ecdsa_pop::attestation::{key_input, Manufacturer, P256KeyHandler};
use cd_ecdsa_pop::device::HashSigner;
use cd_ecdsa_pop::{prepare, EcdsaParams, EcdsaPopProver, EcdsaPopVerifier, Mode, Signer, TYPE_P256_KEY_HASHED};
use cd_tom256::config::n_limbs;
use rand_core::OsRng;

/// Today's UTC date (days since 1970-01-01 to civil, H. Hinnant's algorithm).
fn today() -> Ymd {
    let days = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 86_400) as i64 + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    let y = (yoe + era * 400 + (m <= 2) as i64) as u16;
    Ymd::new(y, m, d).expect("a date after 1900")
}

fn main() -> bbs_cd_plugin::Result<()> {
    let born = std::env::args().nth(1).unwrap_or_else(|| "1990-05-17".into());
    // App start: build the date-range generator tables (~20 ms, once per process).
    cd_date_range::precompute();

    // Issuer: device key (hashed ECDSA only), birth date, two text attributes.
    let limb_bits = 96;
    let schema = Schema::new(
        "pid-demo",
        vec![
            AttributeSpec::scalars("device_key", TYPE_P256_KEY_HASHED, n_limbs(limb_bits) as u16, limb_bits as u16),
            AttributeSpec::octets("name"),
            AttributeSpec::scalars("birth_date", TYPE_DATE, 1, RECOMMENDED_BITS),
            AttributeSpec::octets("nationality"),
        ],
    )?;
    let manufacturer = Manufacturer::new();
    let issuer = Issuer::new(
        schema,
        vec![Box::new(P256KeyHandler::new(vec![manufacturer.public_key()], Mode::Hashed)), Box::new(DateHandler)],
    )?;
    let (device, attestation) = manufacturer.provision(Mode::Hashed, false);
    let cred = issuer.issue(&[
        AttrValue::Input(key_input(&device.hash_public_key()?, &attestation)),
        AttrValue::Octets(b"Alice".to_vec()),
        AttrValue::Input(date_input(&born)),
        AttrValue::Octets(b"SE".to_vec()),
    ])?;

    // Verifier: "at least 18 today" = born on or before today minus 18 years
    // (a day that doesn't exist, such as 02-29, is still a correct bound).
    let t = today();
    let cutoff = Ymd { year: t.year - 18, ..t };
    let age = DateRangeParams { ge: None, le: Some(cutoff) };
    let ecdsa = EcdsaParams::hashed(limb_bits);
    let request = Request::new(
        b"rp.example",
        vec![CredentialRequest::new(&issuer.params, &["nationality"])],
        vec![
            PluginRequest {
                plugin_id: cd_ecdsa_pop::PLUGIN_ID.to_vec(),
                credential: 0,
                attribute: "device_key".into(),
                params: ecdsa.encode(),
            },
            PluginRequest {
                plugin_id: cd_date_range::PLUGIN_ID.to_vec(),
                credential: 0,
                attribute: "birth_date".into(),
                params: age.encode(),
            },
        ],
        &mut OsRng,
    );
    println!("today {t}; verifier asks: {age}");

    // Holder: commit to the device key and the birth date, prepare ecdsa-pop
    // offline, then present.
    let slot = prepare_credential(&cred, &["device_key", "birth_date"], &mut OsRng)?;
    let key = slot.committed_input(&cred, 0, "device_key")?;
    let pop_slot = prepare(&key, &ecdsa, 4, Parallelism::Off, &mut OsRng)?;
    let provers: Vec<Box<dyn PluginProver>> =
        vec![Box::new(EcdsaPopProver::new(pop_slot, Signer::Hash(&device))), Box::new(DateRangeProver::new())];
    let presentation = match present(&request, &[&cred], vec![slot], provers, &mut OsRng, None) {
        Ok(p) => p,
        Err(e) => {
            println!("holder (born {born}) cannot answer: {e}");
            return Ok(());
        }
    };

    let verifier = Verifier::new().register(Box::new(EcdsaPopVerifier::new())).register(Box::new(DateRangeVerifier));
    let verified = verifier.verify(std::slice::from_ref(&issuer.params), &request, &presentation, None, None)?;
    for (name, value) in &verified.disclosed[0] {
        println!("disclosed {name} = {}", String::from_utf8_lossy(value));
    }
    println!("ecdsa-pop verified");
    println!("date-range verified: {}", DateRangeParams::decode(&verified.outputs[1])?);
    println!("presentation: {} bytes", presentation.len());
    Ok(())
}
