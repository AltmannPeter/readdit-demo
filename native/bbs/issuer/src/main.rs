//! bbs-issuer: issues Readdit's demo BBS credential (the `mms_zk` profile, `docs/mms_zk.md`).
//!
//! ```text
//! cargo run --release -p bbs-issuer -- \
//!   --wallet ../../app/wallet/demo-wallet.json --device-of 0 --birth-date 2011-03-14 \
//!   --out ../../app/wallet/demo-wallet-bbs.json --issuer-params demo/issuer-params.bin
//! ```
//!
//! - A new issuer key pair (BLS12-381) signs the profile's schema; `--issuer-params` receives
//!   the public part (`IssuerParams::encode`), the verifier's trust anchor.
//! - The device key is the one of holder `--device-of` in the mdoc wallet file, so a phone has
//!   one device key for both of its credentials. A demo manufacturer key, made for this run,
//!   attests it for hashed ECDSA (the `ecdsa-pop` issuance check).
//! - The pseudonym seed is new and random; the issuer would keep it on record
//!   (`nym-seed.issuer-known`). This tool keeps nothing.
//! - `--out` receives the wallet's BBS material: the credential and the device key.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bbs_cd_plugin::issuer::{AttrValue, Issuer};
use cd_date_range::{date_input, DateHandler, Ymd};
use cd_ecdsa_pop::attestation::{key_input, Manufacturer, P256KeyHandler};
use cd_ecdsa_pop::Mode;
use cd_pseudonym::{new_seed, NymSeedHandler};
use nym_bbs::credential::CredentialJson;
use nym_bbs::profile;
use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use serde_json::{json, Value};

fn arg(args: &[String], name: &str) -> String {
  args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned().unwrap_or_else(|| panic!("missing {name}; see the header of issuer/src/main.rs"))
}

fn main() {
  let args: Vec<String> = std::env::args().collect();
  let wallet_path = arg(&args, "--wallet");
  let device_of: usize = arg(&args, "--device-of").parse().expect("--device-of N");
  let birth_date = arg(&args, "--birth-date");
  let out = arg(&args, "--out");
  let params_out = arg(&args, "--issuer-params");
  assert!(Ymd::parse_iso(birth_date.as_bytes()).is_some_and(|d| d.is_calendar_date()), "--birth-date YYYY-MM-DD");

  // The device key of the mdoc holder.
  let wallet: Value = serde_json::from_str(&std::fs::read_to_string(&wallet_path).expect("read --wallet")).expect("--wallet is JSON");
  let jwk = wallet["holders"][device_of]["device_key"].clone();
  let d = URL_SAFE_NO_PAD.decode(jwk["d"].as_str().expect("device_key.d")).expect("device_key.d base64url");
  let key = SigningKey::from_slice(&d).expect("device_key.d is a P-256 scalar");
  let point = key.verifying_key().to_encoded_point(false);
  assert_eq!(URL_SAFE_NO_PAD.encode(point.x().unwrap()), jwk["x"].as_str().unwrap(), "device_key.x does not match d");
  assert_eq!(URL_SAFE_NO_PAD.encode(point.y().unwrap()), jwk["y"].as_str().unwrap(), "device_key.y does not match d");
  let device_pub: [u8; 33] = key.verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap();

  let manufacturer = Manufacturer::new();
  let attestation = manufacturer.attest(&device_pub, Mode::Hashed);
  let issuer = Issuer::new(
    profile::schema().expect("schema"),
    vec![
      Box::new(P256KeyHandler::new(vec![manufacturer.public_key()], Mode::Hashed)),
      Box::new(DateHandler),
      Box::new(NymSeedHandler),
    ],
  )
  .expect("issuer");
  let credential = issuer
    .issue(&[
      AttrValue::Input(key_input(&device_pub, &attestation)),
      AttrValue::Input(date_input(&birth_date)),
      AttrValue::Input(new_seed(&mut OsRng).to_vec()),
    ])
    .expect("issue");
  credential.verify().expect("the new credential verifies");

  let file = json!({
    "comment": "Demo holder material for the mocked SIROS ID wallet: the BBS nym_auth credential (mms_zk profile, docs/mms_zk.md), issued by native/bbs/issuer (bbs-issuer). The device key is the one of the mdoc holder it was issued for. Not secret: demo only.",
    "holders": [{
      "credential": CredentialJson::from_credential(&credential),
      "device_key": jwk,
      "device_of": device_of,
    }],
  });
  std::fs::write(&out, serde_json::to_string_pretty(&file).unwrap() + "\n").expect("write --out");
  std::fs::write(&params_out, credential.issuer.encode()).expect("write --issuer-params");
  eprintln!(
    "issued {} for a holder born {birth_date}; issuer key {}…; wrote {out} and {params_out}",
    profile::SCHEMA_ID,
    &hex::encode(&credential.issuer.pk)[..16]
  );
}
