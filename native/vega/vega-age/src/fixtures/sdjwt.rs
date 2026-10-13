//! A test PID as an SD-JWT VC.

use super::{EcdsaSignature, ISSUED, KeyPair, point_with_x, salt};
use crate::gadgets::base64::encode;
use crate::gadgets::p256::PublicKey;
use crate::presentation::{Date, Time};
use crate::table::sha256;

/// The type of the EU-wide PID.
pub const PID_TYPE: &str = "urn:eudi:pid:1";

/// The issuer's identifier in the test payloads.
pub const ISSUER: &str = "https://pid-issuer.example";

/// The claims of a test payload besides the digests and the device key.
#[derive(Clone, Copy, Debug)]
pub struct Claims<'a> {
  pub iss: &'a str,
  /// The start and the end of validity, each optional as SD-JWT VC makes them.
  pub nbf: Option<Time>,
  pub exp: Option<Time>,
  pub vct: &'a str,
}

impl Claims<'static> {
  /// The claims of the test PID, valid from its issuance until `exp`.
  pub fn pid(exp: Time) -> Self {
    Claims { iss: ISSUER, nbf: Some(ISSUED), exp: Some(exp), vct: PID_TYPE }
  }
}

/// An issued SD-JWT: the JWS signing input, the signature, and the disclosures by claim name.
#[derive(Clone, Debug)]
pub struct SdJwt {
  pub signing_input: Vec<u8>,
  pub signature: EcdsaSignature,
  pub disclosures: Vec<(String, Vec<u8>)>,
}

impl SdJwt {
  /// The disclosure of a claim.
  pub fn disclosure(&self, name: &str) -> &[u8] {
    let (_, bytes) = self.disclosures.iter().find(|(claim, _)| claim == name).expect("a claim");
    bytes
  }
}

/// A disclosure: the base64url encoding of the JSON array of a salt, a claim name and a claim
/// value (RFC 9901, clause 4.2.1). With `spaced`, a space follows each comma.
pub fn disclosure(salt: &str, name: &str, value: &str, spaced: bool) -> Vec<u8> {
  let comma = if spaced { ", " } else { "," };
  let json = format!("[\"{salt}\"{comma}\"{name}\"{comma}{value}]");
  encode(json.as_bytes()).into_bytes()
}

/// The claims of the test PID, with their values as JSON.
pub fn claims(birth_date: &Date) -> Vec<(&'static str, String)> {
  vec![
    ("family_name", "\"Mustermann\"".to_string()),
    ("given_name", "\"Erika\"".to_string()),
    ("birthdate", format!("\"{}\"", birth_date.text())),
    ("place_of_birth", "{\"locality\":\"Berlin\"}".to_string()),
    ("nationalities", "[\"DE\"]".to_string()),
    ("age_equal_or_over", "{\"18\":true}".to_string()),
    ("issuing_authority", "\"Test PID Issuer\"".to_string()),
    ("issuing_country", "\"DE\"".to_string()),
  ]
}

/// The disclosures of the test PID, each with its own salt.
pub fn disclosures(birth_date: &Date, spaced: bool) -> Vec<(String, Vec<u8>)> {
  claims(birth_date)
    .into_iter()
    .map(|(name, value)| {
      let salt = encode(&salt(&format!("sd-jwt salt {name}")));
      (name.to_string(), disclosure(&salt, name, &value, spaced))
    })
    .collect()
}

/// Issues an SD-JWT with `claims`. The payload lists each disclosure's digest in `_sd` and binds
/// the device key in `cnf.jwk`. The signing input is the one a JWS signs (RFC 7515, clause 5.1).
pub fn issue(
  issuer: &KeyPair,
  device_key: &PublicKey,
  claims: &Claims,
  disclosures: Vec<(String, Vec<u8>)>,
) -> SdJwt {
  let digests: Vec<String> =
    disclosures.iter().map(|(_, d)| format!("\"{}\"", encode(&sha256(d)))).collect();
  let header = r#"{"alg":"ES256","typ":"dc+sd-jwt"}"#;
  let mut times = format!("\"iat\":{}", ISSUED.seconds_since_1970());
  for (key, time) in [("nbf", claims.nbf), ("exp", claims.exp)] {
    if let Some(time) = time {
      times += &format!(",\"{key}\":{}", time.seconds_since_1970());
    }
  }
  let payload = format!(
    concat!(
      r#"{{"iss":"{}",{},"vct":"{}","#,
      r#""_sd":[{}],"_sd_alg":"sha-256","#,
      r#""cnf":{{"jwk":{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}}}}}"#,
    ),
    claims.iss,
    times,
    claims.vct,
    digests.join(","),
    encode(&device_key.x),
    encode(&device_key.y),
  );
  let signing_input = format!("{}.{}", encode(header.as_bytes()), encode(payload.as_bytes()));
  let signature = issuer.sign(signing_input.as_bytes());
  SdJwt { signing_input: signing_input.into_bytes(), signature, disclosures }
}

/// The planted-key attempt. The holder makes up a birthdate disclosure the issuer never signs,
/// and asks for a device key whose x-coordinate is that disclosure's digest. Such a point has
/// no known private key. Returns the forged disclosure and the device key.
pub fn planted_key(forged_birth_date: &Date) -> (Vec<u8>, PublicKey) {
  (0u64..)
    .find_map(|attempt| {
      let salt = encode(&salt(&format!("planted salt {attempt}")));
      let value = format!("\"{}\"", forged_birth_date.text());
      let forged = disclosure(&salt, "birthdate", &value, false);
      point_with_x(&sha256(&forged)).map(|key| (forged, key))
    })
    .expect("half of all x-coordinates lie on the curve")
}
