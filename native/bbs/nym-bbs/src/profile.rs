//! The `mms_zk` profile (`docs/mms_zk.md`): the credential schema, and the BBS request that both
//! sides derive from an OpenID4VP Request Object, its `mms_zk` credential query and the handover.
//!
//! | BBS request | From |
//! | --- | --- |
//! | audience | SHA-256(OpenID4VPHandoverInfoBytes): client_id, nonce, jwk_thumbprint, response_uri |
//! | nonce | the Request Object's `nonce`, as UTF-8 (16 to 64 bytes) |
//! | credentials | one: the issuer's public key and the schema digest; nothing disclosed |
//! | plugins | `ecdsa-pop/0.1` on `device_key` (hashed, 96-bit limbs); `pseudonym/0.1` on `nym_seed` (the req's configuration, verifier input = client_id); `date-range/0.1` on `birth_date` when `age_check` is asked |

use bbs_cd_plugin::issuer::IssuerParams;
use bbs_cd_plugin::request::{CredentialRequest, PluginRequest, Request};
use bbs_cd_plugin::schema::{AttributeSpec, Schema};
use cd_date_range::{DateRangeParams, Ymd, RECOMMENDED_BITS, TYPE_DATE};
use cd_ecdsa_pop::{EcdsaParams, TYPE_P256_KEY_HASHED};
use cd_pseudonym::{PseudonymParams, CONFIG_KNOWN_OFFENDER_MATCHING_SSC, TYPE_NYM_SEED_ISSUER_KNOWN};
use cd_tom256::config::n_limbs;
use serde::Deserialize;
use serde_json::Value as Json;
use sha2::Digest;

use crate::credential::FORMAT;
use crate::error::Refusal;

/// The registry's scheme id: this schema with these plugins (`shared/registry/circuits.ts`).
pub const SCHEME_ID: &str = "urn:mms:bbs-cd:nym_auth:v1";
/// The proof system: the bbs-cd-plugins framework on ETSI BBS committed disclosures v0.7.
pub const PROOF_SYSTEM: &str = "bbs-cd-plugins-v0.1";
/// The credential's schema id: the nym_auth attestation, BBS-encoded.
pub const SCHEMA_ID: &str = "eu.europa.ec.eudi.nym_auth.bbs.1";
pub const FUNCTION_PSEUDONYM: &str = "pseudonym-bbs-v1";
pub const FUNCTION_AGE: &str = "age_check";
pub const VERIFIER_ID_TYPE: &str = "x509_san_dns";
const CLIENT_ID_PREFIX: &str = "x509_san_dns:";

pub const DEVICE_KEY: &str = "device_key";
pub const BIRTH_DATE: &str = "birth_date";
pub const NYM_SEED: &str = "nym_seed";
/// Device-key limb size: 3 limbs per coordinate.
pub const LIMB_BITS: u8 = 96;

/// The schema: the device key (hashed ECDSA), the birth date (date-packed, 17 bits) and the
/// issuer-known pseudonym seed.
pub fn schema() -> bbs_cd_plugin::Result<Schema> {
  Schema::new(
    SCHEMA_ID,
    vec![
      AttributeSpec::scalars(DEVICE_KEY, TYPE_P256_KEY_HASHED, n_limbs(LIMB_BITS) as u16, LIMB_BITS as u16),
      AttributeSpec::scalars(BIRTH_DATE, TYPE_DATE, 1, RECOMMENDED_BITS),
      AttributeSpec::scalars(NYM_SEED, TYPE_NYM_SEED_ISSUER_KNOWN, 1, 255),
    ],
  )
}

// ---- the parts of the Request Object both sides read ----

#[derive(Clone, Debug, Deserialize)]
pub struct RequestObject {
  pub client_id: String,
  pub nonce: String,
  pub response_uri: String,
  pub dcql_query: DcqlQuery,
  pub client_metadata: ClientMetadata,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DcqlQuery {
  pub credentials: Vec<CredentialQuery>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CredentialQuery {
  pub id: String,
  pub format: String,
  #[serde(default)]
  pub meta: Json,
  #[serde(default)]
  pub req: Vec<ReqItem>,
  pub require_cryptographic_holder_binding: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReqItem {
  pub id: String,
  #[serde(rename = "return")]
  pub handle: String,
  #[serde(default)]
  pub params: serde_json::Map<String, Json>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ClientMetadata {
  pub vp_formats_supported: VpFormats,
}

#[derive(Clone, Debug, Deserialize)]
pub struct VpFormats {
  pub mms_zk: Option<MmsZkFormats>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct MmsZkFormats {
  pub scheme_id_values: Option<Vec<String>>,
  pub proof_system_values: Option<Vec<String>>,
}

/// The handover, as the verifier's session store holds it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct Handover {
  pub client_id: String,
  pub nonce: String,
  pub response_uri: String,
  pub jwk_thumbprint: Option<String>,
}

/// CBOR head of major type `major` with argument `n`.
fn cbor_head(out: &mut Vec<u8>, major: u8, n: u64) {
  let m = major << 5;
  match n {
    0..=23 => out.push(m | n as u8),
    24..=0xff => out.extend([m | 24, n as u8]),
    0x100..=0xffff => {
      out.push(m | 25);
      out.extend((n as u16).to_be_bytes());
    }
    0x1_0000..=0xffff_ffff => {
      out.push(m | 26);
      out.extend((n as u32).to_be_bytes());
    }
    _ => {
      out.push(m | 27);
      out.extend(n.to_be_bytes());
    }
  }
}

impl Handover {
  /// OpenID4VPHandoverInfoBytes = CBOR([client_id, nonce, jwk_thumbprint / null, response_uri])
  /// (OpenID4VP 1.0, B.2.6.1), the value the mdoc SessionTranscript hashes too.
  pub fn info_bytes(&self) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    cbor_head(&mut out, 4, 4);
    for s in [&self.client_id, &self.nonce] {
      cbor_head(&mut out, 3, s.len() as u64);
      out.extend(s.as_bytes());
    }
    match &self.jwk_thumbprint {
      None => out.push(0xf6),
      Some(t) => {
        let b = crate::unb64url("handover.jwk_thumbprint", t)?;
        if b.len() != 32 {
          return Err("handover.jwk_thumbprint is not 32 bytes".into());
        }
        cbor_head(&mut out, 2, 32);
        out.extend(b);
      }
    }
    cbor_head(&mut out, 3, self.response_uri.len() as u64);
    out.extend(self.response_uri.as_bytes());
    Ok(out)
  }

  /// The BBS request's audience: SHA-256(OpenID4VPHandoverInfoBytes).
  pub fn digest(&self) -> Result<[u8; 32], String> {
    Ok(sha2::Sha256::digest(self.info_bytes()?).into())
  }
}

/// What the presentation must show, as both sides derive it.
#[derive(Clone, Debug)]
pub struct Statement {
  pub request: Request,
  pub handover_digest: [u8; 32],
  /// The relying party's identifier: client_id (`x509_san_dns:<host>`).
  pub verifier_id: Vec<u8>,
  pub pseudonym: PseudonymParams,
  pub nym_handle: String,
  pub age: Option<DateRangeParams>,
  pub age_handle: Option<String>,
  /// Position of each plugin in `request.plugins`.
  pub index_pseudonym: usize,
  pub index_age: Option<usize>,
  /// The `return` handles, in req order.
  pub handles: Vec<String>,
}

fn iso_date(what: &str, v: &Json) -> Result<Ymd, Refusal> {
  let s = v.as_str().ok_or_else(|| Refusal::unsupported_request(format!("age_check.{what} is not a string")))?;
  let d = Ymd::parse_iso(s.as_bytes()).ok_or_else(|| Refusal::unsupported_request(format!("age_check.{what} {s} is not YYYY-MM-DD")))?;
  if !d.is_calendar_date() {
    return Err(Refusal::unsupported_request(format!("age_check.{what} {s} is not a calendar date")));
  }
  Ok(d)
}

/// The BBS request and what it must show, from the Request Object, the `mms_zk` query
/// `query_id`, the handover and the issuer's parameters.
pub fn statement(req: &RequestObject, query_id: &str, handover: &Handover, issuer: &IssuerParams) -> Result<Statement, Refusal> {
  if handover.client_id != req.client_id || handover.nonce != req.nonce || handover.response_uri != req.response_uri {
    return Err(Refusal::bad_request("the handover does not match the request"));
  }
  let q = req
    .dcql_query
    .credentials
    .iter()
    .find(|q| q.id == query_id)
    .ok_or_else(|| Refusal::bad_request(format!("no credential query {query_id}")))?;
  if q.format != FORMAT {
    return Err(Refusal::unsupported_request(format!("format {}, expected {FORMAT}", q.format)));
  }
  if q.meta.get("schema_id_value").and_then(Json::as_str) != Some(SCHEMA_ID) {
    return Err(Refusal::unsupported_request(format!("meta.schema_id_value is not {SCHEMA_ID}")));
  }
  if q.require_cryptographic_holder_binding == Some(false) {
    return Err(Refusal::unsupported_request("the scheme always binds the device key"));
  }
  let offer = req.client_metadata.vp_formats_supported.mms_zk.as_ref().ok_or_else(|| Refusal::unsupported_scheme("the request has no mms_zk metadata"))?;
  if offer.scheme_id_values.as_ref().is_some_and(|v| !v.iter().any(|s| s == SCHEME_ID))
    || offer.proof_system_values.as_ref().is_some_and(|v| !v.iter().any(|s| s == PROOF_SYSTEM))
  {
    return Err(Refusal::unsupported_scheme("the request does not offer this scheme"));
  }
  if !req.client_id.strip_prefix(CLIENT_ID_PREFIX).is_some_and(|h| !h.is_empty()) {
    return Err(Refusal::unsupported_request(format!("client_id {} is not x509_san_dns", req.client_id)));
  }
  if !(16..=64).contains(&req.nonce.len()) {
    return Err(Refusal::unsupported_request("nonce must be 16 to 64 bytes"));
  }

  let mut nym: Option<(String, String)> = None;
  let mut age: Option<(String, DateRangeParams)> = None;
  let mut handles = Vec::new();
  for r in &q.req {
    handles.push(r.handle.clone());
    match r.id.as_str() {
      FUNCTION_PSEUDONYM => {
        if nym.is_some() {
          return Err(Refusal::unsupported_request("more than one pseudonym in req"));
        }
        let config = r.params.get("config").and_then(Json::as_str).unwrap_or_default();
        if config != CONFIG_KNOWN_OFFENDER_MATCHING_SSC {
          return Err(Refusal::unsupported_config(format!("pseudonym configuration {config}")));
        }
        if r.params.get("verifier_id_type").and_then(Json::as_str) != Some(VERIFIER_ID_TYPE) {
          return Err(Refusal::unsupported_config(format!("{config} needs verifier_id_type {VERIFIER_ID_TYPE}")));
        }
        if r.params.keys().any(|k| k != "config" && k != "verifier_id_type") {
          return Err(Refusal::unsupported_config("unknown pseudonym parameter"));
        }
        nym = Some((r.handle.clone(), config.to_string()));
      }
      FUNCTION_AGE => {
        if age.is_some() {
          return Err(Refusal::unsupported_request("more than one age_check in req"));
        }
        if r.params.keys().any(|k| k != "ge" && k != "le") {
          return Err(Refusal::unsupported_request("age_check takes ge and le only"));
        }
        let ge = r.params.get("ge").map(|v| iso_date("ge", v)).transpose()?;
        let le = r.params.get("le").map(|v| iso_date("le", v)).transpose()?;
        if ge.is_none() && le.is_none() {
          return Err(Refusal::unsupported_request("age_check without ge or le"));
        }
        age = Some((r.handle.clone(), DateRangeParams { ge, le }));
      }
      other => return Err(Refusal::unsupported_function(format!("function {other}"))),
    }
  }
  let (nym_handle, config) = nym.ok_or_else(|| Refusal::unsupported_request(format!("the scheme always reveals a pseudonym; req has no {FUNCTION_PSEUDONYM}")))?;

  let verifier_id = req.client_id.as_bytes().to_vec();
  let pseudonym = PseudonymParams { config, verifier_input: verifier_id.clone() };
  let digest = handover.digest().map_err(Refusal::bad_request)?;
  let mut plugins = vec![
    PluginRequest { plugin_id: cd_ecdsa_pop::PLUGIN_ID.to_vec(), credential: 0, attribute: DEVICE_KEY.into(), params: EcdsaParams::hashed(LIMB_BITS).encode() },
    PluginRequest { plugin_id: cd_pseudonym::PLUGIN_ID.to_vec(), credential: 0, attribute: NYM_SEED.into(), params: pseudonym.encode() },
  ];
  let index_age = age.as_ref().map(|(_, p)| {
    plugins.push(PluginRequest { plugin_id: cd_date_range::PLUGIN_ID.to_vec(), credential: 0, attribute: BIRTH_DATE.into(), params: p.encode() });
    plugins.len() - 1
  });
  let request = Request {
    audience: digest.to_vec(),
    nonce: req.nonce.as_bytes().to_vec(),
    credentials: vec![CredentialRequest::new(issuer, &[])],
    plugins,
  };
  request.validate(std::slice::from_ref(issuer)).map_err(|e| Refusal::unsupported_request(e.to_string()))?;
  Ok(Statement {
    request,
    handover_digest: digest,
    verifier_id,
    pseudonym,
    nym_handle,
    age_handle: age.as_ref().map(|(h, _)| h.clone()),
    age: age.map(|(_, p)| p),
    index_pseudonym: 1,
    index_age,
    handles,
  })
}

/// The attributes the request commits, in schema order.
pub fn committed(s: &Statement) -> Vec<&'static str> {
  let mut v = vec![DEVICE_KEY];
  if s.age.is_some() {
    v.push(BIRTH_DATE);
  }
  v.push(NYM_SEED);
  v
}
