//! The values both sides derive from the signed Request Object and the handover: what the
//! circuits are asked to show, and the public inputs the verifier computes itself (rulebook,
//! "Verification", step 3). The same rules as `native/vega` (nym-vega `request`): both prove the
//! same statement over the same credential.
//!
//! | Public input | From |
//! | --- | --- |
//! | E, C (`age_check.ge`, `age_check.le`) | the request's `age_check`, SPEC.md §3: `ge` d → E = d, `le` d → C = d; absent bounds → `0000-00-00` and `9999-12-31` |
//! | e2 (`session_transcript`) | the handover ([`crate::handover`]); the transcript also seeds Fiat–Shamir |
//! | verifier_input | SHA-256(client_id); `verifier_id_type` `x509_san_dns` makes client_id the verifier_id |
//! | docType and identifier | constants of the hash circuit: `eu.europa.ec.eudi.nym_auth.1`, `birth_date` |

use serde::Deserialize;
use serde_json::Value as Json;
use crate::circuit::DOC_TYPE;
use crate::dates::{self, Date};
use crate::error::Refusal;
use crate::handover::Handover;

/// The parts of the Request Object both sides read. Other members are ignored.
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
  pub meta: Json,
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
  pub circuit_zk: CircuitZkFormats,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CircuitZkFormats {
  pub circuit_id_values: Option<Vec<String>>,
  pub circuit_proof_system_values: Option<Vec<String>>,
}

/// The pseudonym configuration and verifier identity type the circuits implement.
pub const CONFIG: &str = "known-offender-matching-ssc";
pub const VERIFIER_ID_TYPE: &str = "x509_san_dns";
const CLIENT_ID_PREFIX: &str = "x509_san_dns:";

/// The age bounds of a request. Without a bound the circuit's range is open on that side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgeBounds {
  /// `ge`: born on or after. E.
  pub born_from: Option<Date>,
  /// `le`: born on or before. C.
  pub born_by: Option<Date>,
}

/// C when the request sets no `le`: no minimum age.
pub const NO_CUTOFF: Date = Date { year: 9999, month: 12, day: 31 };

impl AgeBounds {
  /// E as the hash circuit reads it: `0000-00-00` without a lower bound.
  pub fn earliest(&self) -> String {
    self.born_from.map_or_else(|| "0000-00-00".to_string(), |d| d.text())
  }

  /// C as the hash circuit reads it: `9999-12-31` without an upper bound.
  pub fn cutoff(&self) -> String {
    self.born_by.unwrap_or(NO_CUTOFF).text()
  }

  /// Whether a birth date lies in [E, C].
  pub fn holds(&self, birth: &Date) -> bool {
    self.born_from.is_none_or(|e| e.digits() <= birth.digits()) && birth.digits() <= self.born_by.unwrap_or(NO_CUTOFF).digits()
  }
}

/// What the presentation must show, and the verifier's own public inputs.
#[derive(Clone, Debug)]
pub struct Statement {
  pub client_id: String,
  /// SHA-256(client_id).
  pub verifier_input: [u8; 32],
  /// SessionTranscript, encoded.
  pub session_transcript: Vec<u8>,
  /// e2 = SHA-256(Sig_structure over DeviceAuthenticationBytes).
  pub challenge: [u8; 32],
  pub age: AgeBounds,
  /// The `return` handle of the pseudonym.
  pub nym_handle: String,
  /// The `return` handle of the age check, when one is requested.
  pub age_handle: Option<String>,
  /// The circuit ids and proof systems the request offers (None: any).
  pub offered_circuits: Option<Vec<String>>,
  pub offered_systems: Option<Vec<String>>,
}

impl Statement {
  /// The `return` handles, in the order of `req`.
  pub fn handles(&self) -> Vec<&str> {
    let mut handles = vec![self.nym_handle.as_str()];
    handles.extend(self.age_handle.as_deref());
    handles
  }
}

fn param_str<'a>(params: &'a serde_json::Map<String, Json>, key: &str) -> Result<Option<&'a str>, Refusal> {
  match params.get(key) {
    None => Ok(None),
    Some(Json::String(s)) => Ok(Some(s)),
    Some(other) => Err(Refusal::unsupported_request(format!("{key} is not a string: {other}"))),
  }
}

/// The statement of `credential_query_id` in `request`, bound to `handover`. Refuses what the
/// rulebook makes unsatisfiable independently of the holder's data, and what this circuit cannot
/// prove.
pub fn statement(
  request: &RequestObject,
  credential_query_id: &str,
  handover: &Handover,
) -> Result<Statement, Refusal> {
  if handover.client_id != request.client_id
    || handover.nonce != request.nonce
    || handover.response_uri != request.response_uri
  {
    return Err(Refusal::bad_request("the handover does not match the request (client_id, nonce, response_uri)"));
  }
  let q = request
    .dcql_query
    .credentials
    .iter()
    .find(|q| q.id == credential_query_id)
    .ok_or_else(|| Refusal::unsupported_request(format!("no credential query {credential_query_id}")))?;
  if q.format != "circuit_zk" {
    return Err(Refusal::unsupported_request(format!("format {} is not circuit_zk", q.format)));
  }
  let doctype = q.meta.get("doctype_value").and_then(Json::as_str);
  let meta_keys = q.meta.as_object().map_or(0, |m| m.len());
  if doctype != Some(DOC_TYPE) || meta_keys != 1 {
    return Err(Refusal::unsupported_request(format!("meta must hold exactly doctype_value {DOC_TYPE}")));
  }
  if q.require_cryptographic_holder_binding == Some(false) {
    return Err(Refusal::unsupported_request("require_cryptographic_holder_binding is false"));
  }
  if q.req.is_empty() {
    return Err(Refusal::unsupported_request("req is empty"));
  }

  let mut nym_handle = None;
  let mut age = None;
  let mut handles = Vec::new();
  for r in &q.req {
    if handles.contains(&r.handle.as_str()) {
      return Err(Refusal::unsupported_request(format!("return handle {} is not unique", r.handle)));
    }
    handles.push(r.handle.as_str());
    match r.id.as_str() {
      "pseudonym-v1-sha256" => {
        if nym_handle.is_some() {
          return Err(Refusal::unsupported_request("more than one pseudonym-v1-sha256 item"));
        }
        if let Some(k) = r.params.keys().find(|k| !["config", "verifier_id_type", "verifier_context"].contains(&k.as_str())) {
          return Err(Refusal::unsupported_request(format!("unknown pseudonym parameter {k}")));
        }
        let config = param_str(&r.params, "config")?;
        if config != Some(CONFIG) {
          return Err(Refusal::unsupported_config(format!("config {config:?}: these circuits implement {CONFIG}")));
        }
        if param_str(&r.params, "verifier_context")?.is_some() {
          return Err(Refusal::unsupported_request("verifier_context is not allowed for this configuration"));
        }
        let id_type = param_str(&r.params, "verifier_id_type")?;
        if id_type != Some(VERIFIER_ID_TYPE) {
          return Err(Refusal::unsupported_request(format!("verifier_id_type {id_type:?}: these circuits take {VERIFIER_ID_TYPE}")));
        }
        if !request.client_id.starts_with(CLIENT_ID_PREFIX) || request.client_id.len() == CLIENT_ID_PREFIX.len() {
          return Err(Refusal::unsupported_request("verifier_id_type x509_san_dns needs an x509_san_dns client_id"));
        }
        nym_handle = Some(r.handle.clone());
      }
      "age_check" => {
        if age.is_some() {
          return Err(Refusal::unsupported_request("more than one age_check item"));
        }
        if let Some(k) = r.params.keys().find(|k| *k != "ge" && *k != "le") {
          return Err(Refusal::unsupported_request(format!("unknown age_check parameter {k}")));
        }
        let parse = |key: &str| -> Result<Option<Date>, Refusal> {
          param_str(&r.params, key)?
            .map(|s| dates::date(s).map_err(|e| Refusal::unsupported_request(format!("age_check.{key}: {e}"))))
            .transpose()
        };
        let bounds = AgeBounds { born_from: parse("ge")?, born_by: parse("le")? };
        match (bounds.born_from, bounds.born_by) {
          (None, None) => return Err(Refusal::unsupported_request("age_check has neither ge nor le")),
          (Some(ge), Some(le)) if dates::days_between(&ge, &le) + 1 < 365 => {
            return Err(Refusal::unsupported_request("age_check: le − ge + 1 is below 365 days"));
          }
          _ => {}
        }
        age = Some((r.handle.clone(), bounds));
      }
      other => return Err(Refusal::unsupported_function(format!("function {other}"))),
    }
  }
  // The hash circuit always reveals a pseudonym, so it proves only requests that ask for one.
  let nym_handle = nym_handle.ok_or_else(|| Refusal::unsupported_request("these circuits need a pseudonym-v1-sha256 item"))?;

  let session_transcript = handover.session_transcript().map_err(Refusal::bad_request)?;
  let formats = &request.client_metadata.vp_formats_supported.circuit_zk;
  Ok(Statement {
    client_id: request.client_id.clone(),
    verifier_input: crate::sha256(request.client_id.as_bytes()),
    challenge: crate::handover::challenge_digest(&session_transcript, DOC_TYPE),
    session_transcript,
    age: age.as_ref().map_or(AgeBounds { born_from: None, born_by: None }, |(_, b)| *b),
    nym_handle,
    age_handle: age.map(|(h, _)| h),
    offered_circuits: formats.circuit_id_values.clone(),
    offered_systems: formats.circuit_proof_system_values.clone(),
  })
}

#[cfg(test)]
mod tests {
  use super::*;

  /// SPEC.md §3, the `age_check` mapping table, for the bounds the rulebook defines (`ge`, `le`,
  /// absent): an independent statement of E and C.
  #[test]
  fn age_check_mapping_spec_table() {
    let cases = [
      (Some("2008-10-14"), None, "2008-10-14", "9999-12-31"),
      (None, Some("2013-10-13"), "0000-00-00", "2013-10-13"),
      (Some("2008-10-14"), Some("2013-10-13"), "2008-10-14", "2013-10-13"),
    ];
    for (ge, le, earliest, cutoff) in cases {
      let mut params = serde_json::Map::new();
      if let Some(ge) = ge {
        params.insert("ge".into(), Json::String(ge.into()));
      }
      if let Some(le) = le {
        params.insert("le".into(), Json::String(le.into()));
      }
      let request: RequestObject = serde_json::from_value(serde_json::json!({
        "client_id": "x509_san_dns:readdit.example", "nonce": "n", "response_uri": "https://r/x",
        "dcql_query": { "credentials": [{ "id": "q", "format": "circuit_zk",
          "meta": { "doctype_value": DOC_TYPE },
          "req": [
            { "id": "pseudonym-v1-sha256", "return": "nym", "params": { "config": CONFIG, "verifier_id_type": "x509_san_dns" } },
            { "id": "age_check", "return": "age", "params": params }
          ] }] },
        "client_metadata": { "vp_formats_supported": { "circuit_zk": {} } }
      }))
      .expect("request");
      let handover = Handover {
        client_id: request.client_id.clone(),
        nonce: "n".into(),
        response_uri: "https://r/x".into(),
        jwk_thumbprint: None,
      };
      let s = statement(&request, "q", &handover).expect("statement");
      assert_eq!((s.age.earliest().as_str(), s.age.cutoff().as_str()), (earliest, cutoff));
    }
  }
}
