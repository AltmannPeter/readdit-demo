//! The values both sides derive from the signed Request Object and the handover: what the
//! circuits are asked to show, and the public inputs the verifier computes itself (rulebook,
//! "Verification", step 3). The same rules as `native/vega` (nym-vega `request`): both prove the
//! same statement over the same credential.
//!
//! | Public input | From |
//! | --- | --- |
//! | E, C (`age_check.ge`, `age_check.le`) | the request's `age_check`, SPEC.md §3: `ge` d → E = d, `le` d → C = d; absent bounds → `0000-00-00` and `9999-12-31` |
//! | e2 (`session_transcript`) | the handover ([`crate::handover`]); the transcript also seeds Fiat–Shamir |
//! | verifier_input | SHA-256(verifier_id); the demo's trust framework fixes the `x509_san_dns` form, so verifier_id = client_id |
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
  #[serde(rename = "_req")]
  pub req: Vec<ReqItem>,
  pub require_cryptographic_holder_binding: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ReqItem {
  pub fn_id: String,
  /// Present for value functions; absent for assertions (v0.5's age_check).
  #[serde(rename = "return", default)]
  pub handle: Option<String>,
  #[serde(default)]
  pub params: serde_json::Map<String, Json>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ClientMetadata {
  pub vp_formats_supported: VpFormats,
}

#[derive(Clone, Debug, Deserialize)]
pub struct VpFormats {
  pub zkp_req: ZkpReqFormats,
}

/// `vp_formats_supported.zkp_req` (rulebook, "Metadata parameters").
#[derive(Clone, Debug, Deserialize)]
pub struct ZkpReqFormats {
  pub system_id_values: Option<Vec<String>>,
  pub proof_system_values: Option<Vec<String>>,
}

/// The pseudonym configuration and verifier identity type the circuits implement.
pub const CONFIG: &str = "known-offender-matching-ssc";
/// The pseudonym function version and PRF the circuit implements.
pub const VERSION: u64 = 1;
pub const PRF: &str = "sha-256";
/// The source format and the format of the credential query.
pub const SOURCE_FORMAT: &str = "mso_mdoc";
pub const FORMAT: &str = "zkp_req";
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
  /// The system ids and proof systems the request offers (None: any).
  pub offered_ids: Option<Vec<String>>,
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

/// The rulebook version a request is read under (the demo profile; `rulebook` in the input, "0.4"
/// when absent). v0.5: `age_check` is an assertion with a `range` in whole years, and both sides
/// compute E and C from it and the UTC date of `proof_time` ([`dates::range_bounds`]). v0.6: the
/// decoy-digest credential layout ([`crate::decoy`]), with v0.5's request and presentation rules.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Rulebook {
  #[default]
  V04,
  V05,
  V06,
}

impl Rulebook {
  pub fn parse(v: Option<&str>) -> Result<Rulebook, Refusal> {
    match v {
      None | Some("0.4") => Ok(Rulebook::V04),
      Some("0.5") => Ok(Rulebook::V05),
      Some("0.6") => Ok(Rulebook::V06),
      Some(other) => Err(Refusal::bad_request(format!("rulebook {other}: this build reads 0.4, 0.5 and 0.6"))),
    }
  }

  /// Whether `age_check` is v0.5's assertion with a `range` (v0.5 and v0.6).
  pub fn years_range(self) -> bool {
    matches!(self, Rulebook::V05 | Rulebook::V06)
  }
}

/// The statement of `credential_query_id` in `request`, bound to `handover`, under rulebook v0.4.
pub fn statement(request: &RequestObject, credential_query_id: &str, handover: &Handover) -> Result<Statement, Refusal> {
  statement_for(request, credential_query_id, handover, Rulebook::V04, None)
}

/// The statement of `credential_query_id` in `request`, bound to `handover`, read under
/// `rulebook`. `date`: D, the UTC date of `proof_time`, for a v0.5 age range (the prover's clock
/// when it proves, the presentation's `proof_time` when the verifier checks). Refuses what the
/// rulebook makes unsatisfiable independently of the holder's data, and what this circuit cannot
/// prove.
pub fn statement_for(
  request: &RequestObject,
  credential_query_id: &str,
  handover: &Handover,
  rulebook: Rulebook,
  date: Option<Date>,
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
  if q.format != FORMAT {
    return Err(Refusal::unsupported_request(format!("format {} is not {FORMAT}", q.format)));
  }
  let source = q.meta.get("source_format").and_then(Json::as_str);
  let doctype = q.meta.get("doctype_value").and_then(Json::as_str);
  let meta_keys = q.meta.as_object().map_or(0, |m| m.len());
  if source != Some(SOURCE_FORMAT) || doctype != Some(DOC_TYPE) || meta_keys != 2 {
    return Err(Refusal::unsupported_request(format!("meta must hold exactly source_format {SOURCE_FORMAT} and doctype_value {DOC_TYPE}")));
  }
  if q.require_cryptographic_holder_binding == Some(false) {
    return Err(Refusal::unsupported_request("require_cryptographic_holder_binding is false"));
  }
  if q.req.is_empty() {
    return Err(Refusal::unsupported_request("_req is empty"));
  }

  let mut nym_handle = None;
  let mut age = None;
  let mut handles = Vec::new();
  for r in &q.req {
    // pseudonym is a value function in both versions; age_check is one in v0.4 and an assertion
    // in v0.5.
    let value = r.fn_id != "age_check" || rulebook == Rulebook::V04;
    match (&r.handle, value) {
      (None, true) => return Err(Refusal::unsupported_request(format!("{} is a value function: return is required", r.fn_id))),
      (Some(_), false) => return Err(Refusal::unsupported_request(format!("{} is an assertion: return must not be present", r.fn_id))),
      (Some(h), true) => {
        if handles.contains(&h.as_str()) {
          return Err(Refusal::unsupported_request(format!("return handle {h} is not unique")));
        }
        handles.push(h.as_str());
      }
      (None, false) => {}
    }
    match r.fn_id.as_str() {
      "pseudonym" => {
        if nym_handle.is_some() {
          return Err(Refusal::unsupported_request("more than one pseudonym item"));
        }
        if let Some(k) = r.params.keys().find(|k| !["config", "ver", "prf", "verifier_context"].contains(&k.as_str())) {
          return Err(Refusal::unsupported_request(format!("unknown pseudonym parameter {k}")));
        }
        if r.params.get("ver").and_then(Json::as_u64) != Some(VERSION) {
          return Err(Refusal::unsupported_request(format!("pseudonym ver {:?}: the rulebook defines {VERSION}", r.params.get("ver"))));
        }
        let prf = param_str(&r.params, "prf")?;
        if prf != Some(PRF) {
          return Err(Refusal::unsupported_config(format!("prf {prf:?}: these circuits implement {PRF}")));
        }
        let config = param_str(&r.params, "config")?;
        if config != Some(CONFIG) {
          return Err(Refusal::unsupported_config(format!("config {config:?}: this circuit implements {CONFIG}")));
        }
        if param_str(&r.params, "verifier_context")?.is_some() {
          return Err(Refusal::unsupported_request("verifier_context is not allowed for this configuration"));
        }
        // The trust framework fixes the x509_san_dns form: verifier_id is the client_id.
        if !request.client_id.starts_with(CLIENT_ID_PREFIX) || request.client_id.len() == CLIENT_ID_PREFIX.len() {
          return Err(Refusal::unsupported_request("the x509_san_dns verifier_id needs an x509_san_dns client_id"));
        }
        nym_handle = r.handle.clone();
      }
      "age_check" if rulebook.years_range() => {
        if age.is_some() {
          return Err(Refusal::unsupported_request("more than one age_check item"));
        }
        if let Some(k) = r.params.keys().find(|k| *k != "range") {
          return Err(Refusal::unsupported_request(format!("unknown age_check parameter {k}")));
        }
        let range = param_str(&r.params, "range")?.ok_or_else(|| Refusal::unsupported_request("age_check without range"))?;
        let range = dates::AgeRange::parse(range).map_err(Refusal::unsupported_request)?;
        let d = date.ok_or_else(|| Refusal::bad_request("age_check needs the date of proof_time"))?;
        let (born_from, born_by) = dates::range_bounds(&range, &d);
        age = Some((None, AgeBounds { born_from, born_by }));
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
  let nym_handle = nym_handle.ok_or_else(|| Refusal::unsupported_request("these circuits need a pseudonym item"))?;

  let session_transcript = handover.session_transcript().map_err(Refusal::bad_request)?;
  let formats = &request.client_metadata.vp_formats_supported.zkp_req;
  Ok(Statement {
    client_id: request.client_id.clone(),
    verifier_input: crate::sha256(request.client_id.as_bytes()),
    challenge: crate::handover::challenge_digest(&session_transcript, DOC_TYPE),
    session_transcript,
    age: age.as_ref().map_or(AgeBounds { born_from: None, born_by: None }, |(_, b)| *b),
    nym_handle,
    age_handle: age.and_then(|(h, _)| h),
    offered_ids: formats.system_id_values.clone(),
    offered_systems: formats.proof_system_values.clone(),
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
        "client_id": "x509_san_dns:community.example", "nonce": "n", "response_uri": "https://r/x",
        "dcql_query": { "credentials": [{ "id": "q", "format": "zkp_req",
          "meta": { "source_format": "mso_mdoc", "doctype_value": DOC_TYPE },
          "_req": [
            { "fn_id": "pseudonym", "return": "nym", "params": { "config": CONFIG, "ver": 1, "prf": "sha-256" } },
            { "fn_id": "age_check", "return": "age", "params": params }
          ] }] },
        "client_metadata": { "vp_formats_supported": { "zkp_req": {} } }
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
