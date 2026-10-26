//! Verification of a presentation (rulebook, "Verification"). The verifier takes `issuer_key_set`,
//! `proof_time` and `results` from the presentation and computes every other public input itself
//! from the request and handover it holds and from its clock:
//!
//! 1. `system_id` is this circuit, and the request offered it;
//! 2. `issuer_key_set` holds one Document Signer certificate, valid against the trust anchors;
//! 3. `proof_time` lies within the tolerance of `now`;
//! 4. the keys of `results` are the `return` handles of `req`;
//! 5. the proof verifies with the public inputs in the registry order ([`PUBLIC_INPUTS`]).
//!
//! A refusal names its rule (`code`) and, for a public input the proof does not match, the input.

use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json, json};
use vega_age::app::{self, Proof, Rejection, VerifierKey};
use vega_age::presentation::{Public, TimeEncoding};
use vega_age::pseudonym::NymPublic;
use vega_age::request::Request;

use crate::circuit::{BIRTH_DATE, CIRCUIT_ID, DOC_TYPE, LAYOUT, PROOF_SYSTEM, PUBLIC_INPUTS, PUBLIC_VALUES, input_at};
use crate::handover::Handover;
use crate::measure::{Heap, Peak, mb, ms};
use crate::presentation::{Presentation, ResultValue};
use crate::request::{RequestObject, statement};
use crate::x509::TrustAnchors;
use crate::{dates, hex, keys, threads};

/// The largest proof the verifier decodes. A proof of this circuit is 96,079 bytes.
const MAX_PROOF_BYTES: u64 = 1 << 20;

#[derive(Clone, Debug, Deserialize)]
pub struct VerifyInput {
  pub request: RequestObject,
  pub credential_query_id: String,
  /// base64url(CBOR(ZkpPresentation)).
  pub presentation: String,
  pub handover: Handover,
  /// The verifier's clock, RFC 3339.
  pub now: String,
  /// Issuers trusted besides the configured trust anchors: Document Signer certificates, base64
  /// DER, that `/tech` learned from earlier presentations ("Trust new issuers").
  #[serde(default)]
  pub learned_issuers: Vec<String>,
  /// One thread per core for the proof check; one thread when false or absent.
  #[serde(default)]
  pub parallel: bool,
}

/// Why a presentation is refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Refused {
  /// The rule: `presentation`, `circuit`, `issuer_key_set`, `request`, `proof_time`, `results`,
  /// `proof_encoding`, `proof_invalid`, `public_input`.
  pub code: &'static str,
  /// For `public_input`: the input whose value the proof does not match.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub input: Option<&'static str>,
  pub reason: String,
  /// For `issuer_key_set` when the certificate is not trusted: the certificate presented, as
  /// base64 DER, so the site can trust it on the next try (`/tech`'s Trust new issuers).
  #[serde(skip_serializing_if = "Option::is_none")]
  pub certificate: Option<String>,
}

fn refuse(code: &'static str, reason: impl Into<String>) -> Refused {
  Refused { code, input: None, reason: reason.into(), certificate: None }
}

pub struct Verifier {
  vk: VerifierKey,
  pub shapes_sha256: [u8; 32],
  pub load_ms: f64,
  /// The heap the loaded keys or circuits hold (measure::Heap; one load at a time).
  pub keys_mb: Option<f64>,
  anchors: TrustAnchors,
  tolerance_s: i64,
}

impl Verifier {
  /// Builds the verifier key from `shapes.zst` and reads the trust anchors (PEM).
  pub fn load(shapes: &Path, trust_anchors_pem: &str, tolerance_s: i64) -> Result<Self, String> {
    if tolerance_s <= 0 {
      return Err("the proof_time tolerance must be positive".into());
    }
    let _one = crate::measure::exclusive()?;
    let heap = Heap::start();
    let anchors = TrustAnchors::from_pem(trust_anchors_pem)?;
    let loaded = keys::verifier_key(shapes)?;
    Ok(Verifier { vk: loaded.key, shapes_sha256: loaded.shapes_sha256, load_ms: loaded.load_ms, keys_mb: mb(heap.held()), anchors, tolerance_s })
  }

  pub fn info(&self) -> Json {
    json!({
      "service": "verifier",
      "implementation": "Vega: microsoft/vega-prover c0ee259 (VegaMcZkSNARK, T256HyraxEngine), nym-auth-circuits vega-age; Node addon",
      "version": env!("CARGO_PKG_VERSION"),
      "stub": false,
      "circuits": [{
        "system_id": CIRCUIT_ID,
        "proof_system": PROOF_SYSTEM,
        "shapes_sha256": hex(&self.shapes_sha256),
        "public_inputs": PUBLIC_INPUTS.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
      }],
      "trust_anchors": self.anchors.0.iter().map(|a| json!({ "subject": a.subject, "not_after": a.not_after })).collect::<Vec<_>>(),
      "proof_time_tolerance_s": self.tolerance_s,
      "load_ms": self.load_ms,
      "keys_mb": self.keys_mb,
      "max_threads": threads::cores(),
    })
  }

  /// Verifies; `ok: false` with the refusal, or `ok: true` with the results.
  pub fn verify(&self, input: &VerifyInput) -> Json {
    let t = Instant::now();
    let peak = Peak::start();
    let heap = Heap::start();
    let mut metrics = Map::new();
    metrics.insert("load_ms".into(), json!(self.load_ms));
    metrics.insert("keys_mb".into(), json!(self.keys_mb));
    let outcome = self.check(input, &mut metrics);
    metrics.insert("total_ms".into(), json!(ms(t)));
    metrics.insert("heap_mb".into(), json!(mb(heap.high() - heap.base())));
    metrics.insert("peak_memory_mb".into(), json!(peak.read()));
    match outcome {
      Ok((results, system_id)) => json!({ "ok": true, "system_id": system_id, "results": results, "metrics": metrics }),
      Err(r) => json!({ "ok": false, "code": r.code, "input": r.input, "reason": r.reason, "certificate": r.certificate, "metrics": metrics }),
    }
  }

  fn check(&self, input: &VerifyInput, metrics: &mut Map<String, Json>) -> Result<(Map<String, Json>, String), Refused> {
    let t = Instant::now();
    let bytes = crate::unb64url("presentation", &input.presentation).map_err(|e| refuse("presentation", e))?;
    let p = Presentation::decode(&bytes).map_err(|e| refuse("presentation", format!("presentation: {e}")))?;
    metrics.insert("decode_ms".into(), json!(ms(t)));
    metrics.insert("proof_bytes".into(), json!(p.proof.len()));
    let now = dates::rfc3339(&input.now).map_err(|e| refuse("request", format!("now: {e}")))?;

    // 1. The circuit.
    if p.system_id != CIRCUIT_ID {
      return Err(refuse("circuit", format!("unknown circuit {}", p.system_id)));
    }
    let s = statement(&input.request, &input.credential_query_id, &input.handover)
      .map_err(|e| refuse("request", format!("{}: {}", e.error, e.detail)))?;
    if s.offered_ids.as_ref().is_some_and(|ids| !ids.iter().any(|id| id == CIRCUIT_ID))
      || s.offered_systems.as_ref().is_some_and(|ps| !ps.iter().any(|p| p == PROOF_SYSTEM))
    {
      return Err(refuse("circuit", "the request did not offer this circuit"));
    }

    // 2. The issuer key set: one certificate, since the circuit names one issuer key.
    let [certificate] = &p.issuer_key_set[..] else {
      return Err(refuse("issuer_key_set", format!("{} certificates; this circuit takes exactly one", p.issuer_key_set.len())));
    };
    let learned: Vec<Vec<u8>> = {
      use base64::Engine;
      input.learned_issuers.iter().filter_map(|b| base64::engine::general_purpose::STANDARD.decode(b).ok()).collect()
    };
    let signer = self.anchors.validate(certificate, now, &learned).map_err(|e| {
      use base64::Engine;
      // An unknown certificate goes back with the refusal (not one that is known but out of date).
      let unknown = e.contains("not a trust anchor");
      let certificate = unknown.then(|| base64::engine::general_purpose::STANDARD.encode(certificate));
      Refused { certificate, ..refuse("issuer_key_set", e) }
    })?;

    // 3. proof_time.
    let proof_time = dates::date_time(&p.proof_time).map_err(|e| refuse("proof_time", format!("proof_time: {e}")))?;
    let proof_s = dates::unix(&proof_time).map_err(|e| refuse("proof_time", e))?;
    if (proof_s - now).abs() > self.tolerance_s {
      return Err(refuse(
        "proof_time",
        format!("proof_time {} is {} s from now, beyond the tolerance of {} s", p.proof_time, proof_s - now, self.tolerance_s),
      ));
    }

    // 4. results: exactly the return handles, with the types the functions output.
    let mut presented: Vec<&str> = p.results.iter().map(|(k, _)| k.as_str()).collect();
    let mut expected_keys = s.handles();
    presented.sort_unstable();
    expected_keys.sort_unstable();
    if presented != expected_keys {
      return Err(refuse("results", format!("results keys {presented:?} are not the return handles {expected_keys:?}")));
    }
    let value = |k: &str| p.results.iter().find(|(key, _)| key == k).map(|(_, v)| v);
    let Some(ResultValue::Pseudonym(nym)) = value(&s.nym_handle) else {
      return Err(refuse("results", format!("results.{} is not a 32-byte pseudonym", s.nym_handle)));
    };
    if let Some(h) = &s.age_handle
      && value(h) != Some(&ResultValue::True)
    {
      return Err(refuse("results", format!("results.{h} is not true")));
    }

    // 5. The proof, against the public inputs in the registry order.
    let t = Instant::now();
    let proof: Proof = {
      use bincode::Options;
      bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_PROOF_BYTES)
        .reject_trailing_bytes()
        .deserialize(&p.proof)
        .map_err(|e| refuse("proof_encoding", format!("the proof does not decode: {e}")))?
    };
    let request = Request::mdoc(DOC_TYPE, BIRTH_DATE).map_err(|e| refuse("request", e))?;
    let public = Public {
      issuer_key: signer.key,
      born_from: s.age.earliest(),
      born_by: s.age.cutoff(),
      now: proof_time,
      challenge: s.challenge,
      request,
    };
    let mut expected = public.values(TimeEncoding::Digits);
    expected.extend(NymPublic::verifier_values(&s.verifier_input));
    if expected.len() + 2 != PUBLIC_VALUES {
      return Err(refuse("request", format!("{} public values computed, the registry lists {}", expected.len() + 2, PUBLIC_VALUES)));
    }
    let pool = threads::pool(input.parallel);
    let accepted = pool.install(|| app::accept_pseudonym(&LAYOUT, &self.vk, &proof, &expected));
    metrics.insert("threads".into(), json!(pool.current_num_threads()));
    metrics.insert("verify_ms".into(), json!(ms(t)));
    let revealed = match accepted {
      Ok(revealed) => revealed,
      Err(Rejection::Invalid(e)) => return Err(refuse("proof_invalid", format!("the proof does not verify: {e:?}"))),
      Err(Rejection::Position { instance, .. }) => {
        return Err(refuse("proof_invalid", format!("step instance {instance} does not report its position")));
      }
      Err(Rejection::PublicValues { reported }) => {
        let index = (0..PUBLIC_VALUES).find(|&i| reported.get(i) != expected.get(i)).unwrap_or(PUBLIC_VALUES);
        let name = input_at(index).ok_or_else(|| refuse("public_input", format!("{} public values reported", reported.len())))?;
        return Err(Refused {
          code: "public_input",
          input: Some(name),
          certificate: None,
          reason: format!("the proof does not match the public input {name} (value {index})"),
        });
      }
    };
    // results.nym is the presentation's public input; the proof's last two values must equal it.
    if &revealed != nym {
      return Err(Refused {
        code: "public_input",
        input: Some("results.nym"),
        certificate: None,
        reason: "the proof does not match the public input results.nym".into(),
      });
    }

    let mut results = Map::new();
    results.insert(s.nym_handle.clone(), Json::String(hex(nym)));
    if let Some(h) = &s.age_handle {
      results.insert(h.clone(), Json::Bool(true));
    }
    Ok((results, CIRCUIT_ID.to_string()))
  }
}
