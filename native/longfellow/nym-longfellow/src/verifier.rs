//! Verification of a presentation (rulebook, "Verification"), with the same rules, input and
//! output as the Vega verifier (`native/vega`, nym-vega `verifier`). The verifier takes
//! `issuer_key_set`, `proof_time` and `results` from the presentation and computes every other
//! public input itself from the request and handover it holds and from its clock:
//!
//! 1. `circuit_id` is this circuit, and the request offered it;
//! 2. `issuer_key_set` holds one Document Signer certificate, valid against the trust anchors;
//! 3. `proof_time` lies within the tolerance of `now`;
//! 4. the keys of `results` are the `return` handles of `req`;
//! 5. both circuits' proofs verify with the public inputs (SPEC.md L6.3), the transcript seeded
//!    with the SessionTranscript.
//!
//! A refusal names its rule (`code`). Longfellow's verifier says which circuit failed, not which
//! public input: a wrong T, E, C, verifier_input or pseudonym fails the hash circuit, a wrong
//! issuer key or e2 the signature circuit.

use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json, json};

use crate::circuit::{CIRCUIT_ID, PROOF_SYSTEM, RUNTIME};
use crate::handover::Handover;
use crate::measure::{Peak, ms};
use crate::presentation::{Presentation, ResultValue};
use crate::request::{RequestObject, statement};
use crate::witness::Public;
use crate::x509::TrustAnchors;
use crate::zk::{Circuits, Rejection, ZkVerifierPair};
use crate::{dates, hex};

/// The largest proof the verifier reads. A proof of these circuits is about 344 kB.
const MAX_PROOF_BYTES: usize = 1 << 20;

#[derive(Clone, Debug, Deserialize)]
pub struct VerifyInput {
  pub request: RequestObject,
  pub credential_query_id: String,
  /// base64url(CBOR(CircuitZkPresentation)).
  pub presentation: String,
  pub handover: Handover,
  /// The verifier's clock, RFC 3339.
  pub now: String,
}

/// Why a presentation is refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Refused {
  /// The rule: `presentation`, `circuit`, `issuer_key_set`, `request`, `proof_time`, `results`,
  /// `proof_encoding`, `proof_invalid`.
  pub code: &'static str,
  /// For `proof_invalid`: the circuit whose proof fails, `hash` or `signature`.
  #[serde(skip_serializing_if = "Option::is_none")]
  pub input: Option<&'static str>,
  pub reason: String,
}

fn refuse(code: &'static str, reason: impl Into<String>) -> Refused {
  Refused { code, input: None, reason: reason.into() }
}

pub struct Verifier {
  pair: ZkVerifierPair,
  pub circuits_sha256: [u8; 32],
  pub load_ms: f64,
  anchors: TrustAnchors,
  tolerance_s: i64,
}

impl Verifier {
  /// Reads the circuits in `dir` (`circuits/mdoc`) and the trust anchors (PEM).
  pub fn load(dir: &Path, trust_anchors_pem: &str, tolerance_s: i64) -> Result<Self, String> {
    if tolerance_s <= 0 {
      return Err("the proof_time tolerance must be positive".into());
    }
    let anchors = TrustAnchors::from_pem(trust_anchors_pem)?;
    let c = Circuits::load(dir)?;
    let (circuits_sha256, load_ms) = (c.sha256, c.load_ms);
    Ok(Verifier { pair: ZkVerifierPair::new(c), circuits_sha256, load_ms, anchors, tolerance_s })
  }

  pub fn info(&self) -> Json {
    json!({
      "service": "verifier",
      "implementation": format!("Longfellow: {RUNTIME}, nym-auth-circuits LFC2 mdoc circuits; Node addon"),
      "version": env!("CARGO_PKG_VERSION"),
      "stub": false,
      "circuits": crate::prover::circuit_info(&self.circuits_sha256),
      "trust_anchors": self.anchors.0.iter().map(|a| json!({ "subject": a.subject, "not_after": a.not_after })).collect::<Vec<_>>(),
      "proof_time_tolerance_s": self.tolerance_s,
      "load_ms": self.load_ms,
      "threads": 1,
    })
  }

  /// Verifies; `ok: false` with the refusal, or `ok: true` with the results.
  pub fn verify(&self, input: &VerifyInput) -> Json {
    let t = Instant::now();
    let peak = Peak::start();
    let mut metrics = Map::new();
    metrics.insert("load_ms".into(), json!(self.load_ms));
    let outcome = self.check(input, &mut metrics);
    metrics.insert("total_ms".into(), json!(ms(t)));
    metrics.insert("peak_memory_mb".into(), json!(peak.read()));
    match outcome {
      Ok((results, circuit_id)) => json!({ "ok": true, "circuit_id": circuit_id, "results": results, "metrics": metrics }),
      Err(r) => json!({ "ok": false, "code": r.code, "input": r.input, "reason": r.reason, "metrics": metrics }),
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
    if p.circuit_id != CIRCUIT_ID {
      return Err(refuse("circuit", format!("unknown circuit {}", p.circuit_id)));
    }
    let s = statement(&input.request, &input.credential_query_id, &input.handover)
      .map_err(|e| refuse("request", format!("{}: {}", e.error, e.detail)))?;
    if s.offered_circuits.as_ref().is_some_and(|ids| !ids.iter().any(|id| id == CIRCUIT_ID))
      || s.offered_systems.as_ref().is_some_and(|ps| !ps.iter().any(|p| p == PROOF_SYSTEM))
    {
      return Err(refuse("circuit", "the request did not offer this circuit"));
    }

    // 2. The issuer key set: one certificate, since the circuit names one issuer key.
    let [certificate] = &p.issuer_key_set[..] else {
      return Err(refuse("issuer_key_set", format!("{} certificates; this circuit takes exactly one", p.issuer_key_set.len())));
    };
    let signer = self.anchors.validate(certificate, now).map_err(|e| refuse("issuer_key_set", e))?;

    // 3. proof_time.
    let proof_time = dates::date_time(&p.proof_time).map_err(|e| refuse("proof_time", format!("proof_time: {e}")))?;
    let proof_s = dates::unix(&proof_time);
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

    // 5. Both proofs, against the verifier's own public values.
    if p.proof.len() > MAX_PROOF_BYTES {
      return Err(refuse("proof_encoding", format!("a proof of {} bytes", p.proof.len())));
    }
    let t = Instant::now();
    let public = Public {
      time: proof_time.text(),
      earliest: s.age.earliest(),
      cutoff: s.age.cutoff(),
      verifier_input: s.verifier_input,
      issuer_key: signer.key,
      challenge: s.challenge,
    };
    let outcome = self.pair.verify(&p.proof, &public, nym, &s.session_transcript);
    metrics.insert("verify_ms".into(), json!(ms(t)));
    match outcome {
      Ok(()) => {}
      Err(Rejection::Encoding(e)) => return Err(refuse("proof_encoding", format!("the proof does not decode: {e}"))),
      Err(Rejection::Invalid(circuit)) => {
        return Err(Refused {
          code: "proof_invalid",
          input: Some(circuit),
          reason: format!("the {circuit} circuit's proof does not verify with the verifier's public inputs"),
        });
      }
    }

    let mut results = Map::new();
    results.insert(s.nym_handle.clone(), Json::String(hex(nym)));
    if let Some(h) = &s.age_handle {
      results.insert(h.clone(), Json::Bool(true));
    }
    Ok((results, CIRCUIT_ID.to_string()))
  }
}
