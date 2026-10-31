//! Verification of a presentation (rulebook, "Verification"), with the same rules, input and
//! output as the Vega verifier (`native/vega`, nym-vega `verifier`). The verifier takes
//! `issuer_key_set`, `proof_time` and `results` from the presentation and computes every other
//! public input itself from the request and handover it holds and from its clock:
//!
//! 1. `system_id` is this circuit, and the request offered it;
//! 2. `issuer_key_set` holds one Document Signer certificate, valid against the trust anchors;
//! 3. `proof_time` lies within the tolerance of `now`;
//! 4. the keys of `results` are the `return` handles of `req`;
//! 5. both circuits' proofs verify with the public inputs (SPEC.md L6.3), the transcript seeded
//!    with the SessionTranscript.
//!
//! Under rulebook v0.5, step 5 runs `nym-auth-zk`'s verifier on the `bsc` circuits
//! ([`crate::v05`]), with the request built from the session's request and handover and the
//! certificate's key ([`crate::bsc::request`]); the crate computes the public inputs.
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
use crate::measure::{Heap, Peak, mb, ms};
use crate::presentation::{Presentation, ResultValue};
use crate::request::{RequestObject, Rulebook, statement_for};
use crate::witness::Public;
use crate::x509::TrustAnchors;
use crate::zk::{Circuits, Rejection, ZkVerifierPair};
use crate::{bsc, dates, hex, v05};
use nym_auth_zk as v5;
use nym_auth_zk_decoy as v6;

/// The largest proof the verifier reads. A proof of these circuits is about 344 kB.
const MAX_PROOF_BYTES: usize = 1 << 20;

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
  /// The rulebook version the site's request follows (the demo profile): "0.4" (absent) or "0.5".
  #[serde(default)]
  pub rulebook: Option<String>,
  /// v0.5: one thread per core for the proof check (`/tech`'s switch); one thread when false or
  /// absent. The v0.4 circuits always run on one thread.
  #[serde(default)]
  pub parallel: bool,
  /// A thread count, 1 up to the cores (`/tech`'s thread setting); it overrides `parallel`.
  #[serde(default)]
  pub threads: Option<usize>,
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
  /// For `issuer_key_set` when the certificate is not trusted: the certificate presented, as
  /// base64 DER, so the site can trust it on the next try (`/tech`'s Trust new issuers).
  #[serde(skip_serializing_if = "Option::is_none")]
  pub certificate: Option<String>,
}

fn refuse(code: &'static str, reason: impl Into<String>) -> Refused {
  Refused { code, input: None, reason: reason.into(), certificate: None }
}

pub struct Verifier {
  pair: ZkVerifierPair,
  /// The v0.5 circuits (`nym-auth-zk`), loaded with the v0.4 ones.
  v5: v05::Loaded<v5::Verifier>,
  /// The v0.6 circuits (`nym-auth-zk-decoy`, the decoy-digest layout), loaded with the others.
  v6: v05::Loaded<v6::Verifier>,
  pub circuits_sha256: [u8; 32],
  pub load_ms: f64,
  /// The heap the loaded keys or circuits hold (measure::Heap; one load at a time).
  pub keys_mb: Option<f64>,
  anchors: TrustAnchors,
  tolerance_s: i64,
}

impl Verifier {
  /// Reads the circuits in `dir` (`circuits/mdoc`) and the trust anchors (PEM).
  pub fn load(dir: &Path, trust_anchors_pem: &str, tolerance_s: i64) -> Result<Self, String> {
    if tolerance_s <= 0 {
      return Err("the proof_time tolerance must be positive".into());
    }
    let _one = crate::measure::exclusive()?;
    let heap = Heap::start();
    let anchors = TrustAnchors::from_pem(trust_anchors_pem)?;
    let c = Circuits::load(dir)?;
    let (circuits_sha256, load_ms) = (c.sha256, c.load_ms);
    let pair = ZkVerifierPair::new(c);
    let v5 = v05::load_verifier()?;
    let v6 = crate::decoy::load_verifier()?;
    let load_ms = load_ms + v5.load_ms + v6.load_ms;
    Ok(Verifier { pair, circuits_sha256, load_ms, v5, v6, keys_mb: mb(heap.held()), anchors, tolerance_s })
  }

  pub fn info(&self) -> Json {
    json!({
      "service": "verifier",
      "implementation": format!("Longfellow: {RUNTIME}, nym-auth-circuits LFC2 mdoc circuits (v0.4) and nym-auth-zk bsc circuits (v0.5) and nym-auth-zk-decoy circuits (v0.6); Node addon"),
      "version": env!("CARGO_PKG_VERSION"),
      "stub": false,
      "circuits": crate::prover::circuit_info(&self.circuits_sha256, &self.v5.sha256, &self.v6.sha256),
      "trust_anchors": self.anchors.0.iter().map(|a| json!({ "subject": a.subject, "not_after": a.not_after })).collect::<Vec<_>>(),
      "proof_time_tolerance_s": self.tolerance_s,
      "load_ms": self.load_ms,
      "keys_mb": self.keys_mb,
      "max_threads": crate::threads::cores(),
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
      Ok((results, system_id, bounds)) => json!({ "ok": true, "system_id": system_id, "results": results, "bounds": bounds, "metrics": metrics }),
      Err(r) => json!({ "ok": false, "code": r.code, "input": r.input, "reason": r.reason, "certificate": r.certificate, "metrics": metrics }),
    }
  }

  /// The results, the circuit, and the birth-date bounds the proof showed (with an age check).
  fn check(&self, input: &VerifyInput, metrics: &mut Map<String, Json>) -> Result<(Map<String, Json>, String, Option<Json>), Refused> {
    let t = Instant::now();
    let bytes = crate::unb64url("presentation", &input.presentation).map_err(|e| refuse("presentation", e))?;
    let p = Presentation::decode(&bytes).map_err(|e| refuse("presentation", format!("presentation: {e}")))?;
    metrics.insert("decode_ms".into(), json!(ms(t)));
    metrics.insert("proof_bytes".into(), json!(p.proof.len()));
    let now = dates::rfc3339(&input.now).map_err(|e| refuse("request", format!("now: {e}")))?;

    // 1. The circuit: v0.4's (circuits/mdoc) or v0.5's (nym-auth-zk), by its id, each for requests
    // of its own rulebook version.
    let v05_id = v05::circuit_id();
    let needs = if p.system_id == CIRCUIT_ID {
      Rulebook::V04
    } else if p.system_id == v05_id {
      Rulebook::V05
    } else if p.system_id == crate::decoy::system_id() {
      Rulebook::V06
    } else {
      return Err(refuse("circuit", format!("unknown circuit {}", p.system_id)));
    };
    let circuit_id = p.system_id.clone();
    // v0.5: an age range's bounds come from the UTC date of proof_time (checked against the clock in 3.).
    let rulebook = Rulebook::parse(input.rulebook.as_deref()).map_err(|r| refuse("request", r.detail))?;
    if rulebook != needs {
      return Err(refuse("circuit", format!("{circuit_id} is not a circuit for this rulebook version")));
    }
    // Rulebook v0.4: `results` holds at least one entry ({ + tstr => ResultValue }); v0.5 allows it
    // empty, and step 4 refuses a missing handle (`results`).
    if rulebook == Rulebook::V04 && p.results.is_empty() {
      return Err(refuse("presentation", "presentation: results is empty"));
    }
    let date = match rulebook {
      Rulebook::V04 => None,
      Rulebook::V05 | Rulebook::V06 => Some(dates::date_time(&p.proof_time).map_err(|e| refuse("proof_time", format!("proof_time: {e}")))?.date),
    };
    let s = statement_for(&input.request, &input.credential_query_id, &input.handover, rulebook, date)
      .map_err(|e| refuse("request", format!("{}: {}", e.error, e.detail)))?;
    if s.offered_ids.as_ref().is_some_and(|ids| !ids.iter().any(|id| *id == circuit_id))
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
    if rulebook == Rulebook::V06 {
      let req = crate::decoy::request(&signer.key, &p.proof_time, &input.request, &input.credential_query_id, &input.handover)
        .map_err(|e| refuse("request", e))?;
      let presentation = v6::Presentation { pseudonym: *nym, proof: p.proof.clone() };
      let (outcome, threads) = crate::threads::pool_of(input.parallel, input.threads).install(|| (self.v6.side.verify(&req, &presentation), v6::threads()));
      metrics.insert("verify_ms".into(), json!(ms(t)));
      metrics.insert("threads".into(), json!(threads));
      if let Err(e) = outcome {
        return Err(match crate::decoy::failing_circuit(&e) {
          Some(c) => Refused {
            code: "proof_invalid",
            input: Some(c),
            certificate: None,
            reason: format!("the {c} circuit's proof does not verify with the verifier's public inputs"),
          },
          None => refuse("proof_encoding", format!("the proof does not decode: {e:?}")),
        });
      }
    } else if rulebook == Rulebook::V05 {
      let req = bsc::request(&signer.key, &p.proof_time, &input.request, &input.credential_query_id, &input.handover)
        .map_err(|e| refuse("request", e))?;
      let presentation = v5::Presentation { pseudonym: *nym, proof: p.proof.clone() };
      let (outcome, threads) = crate::threads::pool_of(input.parallel, input.threads).install(|| (self.v5.side.verify(&req, &presentation), v5::threads()));
      metrics.insert("verify_ms".into(), json!(ms(t)));
      metrics.insert("threads".into(), json!(threads));
      if let Err(e) = outcome {
        return Err(match bsc::failing_circuit(&e) {
          Some(c) => Refused {
            code: "proof_invalid",
            input: Some(c),
            certificate: None,
            reason: format!("the {c} circuit's proof does not verify with the verifier's public inputs"),
          },
          None => refuse("proof_encoding", format!("the proof does not decode: {e:?}")),
        });
      }
    } else {
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
    metrics.insert("threads".into(), json!(1));
    match outcome {
      Ok(()) => {}
      Err(Rejection::Encoding(e)) => return Err(refuse("proof_encoding", format!("the proof does not decode: {e}"))),
      Err(Rejection::Invalid(circuit)) => {
        return Err(Refused {
          code: "proof_invalid",
          input: Some(circuit),
          certificate: None,
          reason: format!("the {circuit} circuit's proof does not verify with the verifier's public inputs"),
        });
      }
    }
    }

    let mut results = Map::new();
    results.insert(s.nym_handle.clone(), Json::String(hex(nym)));
    if let Some(h) = &s.age_handle {
      results.insert(h.clone(), Json::Bool(true));
    }
    let bounds = s.age_handle.is_some() || rulebook.years_range() && (s.age.born_from.is_some() || s.age.born_by.is_some());
    let bounds = bounds.then(|| json!({ "ge": s.age.born_from.map(|d| d.text()), "le": s.age.born_by.map(|d| d.text()) }));
    Ok((results, circuit_id, bounds))
  }
}
