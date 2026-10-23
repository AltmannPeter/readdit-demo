//! Verification of a `ZkpPresentation` over `bbs_cd` (rulebook v0.4, "Verification"). The verifier
//! derives the BBS request itself, from the Request Object and handover in its own session store
//! and the issuer parameters it trusts (`docs/bbs_cd.md`); it takes `issuer_key_set` and `results`
//! from the presentation, and the proof.
//!
//! 1. `system_id` is this scheme, and the request offered it;
//! 2. `issuer_key_set` is one BBS issuer key, the trusted issuer's;
//! 3. the request's `zkp_req` query over `bbs_cd` is one the profile defines, and the keys of
//!    `results` are its `return` handles;
//! 4. the envelope parses against the BBS request (`BCDP`, counts, lengths), the ETSI BBS proof
//!    verifies with the presentation header ph, which binds the nonce and ctx, and each plugin
//!    verifies against env: `ecdsa-pop`, `pseudonym` (verifier input UTF-8(client_id)),
//!    `date-range` when asked;
//! 5. `results`: the pseudonym equals the pseudonym plugin's G1 point; the age check is true.
//!
//! A refusal names its rule: `presentation`, `scheme`, `issuer_key_set`, `request`, `results`,
//! `proof_invalid`.

use std::time::Instant;

use bbs_cd_plugin::envelope::{Verifier as BbsVerifier, VerifyStats};
use bbs_cd_plugin::issuer::IssuerParams;
use bbs_cd_plugin::par::Parallelism;
use cd_date_range::DateRangeVerifier;
use cd_ecdsa_pop::EcdsaPopVerifier;
use cd_pseudonym::PseudonymVerifier;
use serde::Deserialize;
use serde_json::{json, Map, Value as Json};

use crate::measure::{mb, ms, Heap, Peak};
use crate::presentation::{Presentation, ResultValue};
use crate::profile::{self, Handover, RequestObject, PROOF_SYSTEM, SYSTEM_ID};
use crate::prover::scheme_json;
use crate::{hex, unb64url};

/// The largest presentation the verifier reads (the framework's own limit is 4 MiB).
const MAX_PRESENTATION_BYTES: usize = 1 << 20;

#[derive(Clone, Debug, Deserialize)]
pub struct VerifyInput {
  pub request: RequestObject,
  pub credential_query_id: String,
  /// base64url(CBOR(ZkpPresentation)).
  pub presentation: String,
  pub handover: Handover,
  /// ecdsa-pop's check on one thread per core; one thread when false or absent.
  #[serde(default)]
  pub parallel: bool,
}

pub struct Verifier {
  issuer: IssuerParams,
  /// The plugin verifiers with ecdsa-pop sequential, and with ecdsa-pop on every core.
  bbs: BbsVerifier,
  bbs_parallel: BbsVerifier,
  pub load_ms: f64,
  /// The heap the loaded keys or circuits hold (measure::Heap; one load at a time).
  pub keys_mb: Option<f64>,
}

struct Refused {
  code: &'static str,
  reason: String,
}

fn refuse(code: &'static str, reason: impl Into<String>) -> Refused {
  Refused { code, reason: reason.into() }
}

impl Verifier {
  /// `issuer_params`: the trusted issuer's `IssuerParams::encode` (its public key and schema).
  pub fn load(issuer_params: &[u8]) -> Result<Self, String> {
    let _one = crate::measure::exclusive()?;
    let heap = Heap::start();
    let t = Instant::now();
    let issuer = IssuerParams::decode(issuer_params).map_err(|e| format!("issuer parameters: {e}"))?;
    if issuer.schema.digest() != profile::schema().map_err(|e| e.to_string())?.digest() {
      return Err("the trusted issuer's schema is not the profile's".into());
    }
    cd_date_range::precompute();
    let with = |par: Parallelism| {
      let mut pop = EcdsaPopVerifier::new();
      pop.parallelism = par;
      BbsVerifier::new().register(Box::new(pop)).register(Box::new(PseudonymVerifier::any())).register(Box::new(DateRangeVerifier))
    };
    let (bbs, bbs_parallel) = (with(Parallelism::Off), with(Parallelism::Max));
    Ok(Verifier { issuer, bbs, bbs_parallel, load_ms: ms(t), keys_mb: mb(heap.held()) })
  }

  pub fn info(&self) -> Json {
    json!({
      "service": "verifier",
      "implementation": "BBS: sirosfoundation/bbs-cd-plugins 0.1 (ETSI BBS committed disclosures v0.7, BLS12-381-SHA-256), plugins ecdsa-pop, date-range, pseudonym; Node addon",
      "version": env!("CARGO_PKG_VERSION"),
      "schemes": [scheme_json()],
      "issuers": [{ "issuer_pk": hex(&self.issuer.pk), "schema_id": self.issuer.schema.id(), "schema_digest": hex(&self.issuer.schema.digest()) }],
      "load_ms": self.load_ms,
      "keys_mb": self.keys_mb,
      "max_threads": Parallelism::Max.threads(),
    })
  }

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
      Ok(results) => json!({ "ok": true, "system_id": SYSTEM_ID, "results": results, "metrics": metrics }),
      Err(r) => json!({ "ok": false, "code": r.code, "reason": r.reason, "metrics": metrics }),
    }
  }

  fn check(&self, input: &VerifyInput, metrics: &mut Map<String, Json>) -> Result<Map<String, Json>, Refused> {
    let t = Instant::now();
    let bytes = unb64url("presentation", &input.presentation).map_err(|e| refuse("presentation", e))?;
    if bytes.len() > MAX_PRESENTATION_BYTES {
      return Err(refuse("presentation", format!("{} bytes; the limit is {MAX_PRESENTATION_BYTES}", bytes.len())));
    }
    let p = Presentation::decode(&bytes).map_err(|e| refuse("presentation", format!("presentation: {e}")))?;
    metrics.insert("decode_ms".into(), json!(ms(t)));
    metrics.insert("proof_bytes".into(), json!(p.proof.len()));

    // 1. The scheme.
    if p.system_id != SYSTEM_ID {
      return Err(refuse("scheme", format!("unknown system {}", p.system_id)));
    }
    let s = profile::statement(&input.request, &input.credential_query_id, &input.handover, &self.issuer).map_err(|r| {
      let code = if r.error == "unsupported_circuit" { "scheme" } else { "request" };
      refuse(code, format!("{}: {}", r.error, r.detail))
    })?;
    let offer = input.request.client_metadata.vp_formats_supported.zkp_req.as_ref();
    if offer.and_then(|o| o.proof_system_values.as_ref()).is_some_and(|v| !v.iter().any(|x| x == PROOF_SYSTEM)) {
      return Err(refuse("scheme", "the request did not offer this proof system"));
    }

    // 2. The issuer key set: one key, since a BBS proof verifies under one issuer key.
    let [key] = &p.issuer_key_set[..] else {
      return Err(refuse("issuer_key_set", format!("{} keys; this scheme takes exactly one", p.issuer_key_set.len())));
    };
    if *key != self.issuer.pk {
      return Err(refuse("issuer_key_set", "not a trusted issuer key"));
    }

    // 3. results: exactly the return handles.
    let mut presented: Vec<&str> = p.results.iter().map(|(k, _)| k.as_str()).collect();
    let mut expected: Vec<&str> = s.handles.iter().map(String::as_str).collect();
    presented.sort_unstable();
    expected.sort_unstable();
    if presented != expected {
      return Err(refuse("results", format!("results keys {presented:?} are not the return handles {expected:?}")));
    }
    let value = |k: &str| p.results.iter().find(|(key, _)| key == k).map(|(_, v)| v);
    let Some(ResultValue::Pseudonym(claimed)) = value(&s.nym_handle) else {
      return Err(refuse("results", format!("results.{} is not a 48-byte pseudonym", s.nym_handle)));
    };
    if let Some(h) = &s.age_handle {
      if value(h) != Some(&ResultValue::True) {
        return Err(refuse("results", format!("results.{h} is not true")));
      }
    }
    let bytes = &p.proof;

    let t = Instant::now();
    let mut vs = VerifyStats::default();
    let par = crate::prover::parallelism(input.parallel);
    metrics.insert("threads".into(), json!(par.threads()));
    let bbs = if input.parallel { &self.bbs_parallel } else { &self.bbs };
    let verified = bbs
      .verify(std::slice::from_ref(&self.issuer), &s.request, bytes, None, Some(&mut vs))
      .map_err(|e| match e {
        bbs_cd_plugin::error::Error::Decode(m) => refuse("presentation", m),
        other => refuse("proof_invalid", other.to_string()),
      })?;
    metrics.insert("verify_ms".into(), json!(ms(t)));
    let d = |x: std::time::Duration| x.as_secs_f64() * 1e3;
    metrics.insert("parse_ms".into(), json!(d(vs.parse)));
    metrics.insert("bbs_ms".into(), json!(d(vs.bbs)));
    metrics.insert("ecdsa_pop_ms".into(), json!(vs.plugins.first().map(|x| d(*x))));
    metrics.insert("pseudonym_ms".into(), json!(vs.plugins.get(s.index_pseudonym).map(|x| d(*x))));
    metrics.insert("date_range_ms".into(), json!(s.index_age.and_then(|i| vs.plugins.get(i)).map(|x| d(*x))));

    // 5. The pseudonym in results is the one the plugin proved.
    let nym = verified.outputs.get(s.index_pseudonym).filter(|o| o.len() == 48).ok_or_else(|| refuse("proof_invalid", "the pseudonym output is not a 48-byte point"))?;
    if nym.as_slice() != claimed.as_slice() {
      return Err(refuse("results", format!("results.{} is not the pseudonym the proof shows", s.nym_handle)));
    }
    let mut results = Map::new();
    results.insert(s.nym_handle.clone(), Json::String(hex(nym)));
    if let Some(h) = &s.age_handle {
      results.insert(h.clone(), Json::Bool(true));
    }
    Ok(results)
  }
}
