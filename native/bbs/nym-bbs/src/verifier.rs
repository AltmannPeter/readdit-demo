//! Verification of an `mms_zk` presentation. The verifier derives the BBS request itself, from the
//! Request Object and handover in its own session store and the issuer parameters it trusts
//! (`docs/mms_zk.md`); the presentation contributes only the envelope.
//!
//! 1. the request offers this scheme, and its `mms_zk` query is one the profile defines;
//! 2. the envelope parses against that request (`BCDP`, counts, lengths);
//! 3. the ETSI BBS proof verifies with the presentation header ph, which binds the nonce and ctx;
//! 4. each plugin verifies against env: `ecdsa-pop`, `pseudonym` (its verifier input is client_id),
//!    `date-range` when asked;
//! 5. `results`: the pseudonym is SHA-256 of the plugin's output; the age check is true.
//!
//! A refusal names its rule: `presentation`, `request`, `scheme`, `proof_invalid`.

use std::time::Instant;

use bbs_cd_plugin::envelope::{Verifier as BbsVerifier, VerifyStats};
use bbs_cd_plugin::issuer::IssuerParams;
use bbs_cd_plugin::par::Parallelism;
use cd_date_range::DateRangeVerifier;
use cd_ecdsa_pop::EcdsaPopVerifier;
use cd_pseudonym::PseudonymVerifier;
use serde::Deserialize;
use serde_json::{json, Map, Value as Json};

use crate::measure::{ms, Peak};
use crate::profile::{self, Handover, RequestObject, SCHEME_ID};
use crate::prover::scheme_json;
use crate::{hex, public_pseudonym, unb64url};

/// The largest presentation the verifier reads (the framework's own limit is 4 MiB).
const MAX_PRESENTATION_BYTES: usize = 1 << 20;

#[derive(Clone, Debug, Deserialize)]
pub struct VerifyInput {
  pub request: RequestObject,
  pub credential_query_id: String,
  /// base64url of the envelope.
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
    Ok(Verifier { issuer, bbs: with(Parallelism::Off), bbs_parallel: with(Parallelism::Max), load_ms: ms(t) })
  }

  pub fn info(&self) -> Json {
    json!({
      "service": "verifier",
      "implementation": "BBS: sirosfoundation/bbs-cd-plugins 0.1 (ETSI BBS committed disclosures v0.7, BLS12-381-SHA-256), plugins ecdsa-pop, date-range, pseudonym; Node addon",
      "version": env!("CARGO_PKG_VERSION"),
      "schemes": [scheme_json()],
      "issuers": [{ "issuer_pk": hex(&self.issuer.pk), "schema_id": self.issuer.schema.id(), "schema_digest": hex(&self.issuer.schema.digest()) }],
      "load_ms": self.load_ms,
      "max_threads": Parallelism::Max.threads(),
    })
  }

  pub fn verify(&self, input: &VerifyInput) -> Json {
    let t = Instant::now();
    let peak = Peak::start();
    let mut metrics = Map::new();
    metrics.insert("load_ms".into(), json!(self.load_ms));
    let outcome = self.check(input, &mut metrics);
    metrics.insert("total_ms".into(), json!(ms(t)));
    metrics.insert("peak_memory_mb".into(), json!(peak.read()));
    match outcome {
      Ok(results) => json!({ "ok": true, "scheme_id": SCHEME_ID, "results": results, "metrics": metrics }),
      Err(r) => json!({ "ok": false, "code": r.code, "reason": r.reason, "metrics": metrics }),
    }
  }

  fn check(&self, input: &VerifyInput, metrics: &mut Map<String, Json>) -> Result<Map<String, Json>, Refused> {
    let t = Instant::now();
    let bytes = unb64url("presentation", &input.presentation).map_err(|e| refuse("presentation", e))?;
    if bytes.len() > MAX_PRESENTATION_BYTES {
      return Err(refuse("presentation", format!("{} bytes; the limit is {MAX_PRESENTATION_BYTES}", bytes.len())));
    }
    metrics.insert("decode_ms".into(), json!(ms(t)));
    metrics.insert("proof_bytes".into(), json!(bytes.len()));

    let s = profile::statement(&input.request, &input.credential_query_id, &input.handover, &self.issuer).map_err(|r| {
      let code = if r.error == "unsupported_circuit" { "scheme" } else { "request" };
      refuse(code, format!("{}: {}", r.error, r.detail))
    })?;

    let t = Instant::now();
    let mut vs = VerifyStats::default();
    let par = crate::prover::parallelism(input.parallel);
    metrics.insert("threads".into(), json!(par.threads()));
    let bbs = if input.parallel { &self.bbs_parallel } else { &self.bbs };
    let verified = bbs
      .verify(std::slice::from_ref(&self.issuer), &s.request, &bytes, None, Some(&mut vs))
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

    let nym = verified.outputs.get(s.index_pseudonym).filter(|o| o.len() == 48).ok_or_else(|| refuse("proof_invalid", "the pseudonym output is not a 48-byte point"))?;
    let mut results = Map::new();
    results.insert(s.nym_handle.clone(), Json::String(hex(&public_pseudonym(nym))));
    if let Some(h) = &s.age_handle {
      results.insert(h.clone(), Json::Bool(true));
    }
    Ok(results)
  }
}
