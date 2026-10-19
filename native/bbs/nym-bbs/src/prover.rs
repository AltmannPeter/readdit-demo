//! The holder side: one presentation from the BBS credential, its device key and a request.
//!
//! The mocked wallet sends the credential and the device key with every call; nothing is kept.
//! The device key signs inside `ecdsa-pop` (hashed mode: ECDSA-P256-SHA256 over the plugin's
//! device message, which binds the request's nonce and env), so there is no separate signing step
//! as in the mdoc flow.

use std::cell::RefCell;
use std::time::Instant;

use bbs_cd_plugin::envelope::{parse, prepare_credential, present, PresentStats};
use bbs_cd_plugin::issuer::scalar_to_u128;
use bbs_cd_plugin::par::Parallelism;
use bbs_cd_plugin::plugin::PluginProver;
use cd_date_range::{DateRangeProver, RECOMMENDED_BITS};
use cd_ecdsa_pop::{prepare, EcdsaParams, EcdsaPopProver, Mode, ProveStats, Signer, SoftwareDevice};
use cd_pseudonym::PseudonymProver;
use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use serde::Deserialize;
use serde_json::{json, Map, Value as Json};

use crate::credential::CredentialJson;
use crate::error::Refusal;
use crate::measure::{ms, Peak};
use crate::profile::{self, Handover, RequestObject, BIRTH_DATE, DEVICE_KEY, LIMB_BITS, PROOF_SYSTEM, SCHEME_ID};
use crate::{b64url, hex, public_pseudonym, unb64url};

/// The device key as the wallet holds it (P-256 JWK with its private part).
#[derive(Clone, Debug, Deserialize)]
pub struct DeviceKeyJwk {
  pub kty: String,
  pub crv: String,
  pub x: String,
  pub y: String,
  pub d: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProveInput {
  pub request: RequestObject,
  pub credential_query_id: String,
  pub handover: Handover,
  pub credential: CredentialJson,
  pub device_key: DeviceKeyJwk,
}

pub struct Prover {
  pub load_ms: f64,
}

impl Prover {
  /// Builds the date-range plugin's generator tables once.
  pub fn load() -> Self {
    let t = Instant::now();
    cd_date_range::precompute();
    Prover { load_ms: ms(t) }
  }

  pub fn info(&self) -> Json {
    json!({
      "service": "prover",
      "implementation": "BBS: sirosfoundation/bbs-cd-plugins 0.1 (ETSI BBS committed disclosures v0.7, BLS12-381-SHA-256), plugins ecdsa-pop, date-range, pseudonym; Node addon",
      "version": env!("CARGO_PKG_VERSION"),
      "schemes": [scheme_json()],
      "load_ms": self.load_ms,
      "threads": 1,
    })
  }

  /// The presentation, or the refusal.
  pub fn prove(&self, input: &ProveInput) -> Result<Json, Refusal> {
    let t_all = Instant::now();
    let peak = Peak::start();
    let cred = input.credential.decode().map_err(Refusal::bad_credential)?;
    let s = profile::statement(&input.request, &input.credential_query_id, &input.handover, &cred.issuer)?;

    if let Some(age) = &s.age {
      let birth = cred
        .scalars(BIRTH_DATE)
        .and_then(|v| v.first().and_then(scalar_to_u128))
        .ok_or_else(|| Refusal::bad_credential("birth_date"))? as u64;
      let (lo, hi) = age.bounds(RECOMMENDED_BITS).map_err(|e| Refusal::unsupported_request(e.to_string()))?;
      if birth < lo || birth > hi {
        return Err(Refusal::unsatisfiable(format!("the birth date is not {age}")));
      }
    }

    let jwk = &input.device_key;
    if jwk.kty != "EC" || jwk.crv != "P-256" {
      return Err(Refusal::bad_credential("device_key is not a P-256 key"));
    }
    let d = unb64url("device_key.d", &jwk.d).map_err(Refusal::bad_credential)?;
    let key = SigningKey::from_slice(&d).map_err(|e| Refusal::bad_credential(format!("device_key: {e}")))?;
    let device = SoftwareDevice::from_key(key, Mode::Hashed, true);

    // Offline: the BBS commitments and the ecdsa-pop preparation, independent of the request's
    // nonce (a wallet would do this ahead of time).
    let t = Instant::now();
    let committed = profile::committed(&s);
    let slot = prepare_credential(&cred, &committed, &mut OsRng).map_err(|e| Refusal::bad_credential(e.to_string()))?;
    let key_input = slot.committed_input(&cred, 0, DEVICE_KEY).map_err(|e| Refusal::bad_credential(e.to_string()))?;
    let pop_slot = prepare(&key_input, &EcdsaParams::hashed(LIMB_BITS), 4, Parallelism::Off, &mut OsRng)
      .map_err(|e| Refusal::bad_credential(e.to_string()))?;
    let offline_ms = ms(t);

    // Online.
    let stats = RefCell::new(ProveStats::default());
    let mut pop = EcdsaPopProver::new(pop_slot, Signer::Hash(&device));
    pop.stats = Some(&stats);
    let mut provers: Vec<Box<dyn PluginProver>> = vec![Box::new(pop), Box::new(PseudonymProver::new(&s.verifier_id))];
    if s.age.is_some() {
      provers.push(Box::new(DateRangeProver::new()));
    }
    let mut ps = PresentStats::default();
    let presentation = present(&s.request, &[&cred], vec![slot], provers, &mut OsRng, Some(&mut ps))
      .map_err(|e| Refusal::bad_credential(format!("the presentation failed: {e}")))?;

    // The pseudonym, from the plugin proof: "PSN\x01" ‖ nym (48 bytes) ‖ c ‖ z_m ‖ z_s.
    let parsed = parse(&presentation, std::slice::from_ref(&cred.issuer), &s.request).map_err(|e| Refusal::bad_request(e.to_string()))?;
    let nym = parsed.plugin_proofs[s.index_pseudonym].get(4..52).ok_or_else(|| Refusal::bad_request("pseudonym proof"))?;
    let mut results = Map::new();
    results.insert(s.nym_handle.clone(), Json::String(hex(&public_pseudonym(nym))));
    if let Some(h) = &s.age_handle {
      results.insert(h.clone(), Json::Bool(true));
    }

    let len = |r: (usize, usize)| r.1 - r.0;
    let plugin_ms = |i: Option<usize>| i.and_then(|i| ps.plugins.get(i)).map(|d| d.as_secs_f64() * 1e3);
    let online_ms = ps.total.as_secs_f64() * 1e3;
    let metrics = json!({
      "load_ms": self.load_ms,
      "offline_ms": offline_ms,
      "bbs_ms": ps.bbs.as_secs_f64() * 1e3,
      "ecdsa_pop_ms": plugin_ms(Some(0)),
      "device_sign_ms": stats.borrow().device_sign.as_secs_f64() * 1e3,
      "pseudonym_ms": plugin_ms(Some(s.index_pseudonym)),
      "date_range_ms": plugin_ms(s.index_age),
      "online_ms": online_ms,
      "prove_ms": offline_ms + online_ms,
      "total_ms": ms(t_all),
      "peak_memory_mb": peak.read(),
      "proof_bytes": presentation.len(),
      "presentation_bytes": presentation.len(),
      "parts": {
        "bbs_proof": len(parsed.credentials[0].bbs_range),
        "ecdsa_pop": len(parsed.plugin_ranges[0]),
        "pseudonym": len(parsed.plugin_ranges[s.index_pseudonym]),
        "date_range": s.index_age.map(|i| len(parsed.plugin_ranges[i])),
      },
      "threads": 1,
    });
    Ok(json!({
      "scheme_id": SCHEME_ID,
      "presentation": b64url(&presentation),
      "results": results,
      "metrics": metrics,
      "statement": {
        "audience": hex(&s.request.audience),
        "nonce": input.request.nonce,
        "verifier_input": String::from_utf8_lossy(&s.verifier_id),
        "committed": committed,
        "plugins": s.request.plugins.iter().map(|p| String::from_utf8_lossy(&p.plugin_id).into_owned()).collect::<Vec<_>>(),
      },
    }))
  }
}

/// The scheme as the registry pins it (`shared/registry/circuits.ts`).
pub fn scheme_json() -> Json {
  let schema = profile::schema().expect("the profile's schema");
  json!({
    "scheme_id": SCHEME_ID,
    "proof_system": PROOF_SYSTEM,
    "schema_id": schema.id(),
    "schema_digest": hex(&schema.digest()),
    "plugins": [
      String::from_utf8_lossy(cd_ecdsa_pop::PLUGIN_ID),
      String::from_utf8_lossy(cd_pseudonym::PLUGIN_ID),
      String::from_utf8_lossy(cd_date_range::PLUGIN_ID),
    ],
  })
}
