//! The holder's native steps, as a phone would run them, with the same interface as the Vega
//! prover (`native/vega`, nym-vega `prover`). The wallet brings the credential material to each
//! step; the prover keeps only the circuits.
//!
//! 1. [`Prover::sign`]: the device key signs DeviceAuthentication (ES256). The wallet's PIN screen
//!    stands for the phone's unlock; any PIN unlocks in this demo, so the prover takes none.
//! 2. [`Prover::witness`]: the credential taken apart, every holder-side check, and both input
//!    vectors (SPEC.md L3 to L5).
//! 3. [`Prover::prove`]: the two-circuit proof (SPEC.md L6.2), and the presentation.

use std::path::Path;
use std::time::Instant;

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature as EcdsaSignature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json, json};

use crate::circuit::{CIRCUIT_ID, DOC_TYPE, PROOF_SYSTEM, PUBLIC_INPUTS, RUNTIME};
use crate::error::Refusal;
use crate::handover::{self, Handover};
use crate::measure::{Heap, Peak, mb, ms};
use crate::presentation::{Presentation, ResultValue};
use crate::request::{RequestObject, Statement, statement};
use crate::witness::{self, Private, Public};
use crate::x509::PublicKey;
use crate::zk::{Circuits, ZkProverPair};
use crate::{dates, hex, mdoc, unb64url, unhex, x509};

/// The device key as the wallet holds it: a P-256 JWK with its private part.
#[derive(Clone, Debug, Deserialize)]
pub struct DeviceKey {
  pub kty: String,
  pub crv: String,
  pub x: String,
  pub y: String,
  pub d: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SignInput {
  pub device_key: DeviceKey,
  pub doc_type: String,
  pub handover: Handover,
}

#[derive(Clone, Debug, Serialize)]
pub struct SignOutput {
  /// r ‖ s, hex.
  pub device_signature: String,
  pub session_transcript: String,
  pub challenge_digest: String,
  pub metrics: Json,
}

/// The credential as the wallet holds it.
#[derive(Clone, Debug, Deserialize)]
pub struct Credential {
  pub format: String,
  pub doctype: String,
  /// base64url IssuerSigned.
  pub issuer_signed: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct WitnessInput {
  pub system_id: String,
  pub credential_query_id: String,
  pub request: RequestObject,
  pub handover: Handover,
  pub credential: Credential,
  /// 16 bytes, hex.
  pub secret_seed: String,
  /// r ‖ s, hex, from [`Prover::sign`].
  pub device_signature: String,
}

/// The witness of one presentation, which [`Prover::prove`] consumes. It lives for one request.
pub struct WitnessData {
  witness: witness::Witness,
  transcript_seed: Vec<u8>,
  presentation: Presentation,
  results: Map<String, Json>,
  witness_ms: f64,
  /// The heap held before the witness step, and the most it held during it (measure::Heap).
  heap_base: usize,
  witness_high: usize,
  /// What the witness step reports: its time, sizes and the public values it claims.
  pub summary: Json,
}

pub struct Prover {
  pair: ZkProverPair,
  pub circuits_sha256: [u8; 32],
  pub load_ms: f64,
}

fn bad(e: impl std::fmt::Display) -> Refusal {
  Refusal::bad_credential(e.to_string())
}

fn verifying_key(key: &PublicKey) -> Result<VerifyingKey, String> {
  let point = [&[0x04][..], &key.x, &key.y].concat();
  VerifyingKey::from_sec1_bytes(&point).map_err(|e| format!("not a P-256 point: {e}"))
}

fn ecdsa(rs: &[u8; 64]) -> Result<EcdsaSignature, String> {
  EcdsaSignature::from_slice(rs).map_err(|e| format!("not an ECDSA signature: {e}"))
}

/// The registry's description of the circuits, for both sides' `info`.
pub fn circuit_info(sha256: &[u8; 32]) -> Json {
  json!([{
    "system_id": CIRCUIT_ID,
    "proof_system": PROOF_SYSTEM,
    "artifact_sha256": hex(sha256),
    "public_inputs": PUBLIC_INPUTS.iter().map(|(n, _, _)| *n).collect::<Vec<_>>(),
  }])
}

/// The public values a witness claims, by input, as the guide shows them: text for T, E and C,
/// hex for the rest. The tags and a_v exist only once the proof is made.
fn public_summary(p: &Public, nym: &[u8; 32]) -> Json {
  let mut q = [0u8; 64];
  q[..32].copy_from_slice(&p.issuer_key.x);
  q[32..].copy_from_slice(&p.issuer_key.y);
  Json::Array(
    [
      ("proof_time", vec![p.time.clone()]),
      ("age_check.ge", vec![p.earliest.clone()]),
      ("age_check.le", vec![p.cutoff.clone()]),
      ("pseudonym.verifier_input", vec![hex(&p.verifier_input)]),
      ("mac.tags", vec![]),
      ("mac.a_v", vec![]),
      ("results.nym", vec![hex(nym)]),
      ("issuer_key_set", vec![hex(&q[..32]), hex(&q[32..])]),
      ("session_transcript", vec![hex(&p.challenge)]),
    ]
    .into_iter()
    .map(|(name, values)| json!({ "name": name, "values": values }))
    .collect(),
  )
}

impl Prover {
  /// Reads the circuits in `dir` (`circuits/mdoc`).
  pub fn load(dir: &Path) -> Result<Self, String> {
    let c = Circuits::load(dir)?;
    let (circuits_sha256, load_ms) = (c.sha256, c.load_ms);
    Ok(Prover { pair: ZkProverPair::new(c), circuits_sha256, load_ms })
  }

  pub fn info(&self) -> Json {
    json!({
      "service": "prover",
      "implementation": format!("Longfellow: {RUNTIME}, nym-auth-circuits LFC2 mdoc circuits; Node addon"),
      "version": env!("CARGO_PKG_VERSION"),
      "stub": false,
      "circuits": circuit_info(&self.circuits_sha256),
      "load_ms": self.load_ms,
      "threads": 1,
    })
  }

  /// Step 1: the device key signs DeviceAuthentication over the SessionTranscript of `handover`.
  pub fn sign(&self, input: &SignInput) -> Result<SignOutput, Refusal> {
    let t = Instant::now();
    if input.doc_type != DOC_TYPE {
      return Err(Refusal::unsupported_request(format!("docType {} is not {DOC_TYPE}", input.doc_type)));
    }
    let k = &input.device_key;
    if k.kty != "EC" || k.crv != "P-256" {
      return Err(bad("the device key is not a P-256 EC key"));
    }
    let d: [u8; 32] = unb64url("device_key.d", &k.d).map_err(bad)?.try_into().map_err(|_| bad("device_key.d is not 32 bytes"))?;
    let signing = SigningKey::from_bytes(&d.into()).map_err(|e| bad(format!("device_key.d: {e}")))?;
    let point = signing.verifying_key().to_encoded_point(false);
    let (x, y) = (point.x().ok_or_else(|| bad("no x"))?, point.y().ok_or_else(|| bad("no y"))?);
    if crate::b64url(x) != k.x || crate::b64url(y) != k.y {
      return Err(bad("device_key.x and y are not the public key of device_key.d"));
    }
    let transcript = input.handover.session_transcript().map_err(Refusal::bad_request)?;
    let message = handover::device_message(&transcript, DOC_TYPE);
    let signature: EcdsaSignature = signing.sign(&message);
    Ok(SignOutput {
      device_signature: hex(&signature.to_bytes()),
      challenge_digest: hex(&handover::challenge_digest(&transcript, DOC_TYPE)),
      session_transcript: hex(&transcript),
      metrics: json!({ "sign_ms": ms(t) }),
    })
  }

  /// Step 2: takes the credential apart, makes every holder-side check, and builds both vectors.
  pub fn witness(&self, input: &WitnessInput) -> Result<WitnessData, Refusal> {
    let t = Instant::now();
    let heap = Heap::start();
    if input.system_id != CIRCUIT_ID {
      return Err(Refusal::unsupported_circuit(format!("{} is not {CIRCUIT_ID}", input.system_id)));
    }
    let s: Statement = statement(&input.request, &input.credential_query_id, &input.handover)?;
    if s.offered_ids.as_ref().is_some_and(|ids| !ids.iter().any(|id| id == CIRCUIT_ID))
      || s.offered_systems.as_ref().is_some_and(|ps| !ps.iter().any(|p| p == PROOF_SYSTEM))
    {
      return Err(Refusal::unsupported_circuit("the request does not offer this circuit"));
    }
    if input.credential.format != "mso_mdoc" || input.credential.doctype != DOC_TYPE {
      return Err(bad(format!("the credential is not an mso_mdoc of {DOC_TYPE}")));
    }
    let m = mdoc::parse(&input.credential.issuer_signed).map_err(bad)?;
    if m.doc_type != DOC_TYPE {
      return Err(bad(format!("the MSO's docType {} is not {DOC_TYPE}", m.doc_type)));
    }
    let signer = x509::parse(&m.document_signer).map_err(|e| bad(format!("x5chain: {e}")))?;
    let issuer_key = signer.key;
    let mut rs = [0u8; 64];
    rs[..32].copy_from_slice(&m.r);
    rs[32..].copy_from_slice(&m.s);
    verifying_key(&issuer_key)
      .and_then(|vk| ecdsa(&rs).and_then(|sig| vk.verify(&m.signed, &sig).map_err(|e| e.to_string())))
      .map_err(|e| bad(format!("the issuer signature does not verify under the Document Signer's key: {e}")))?;
    if !m.digests_listed() {
      return Err(bad("the MSO does not list the items' digests"));
    }
    let seed: [u8; 16] = unhex("secret_seed", &input.secret_seed).map_err(bad)?;
    if crate::sha256(&seed) != m.ssc {
      return Err(bad("secret_seed does not open the credential's ssc"));
    }
    let device: [u8; 64] = unhex("device_signature", &input.device_signature).map_err(bad)?;
    verifying_key(&m.device_key)
      .and_then(|vk| {
        let sig = ecdsa(&device)?;
        vk.verify(&handover::device_message(&s.session_transcript, DOC_TYPE), &sig).map_err(|e| e.to_string())
      })
      .map_err(|e| bad(format!("the device signature does not verify under the credential's device key: {e}")))?;

    // Holder data against the request: validity now, and the birth date in [E, C].
    let now = dates::now().map_err(Refusal::bad_request)?;
    let (now_s, from_s, until_s) = (dates::unix(&now), dates::unix(&m.valid_from), dates::unix(&m.valid_until));
    if !(from_s <= now_s && now_s < until_s) {
      return Err(Refusal::unsatisfiable(format!(
        "the credential is valid from {} until {}, not at {}",
        m.valid_from.text(),
        m.valid_until.text(),
        now.text()
      )));
    }
    if !s.age.holds(&m.birth_date) {
      return Err(Refusal::unsatisfiable("the birth date lies outside the requested range"));
    }

    let public = Public {
      time: now.text(),
      earliest: s.age.earliest(),
      cutoff: s.age.cutoff(),
      verifier_input: s.verifier_input,
      issuer_key,
      challenge: s.challenge,
    };
    let private = Private { mdoc: &m, secret_seed: seed, device_signature: device };
    let w = witness::witness(&self.pair.layout, &public, &private).map_err(|e| bad(format!("witness: {e}")))?;
    let nym = w.nym;
    let witness_ms = ms(t);

    let mut results = Map::new();
    let mut result_values = vec![(s.nym_handle.clone(), ResultValue::Pseudonym(nym))];
    results.insert(s.nym_handle.clone(), Json::String(hex(&nym)));
    if let Some(h) = &s.age_handle {
      result_values.push((h.clone(), ResultValue::True));
      results.insert(h.clone(), Json::Bool(true));
    }
    let l = &self.pair.layout;
    let summary = json!({
      "proof_time": now.text(),
      "results": results,
      "public_inputs": public_summary(&public, &nym),
      "counts": {
        "hash": { "inputs": l.hash.ninputs, "public": l.hash.npub },
        "signature": { "inputs": l.sig.ninputs, "public": l.sig.npub },
      },
      "metrics": { "witness_ms": witness_ms, "heap_mb": mb(heap.high() - heap.base()) },
    });
    Ok(WitnessData {
      witness: w,
      transcript_seed: s.session_transcript.clone(),
      presentation: Presentation {
        system_id: CIRCUIT_ID.into(),
        proof: Vec::new(),
        issuer_key_set: vec![m.document_signer.clone()],
        proof_time: now.text(),
        results: result_values,
      },
      results,
      witness_ms,
      heap_base: heap.base(),
      witness_high: heap.high(),
      summary,
    })
  }

  /// Step 3: proves both circuits from the witness, and encodes the presentation.
  pub fn prove(&self, w: WitnessData) -> Result<Json, String> {
    let peak = Peak::start();
    let heap = Heap::start();
    let t = Instant::now();
    let proved = self.pair.prove(w.witness, &w.transcript_seed)?;
    let prove_ms = ms(t);
    let peak_mb = peak.read();
    // The proof's working memory: the most the witness and prove steps held at once, above what
    // was held before the witness step (the witness itself stays held between the two).
    let heap_mb = mb(heap.high().max(w.witness_high).saturating_sub(w.heap_base));
    let proof_bytes = proved.proof.len();
    let presentation = Presentation { proof: proved.proof, ..w.presentation }.encode()?;
    Ok(json!({
      "system_id": CIRCUIT_ID,
      "presentation": crate::b64url(&presentation),
      "results": w.results,
      "metrics": {
        "load_ms": self.load_ms,
        "witness_ms": w.witness_ms,
        "prove_ms": prove_ms,
        "total_ms": ((w.witness_ms + prove_ms) * 1e3).round() / 1e3,
        "heap_mb": heap_mb,
        "peak_memory_mb": peak_mb,
        "proof_bytes": proof_bytes,
        "presentation_bytes": presentation.len(),
        "threads": 1,
      },
    }))
  }
}
