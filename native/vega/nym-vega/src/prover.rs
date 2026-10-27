//! The holder's native steps, as a phone would run them. The wallet brings the credential
//! material to each step; the prover keeps only the prover key, which setup makes the same every
//! time.
//!
//! 1. [`Prover::sign`]: the device key signs DeviceAuthentication (ES256). The wallet's PIN screen
//!    stands for the phone's unlock; any PIN unlocks in this demo, so the prover takes none.
//! 2. [`Prover::witness`]: the credential taken apart, every holder-side check, and the witness of
//!    every circuit instance (SPEC.md V5).
//! 3. [`Prover::prove`]: prepare and prove (SPEC.md V6), and the presentation.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::ecdsa::{Signature as EcdsaSignature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json, json};
use vega_age::app::{self, Assignment, ProverKey};
use vega_age::gadgets::lc::to_be;
use vega_age::gadgets::p256::{PublicKey, Signature};
use vega_age::mdoc::{MdocNymCore, MdocWitness};
use vega_age::presentation::{Presentation as CorePresentation, Public, Time};
use vega_age::pseudonym::{self, NymMessages, NymPublic};
use vega_age::request::Request;
use vega_age::table::sha256;

use crate::circuit::{BIRTH_DATE, CIRCUIT_ID, DOC_TYPE, PROOF_SYSTEM, PUBLIC_INPUTS, SSC};
use crate::error::Refusal;
use crate::handover::{self, Handover};
use crate::measure::{Heap, Peak, mb, ms};
use crate::presentation::{Presentation, ResultValue};
use crate::request::{RequestObject, Rulebook, Statement, statement_for};
use crate::{dates, hex, keys, mdoc, threads, unb64url, unhex, x509};

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
  /// One thread per core for the witness and the proof; one thread when false or absent.
  #[serde(default)]
  pub parallel: bool,
  /// The rulebook version the wallet read the request under: "0.4" (absent) or "0.5".
  #[serde(default)]
  pub rulebook: Option<String>,
}

/// The witness of one presentation, which [`Prover::prove`] consumes. It lives for one request.
pub struct WitnessData {
  assignment: Assignment,
  presentation: Presentation,
  results: Map<String, Json>,
  witness_ms: f64,
  /// The heap held before the witness step, and the most it held during it (measure::Heap).
  heap_base: usize,
  witness_high: usize,
  parallel: bool,
  /// What the witness step reports: its time, sizes and the public values it claims.
  pub summary: Json,
}

pub struct Prover {
  pk: ProverKey,
  pub shapes_sha256: [u8; 32],
  pub load_ms: f64,
  /// The heap the loaded keys or circuits hold (measure::Heap; one load at a time).
  pub keys_mb: Option<f64>,
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

/// The core public values (32 bytes of hex each), grouped by input in the registry order.
fn public_inputs(values: &[String]) -> Json {
  let mut at = 0;
  let groups: Vec<Json> = PUBLIC_INPUTS
    .iter()
    .map(|(name, count)| {
      let group = values.get(at..at + count).unwrap_or(&[]).to_vec();
      at += count;
      json!({ "name": name, "values": group })
    })
    .collect();
  Json::Array(groups)
}

impl Prover {
  /// Builds the prover key from `shapes.zst`.
  pub fn load(shapes: &Path) -> Result<Self, String> {
    let _one = crate::measure::exclusive()?;
    let heap = Heap::start();
    let loaded = keys::prover_key(shapes)?;
    Ok(Prover { pk: loaded.key, shapes_sha256: loaded.shapes_sha256, load_ms: loaded.load_ms, keys_mb: mb(heap.held()) })
  }

  pub fn info(&self) -> Json {
    json!({
      "service": "prover",
      "implementation": "Vega: microsoft/vega-prover c0ee259 (VegaMcZkSNARK, T256HyraxEngine), nym-auth-circuits vega-age; Node addon",
      "version": env!("CARGO_PKG_VERSION"),
      "stub": false,
      "circuits": [{
        "system_id": CIRCUIT_ID,
        "proof_system": PROOF_SYSTEM,
        "shapes_sha256": hex(&self.shapes_sha256),
        "public_inputs": PUBLIC_INPUTS.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
      }],
      "load_ms": self.load_ms,
      "keys_mb": self.keys_mb,
      "max_threads": threads::cores(),
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

  /// Step 2: takes the credential apart, makes every holder-side check, and computes the witness.
  pub fn witness(&self, input: &WitnessInput) -> Result<WitnessData, Refusal> {
    let t = Instant::now();
    let heap = Heap::start();
    if input.system_id != CIRCUIT_ID {
      return Err(Refusal::unsupported_circuit(format!("{} is not {CIRCUIT_ID}", input.system_id)));
    }
    // The time of the proof (proof_time), read first: v0.5 computes an age range's bounds from its date.
    let now: Time = dates::now().map_err(Refusal::bad_request)?;
    let rulebook = Rulebook::parse(input.rulebook.as_deref())?;
    let s: Statement = statement_for(&input.request, &input.credential_query_id, &input.handover, rulebook, Some(now.date))?;
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
      .and_then(|vk| ecdsa(&rs).and_then(|sig| vk.verify(&m.sig_structure, &sig).map_err(|e| e.to_string())))
      .map_err(|e| bad(format!("the issuer signature does not verify under the Document Signer's key: {e}")))?;
    if !m.digests_listed() {
      return Err(bad("the MSO does not list every item's digest"));
    }
    let seed: [u8; 16] = unhex("secret_seed", &input.secret_seed).map_err(bad)?;
    let ssc = m.ssc().map_err(bad)?;
    if sha256(&seed) != ssc {
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
    let (now_s, from_s, until_s) = (
      dates::unix(&now).map_err(Refusal::bad_request)?,
      dates::unix(&m.valid_from).map_err(bad)?,
      dates::unix(&m.valid_until).map_err(bad)?,
    );
    if !(from_s <= now_s && now_s < until_s) {
      return Err(Refusal::unsatisfiable(format!(
        "the credential is valid from {} until {}, not at {}",
        m.valid_from.text(),
        m.valid_until.text(),
        now.text()
      )));
    }
    let birth = m.birth_date().map_err(bad)?;
    if !s.age.holds(&birth) {
      return Err(Refusal::unsatisfiable("the birth date lies outside the requested range"));
    }

    let request = Request::mdoc(DOC_TYPE, BIRTH_DATE).map_err(Refusal::bad_request)?;
    let public = Public {
      issuer_key,
      born_from: s.age.earliest(),
      born_by: s.age.cutoff(),
      now,
      challenge: s.challenge,
      request,
    };
    let nym = pseudonym::pseudonym(&seed, &s.verifier_input);
    let messages = NymMessages { ssc: m.item(SSC).map_err(bad)?, secret_seed: &seed, verifier_input: &s.verifier_input };
    let birth_item = m.item(BIRTH_DATE).map_err(bad)?;
    let issuer_signature = Signature::from_rs(&m.r, &m.s);
    let device_signature = Signature::from_rs(
      device[..32].try_into().map_err(|_| bad("r"))?,
      device[32..].try_into().map_err(|_| bad("s"))?,
    );
    let w = MdocWitness::full(&m.sig_structure, birth_item, messages, issuer_key, issuer_signature).map_err(bad)?;
    let table = w.table.clone();
    let core = MdocNymCore {
      witness: Some(Arc::new(w)),
      presentation: Some(CorePresentation { public, device_signature }),
      nym: Some(NymPublic { verifier_input: s.verifier_input, pseudonym: nym }),
    };
    let assignment = threads::pool(input.parallel)
      .install(|| app::witness(&app::steps(&table), &core))
      .map_err(|e| bad(format!("witness: {e:?}")))?;
    let witness_ms = ms(t);

    let mut results = Map::new();
    let mut result_values = vec![(s.nym_handle.clone(), ResultValue::Pseudonym(nym))];
    results.insert(s.nym_handle.clone(), Json::String(hex(&nym)));
    if let Some(h) = &s.age_handle {
      result_values.push((h.clone(), ResultValue::True));
      results.insert(h.clone(), Json::Bool(true));
    }
    let [shared, precommitted, rest, public_count] = assignment.counts();
    let summary = json!({
      "proof_time": now.text(),
      "results": results,
      "public_inputs": public_inputs(&assignment.core.public_values.iter().map(|v| hex(&to_be(v))).collect::<Vec<_>>()),
      "counts": { "shared": shared, "precommitted": precommitted, "rest": rest, "public": public_count },
      "metrics": { "witness_ms": witness_ms, "heap_mb": mb(heap.high() - heap.base()), "threads": threads::pool(input.parallel).current_num_threads() },
    });
    Ok(WitnessData {
      presentation: Presentation {
        system_id: CIRCUIT_ID.into(),
        proof: Vec::new(),
        issuer_key_set: vec![m.document_signer.clone()],
        proof_time: now.text(),
        results: result_values,
      },
      assignment,
      results,
      witness_ms,
      heap_base: heap.base(),
      witness_high: heap.high(),
      parallel: input.parallel,
      summary,
    })
  }

  /// Step 3: prepares and proves from the witness, and encodes the presentation.
  pub fn prove(&self, w: WitnessData) -> Result<Json, String> {
    let peak = Peak::start();
    let heap = Heap::start();
    let t = Instant::now();
    let (steps, core) = (w.assignment.steps(), w.assignment.core());
    let pool = threads::pool(w.parallel);
    let (proof, _) = pool.install(|| {
      let prepared = app::prepare(&self.pk, &steps, &core).map_err(|e| format!("prepare: {e:?}"))?;
      app::prove(&self.pk, &steps, &core, prepared).map_err(|e| format!("prove: {e:?}"))
    })?;
    let prove_ms = ms(t);
    let peak_mb = peak.read();
    // The proof's working memory: the most the witness and prove steps held at once, above what
    // was held before the witness step (the witness itself stays held between the two).
    let heap_mb = mb(heap.high().max(w.witness_high).saturating_sub(w.heap_base));
    // The proof's parts by field (two levels), when they add up to the bytes bincode writes.
    let parts = crate::sizes::breakdown(&proof, 2).ok();
    let proof = bincode::serialize(&proof).map_err(|e| format!("serializing the proof: {e}"))?;
    let proof_bytes = proof.len();
    let proof_parts = parts.filter(|(total, _)| *total == proof_bytes as u64).map(|(_, nodes)| crate::sizes::to_json(&nodes));
    let presentation = Presentation { proof, ..w.presentation }.encode()?;
    Ok(json!({
      "system_id": CIRCUIT_ID,
      "presentation": crate::b64url(&presentation),
      "results": w.results,
      "metrics": {
        "load_ms": self.load_ms,
        "keys_mb": self.keys_mb,
        "witness_ms": w.witness_ms,
        "prove_ms": prove_ms,
        "total_ms": ((w.witness_ms + prove_ms) * 1e3).round() / 1e3,
        "heap_mb": heap_mb,
        // The witness held from the witness step into the prove step (part of heap_mb).
        "witness_mb": mb(heap.base().saturating_sub(w.heap_base)),
        "peak_memory_mb": peak_mb,
        "proof_bytes": proof_bytes,
        "proof_parts": proof_parts,
        "presentation_bytes": presentation.len(),
        "threads": pool.current_num_threads(),
      },
    }))
  }
}
