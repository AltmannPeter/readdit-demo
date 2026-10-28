//! `ZkpPresentation` (rulebook v0.4, "Presentation encoding"), for a circuit over `mso_mdoc`:
//!
//! ```cddl
//! ZkpPresentation = {
//!   "system_id"      => tstr,          ; the circuit id
//!   "proof"          => bstr,
//!   "issuer_key_set" => [+ bstr],      ; DER Document Signer certificates
//!   ? "proof_time"   => tdate,         ; present when the circuit checks validity
//!   "results"        => { * tstr => bstr .size 32 / true }
//! }
//! ```
//!
//! The Longfellow circuits check validity, so `proof_time` is required. The reader takes untrusted input:
//! it refuses unknown, duplicate or missing members, other types, and trailing bytes.

use ciborium::value::Value;

/// A value of `results`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResultValue {
  Pseudonym([u8; 32]),
  True,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Presentation {
  pub system_id: String,
  pub proof: Vec<u8>,
  pub issuer_key_set: Vec<Vec<u8>>,
  /// `YYYY-MM-DDThh:mm:ssZ`.
  pub proof_time: String,
  /// In the order of `req`.
  pub results: Vec<(String, ResultValue)>,
}

impl Presentation {
  /// The CBOR encoding.
  pub fn encode(&self) -> Result<Vec<u8>, String> {
    let results = self
      .results
      .iter()
      .map(|(k, v)| {
        let v = match v {
          ResultValue::Pseudonym(p) => Value::Bytes(p.to_vec()),
          ResultValue::True => Value::Bool(true),
        };
        (Value::Text(k.clone()), v)
      })
      .collect();
    let map = Value::Map(vec![
      (Value::Text("system_id".into()), Value::Text(self.system_id.clone())),
      (Value::Text("proof".into()), Value::Bytes(self.proof.clone())),
      (
        Value::Text("issuer_key_set".into()),
        Value::Array(self.issuer_key_set.iter().map(|c| Value::Bytes(c.clone())).collect()),
      ),
      (Value::Text("proof_time".into()), Value::Tag(0, Box::new(Value::Text(self.proof_time.clone())))),
      (Value::Text("results".into()), Value::Map(results)),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&map, &mut out).map_err(|e| format!("encoding the presentation: {e}"))?;
    Ok(out)
  }

  /// Reads a presentation.
  pub fn decode(bytes: &[u8]) -> Result<Self, String> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value: Value = ciborium::de::from_reader(&mut cursor).map_err(|e| format!("not CBOR: {e}"))?;
    if usize::try_from(cursor.position()).ok() != Some(bytes.len()) {
      return Err("trailing bytes after the presentation".into());
    }
    let Value::Map(entries) = value else { return Err("not a CBOR map".into()) };
    let (mut system_id, mut proof, mut issuer_key_set, mut proof_time, mut results) = (None, None, None, None, None);
    for (key, value) in entries {
      let Value::Text(key) = key else { return Err("a member key is not a text string".into()) };
      let slot_taken = |taken: bool| if taken { Err(format!("member {key} appears twice")) } else { Ok(()) };
      match key.as_str() {
        "system_id" => {
          slot_taken(system_id.is_some())?;
          let Value::Text(t) = value else { return Err("system_id is not a text string".into()) };
          system_id = Some(t);
        }
        "proof" => {
          slot_taken(proof.is_some())?;
          let Value::Bytes(b) = value else { return Err("proof is not a byte string".into()) };
          proof = Some(b);
        }
        "issuer_key_set" => {
          slot_taken(issuer_key_set.is_some())?;
          let Value::Array(items) = value else { return Err("issuer_key_set is not an array".into()) };
          let certs = items
            .into_iter()
            .map(|i| if let Value::Bytes(b) = i { Ok(b) } else { Err("an issuer_key_set element is not a byte string".to_string()) })
            .collect::<Result<Vec<_>, _>>()?;
          if certs.is_empty() {
            return Err("issuer_key_set is empty".into());
          }
          issuer_key_set = Some(certs);
        }
        "proof_time" => {
          slot_taken(proof_time.is_some())?;
          let Value::Tag(0, inner) = value else { return Err("proof_time is not a tdate (tag 0)".into()) };
          let Value::Text(t) = *inner else { return Err("proof_time is not a tdate (tag 0)".into()) };
          proof_time = Some(t);
        }
        "results" => {
          slot_taken(results.is_some())?;
          let Value::Map(items) = value else { return Err("results is not a map".into()) };
          let mut out: Vec<(String, ResultValue)> = Vec::new();
          for (k, v) in items {
            let Value::Text(k) = k else { return Err("a results key is not a text string".into()) };
            if out.iter().any(|(seen, _)| *seen == k) {
              return Err(format!("results key {k} appears twice"));
            }
            let v = match v {
              Value::Bytes(b) => ResultValue::Pseudonym(b.try_into().map_err(|_| format!("results.{k} is not 32 bytes"))?),
              Value::Bool(true) => ResultValue::True,
              _ => return Err(format!("results.{k} is neither a 32-byte string nor true")),
            };
            out.push((k, v));
          }
          // Empty is allowed from rulebook v0.5 on (`{ * tstr => ResultValue }`, "empty if _req
          // holds only assertions"); v0.4's `+` is the verifier's check, which knows the version.
          results = Some(out);
        }
        other => return Err(format!("unknown member {other}")),
      }
    }
    Ok(Presentation {
      system_id: system_id.ok_or("no system_id")?,
      proof: proof.ok_or("no proof")?,
      issuer_key_set: issuer_key_set.ok_or("no issuer_key_set")?,
      proof_time: proof_time.ok_or("no proof_time, which this circuit needs")?,
      results: results.ok_or("no results")?,
    })
  }
}
