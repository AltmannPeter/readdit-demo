//! `ZkpPresentation` (rulebook v0.4 and v0.5, "Presentation encoding"), for the `bbs_cd` scheme:
//!
//! ```cddl
//! ZkpPresentation = {
//!   "system_id"      => tstr,          ; the scheme id
//!   "proof"          => bstr,          ; the bbs-cd-plugins envelope (BCDP)
//!   "issuer_key_set" => [+ bstr],      ; one BBS issuer public key, 96 bytes
//!   ? "proof_time"   => tdate,         ; v0.5, when _req has age_check (bbs_cd checks no validity)
//!   "results"        => { * tstr => bstr .size 48 / true }  ; v0.4: age_check's true
//! }
//! ```
//!
//! The pseudonym is the compressed G1 point of `hashdh-bls12381g1` (48 bytes). `proof_time` is a tag
//! 0 text string `YYYY-MM-DDThh:mm:ssZ`; whether one may or must be there is the verifier's rule
//! (by rulebook version). The reader takes untrusted input: it refuses unknown, duplicate or missing
//! members, other types and trailing bytes.

use ciborium::value::Value;

/// A value of `results`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResultValue {
  Pseudonym([u8; 48]),
  True,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Presentation {
  pub system_id: String,
  pub proof: Vec<u8>,
  pub issuer_key_set: Vec<Vec<u8>>,
  /// v0.5 with an age check: the time the bounds are computed for, `YYYY-MM-DDThh:mm:ssZ`.
  pub proof_time: Option<String>,
  /// In the order of `_req`.
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
    let mut members = vec![
      (Value::Text("system_id".into()), Value::Text(self.system_id.clone())),
      (Value::Text("proof".into()), Value::Bytes(self.proof.clone())),
      (Value::Text("issuer_key_set".into()), Value::Array(self.issuer_key_set.iter().map(|k| Value::Bytes(k.clone())).collect())),
    ];
    if let Some(t) = &self.proof_time {
      members.push((Value::Text("proof_time".into()), Value::Tag(0, Box::new(Value::Text(t.clone())))));
    }
    members.push((Value::Text("results".into()), Value::Map(results)));
    let map = Value::Map(members);
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
          let keys = items
            .into_iter()
            .map(|i| if let Value::Bytes(b) = i { Ok(b) } else { Err("an issuer_key_set element is not a byte string".to_string()) })
            .collect::<Result<Vec<_>, _>>()?;
          if keys.is_empty() {
            return Err("issuer_key_set is empty".into());
          }
          issuer_key_set = Some(keys);
        }
        "proof_time" => {
          slot_taken(proof_time.is_some())?;
          let Value::Tag(0, inner) = value else { return Err("proof_time is not a tag 0 date-time".into()) };
          let Value::Text(t) = *inner else { return Err("proof_time is not a tag 0 text string".into()) };
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
              Value::Bytes(b) => ResultValue::Pseudonym(b.try_into().map_err(|_| format!("results.{k} is not 48 bytes"))?),
              Value::Bool(true) => ResultValue::True,
              _ => return Err(format!("results.{k} is neither a 48-byte string nor true")),
            };
            out.push((k, v));
          }
          results = Some(out);
        }
        other => return Err(format!("unknown member {other}")),
      }
    }
    Ok(Presentation {
      system_id: system_id.ok_or("no system_id")?,
      proof: proof.ok_or("no proof")?,
      issuer_key_set: issuer_key_set.ok_or("no issuer_key_set")?,
      proof_time,
      results: results.ok_or("no results")?,
    })
  }
}
