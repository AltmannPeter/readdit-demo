//! Fixture encoding contract from IMPLEMENTERS.md Sections 5 and 8.
use bls12_381::G1Projective;
use serde_json::{Value, json};

use crate::BbsError;
use crate::primitives::{decode_G1, point_to_octets_E1};
use crate::types::{DisclosureState, Index, InitResult, Message, MessageType, ScalarInput};

#[derive(Debug)]
pub(super) enum RunError {
    Harness(String),
    Operation(BbsError),
    InputInvalid(String),
}
impl From<BbsError> for RunError {
    /// Spec 1.3: preserve operation INVALID and ABORT separately from schema errors.
    fn from(error: BbsError) -> Self {
        Self::Operation(error)
    }
}
pub(super) type RunResult<T> = Result<T, RunError>;

/// Fixture schema: every required field must exist; null is never missing.
pub(super) fn field<'a>(value: &'a Value, field: &str) -> RunResult<&'a Value> {
    value
        .as_object()
        .and_then(|object| object.get(field))
        .ok_or_else(|| RunError::Harness(format!("missing field {field}")))
}
/// Fixture schema: strings are not coerced from other JSON types.
pub(super) fn string<'a>(value: &'a Value, name: &str) -> RunResult<&'a str> {
    field(value, name)?
        .as_str()
        .ok_or_else(|| RunError::Harness(format!("{name}: expected string")))
}
/// Fixture schema: arrays are not coerced from other JSON types.
pub(super) fn array<'a>(value: &'a Value, name: &str) -> RunResult<&'a Vec<Value>> {
    field(value, name)?
        .as_array()
        .ok_or_else(|| RunError::Harness(format!("{name}: expected array")))
}
/// Fixture schema: lowercase hex only, no prefixes, separators or odd-length values.
pub(super) fn unhex(value: &str) -> RunResult<Vec<u8>> {
    if value.len() % 2 != 0
        || !value
            .bytes()
            .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
    {
        return Err(RunError::Harness(
            "expected even-length lowercase hex".into(),
        ));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };
            Ok((digit(pair[0]) << 4) | digit(pair[1]))
        })
        .collect()
}
/// Fixture schema: decode octets while preserving empty octet strings.
pub(super) fn bytes(value: &Value, name: &str) -> RunResult<Vec<u8>> {
    unhex(string(value, name)?)
}
/// Spec 1.4.3: preserve all raw 256 bits rather than reducing into the field.
pub(super) fn scalar(value: &str) -> RunResult<ScalarInput> {
    let raw = unhex(value)?;
    Ok(ScalarInput(raw.try_into().map_err(|_| {
        RunError::Harness("scalar must contain exactly 32 octets".into())
    })?))
}
/// Fixture schema: arrays of unreduced scalar inputs.
pub(super) fn scalars(value: &Value, name: &str) -> RunResult<Vec<ScalarInput>> {
    array(value, name)?
        .iter()
        .map(|v| {
            scalar(
                v.as_str().ok_or_else(|| {
                    RunError::Harness(format!("{name}: scalar must be a hex string"))
                })?,
            )
        })
        .collect()
}
/// Spec 3.3.2.1: preserve message value kind separately from the type vector.
pub(super) fn messages(value: &Value, name: &str) -> RunResult<Vec<Message>> {
    array(value, name)?
        .iter()
        .map(|v| {
            if let Some(octets) = v.as_str() {
                return Ok(Message::Octets(unhex(octets)?));
            }
            if v.as_object()
                .is_some_and(|o| o.len() == 1 && o.contains_key("scalar"))
            {
                return Ok(Message::Scalar(scalar(string(v, "scalar")?)?));
            }
            Err(RunError::Harness(format!(
                "{name}: expected hex string or scalar object"
            )))
        })
        .collect()
}
/// Spec 4.1.4: unknown tokens reach the library predicate unchanged.
pub(super) fn message_types(value: &Value, name: &str) -> RunResult<Vec<MessageType>> {
    array(value, name)?
        .iter()
        .map(|v| {
            Ok(
                match v
                    .as_str()
                    .ok_or_else(|| RunError::Harness(format!("{name}: expected token string")))?
                {
                    "OCTETS" => MessageType::OCTETS,
                    "SCALAR" => MessageType::SCALAR,
                    other => MessageType::Unknown(other.into()),
                },
            )
        })
        .collect()
}
/// Spec 3.3.2: unknown disclosure tokens reach library validation unchanged.
pub(super) fn disclosures(value: &Value, name: &str) -> RunResult<Vec<DisclosureState>> {
    array(value, name)?
        .iter()
        .map(|v| {
            Ok(
                match v
                    .as_str()
                    .ok_or_else(|| RunError::Harness(format!("{name}: expected token string")))?
                {
                    "DISCLOSE" => DisclosureState::DISCLOSE,
                    "COMMIT" => DisclosureState::COMMIT,
                    "HIDE" => DisclosureState::HIDE,
                    other => DisclosureState::Unknown(other.into()),
                },
            )
        })
        .collect()
}
/// Spec Section 5: noninteger JSON numbers remain input to valid_indexes.
pub(super) fn indexes(value: &Value, name: &str) -> RunResult<Vec<Index>> {
    array(value, name)?
        .iter()
        .map(|v| match v {
            Value::Number(n) => Ok(n
                .as_u64()
                .map(Index::Integer)
                .unwrap_or_else(|| Index::Other(n.to_string()))),
            _ => Err(RunError::Harness(format!("{name}: expected index number"))),
        })
        .collect()
}
/// Fixture schema: count is an unsigned integer, not a scalar or fraction.
pub(super) fn count(value: &Value, name: &str) -> RunResult<u64> {
    field(value, name)?
        .as_u64()
        .ok_or_else(|| RunError::Harness(format!("{name}: expected unsigned integer")))
}
/// Spec 4.2.4.6: inventory boundary point rejections independently of JSON failures.
pub(super) fn points(
    value: &Value,
    name: &str,
    allow_identity: bool,
) -> RunResult<Vec<G1Projective>> {
    array(value, name)?
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let text = v.as_str().ok_or_else(|| {
                RunError::Harness(format!("{name}[{i}]: expected point hex string"))
            })?;
            let raw = unhex(text)?;
            decode_G1(&raw, allow_identity).map_err(|e| {
                RunError::InputInvalid(format!("{name}[{i}]: point decoding rejected input ({e})"))
            })
        })
        .collect()
}
/// Spec 3.7.1: decode fixture initialization points with identity allowed.
pub(super) fn init_result(value: &Value) -> RunResult<InitResult> {
    let point = |name: &str| -> RunResult<G1Projective> {
        let raw = bytes(value, name)?;
        decode_G1(&raw, true).map_err(|e| {
            RunError::InputInvalid(format!(
                "initRes.{name}: point decoding rejected input ({e})"
            ))
        })
    };
    Ok(InitResult {
        A_bar: point("A_bar")?,
        B_bar: point("B_bar")?,
        D: point("D")?,
        T1: point("T1")?,
        T2: point("T2")?,
        domain: scalar(string(value, "domain")?)?,
        C_tildes: points(value, "C_tildes", true)?,
    })
}
/// Fixture encoding: canonical lowercase octets.
pub(super) fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}
/// Spec 4.2.4.1: scalar outputs retain their complete fixed width.
pub(super) fn scalar_values(values: &[ScalarInput]) -> Value {
    json!(values.iter().map(|s| hex(&s.0)).collect::<Vec<_>>())
}
/// Spec 4.2.4.6: canonical compressed point output.
pub(super) fn point_values(values: &[G1Projective]) -> Value {
    json!(
        values
            .iter()
            .map(|p| hex(&point_to_octets_E1(p)))
            .collect::<Vec<_>>()
    )
}
/// Spec 3.7.1: fixture field names match the seven-element init result.
pub(super) fn init_value(init: &InitResult) -> Value {
    json!({"A_bar":hex(&point_to_octets_E1(&init.A_bar)),"B_bar":hex(&point_to_octets_E1(&init.B_bar)),"D":hex(&point_to_octets_E1(&init.D)),"T1":hex(&point_to_octets_E1(&init.T1)),"T2":hex(&point_to_octets_E1(&init.T2)),"domain":hex(&init.domain.0),"C_tildes":point_values(&init.C_tildes)})
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Spec 4.1.4 / Section 5: invalid tokens and fractions reach validation.
    #[test]
    fn preserve_unknown_tokens_and_fractional_indexes() {
        let input = json!({"types":["UNKNOWN"],"states":["SHOW"],"indexes":[1.5,4.5,-1]});
        assert_eq!(
            message_types(&input, "types").unwrap(),
            [MessageType::Unknown("UNKNOWN".into())]
        );
        assert_eq!(
            disclosures(&input, "states").unwrap(),
            [DisclosureState::Unknown("SHOW".into())]
        );
        assert_eq!(
            indexes(&input, "indexes").unwrap(),
            [
                Index::Other("1.5".into()),
                Index::Other("4.5".into()),
                Index::Other("-1".into())
            ]
        );
    }
    /// Fixture schema errors must never satisfy an expected INVALID result.
    #[test]
    fn schema_errors_are_harness_errors() {
        for input in [
            json!({}),
            json!({"x":null}),
            json!({"x":1}),
            json!({"x":"0"}),
            json!({"x":"AA"}),
            json!({"x":"0x00"}),
        ] {
            assert!(matches!(bytes(&input, "x"), Err(RunError::Harness(_))));
        }
        assert!(matches!(
            indexes(&json!({"x":["1.5"]}), "x"),
            Err(RunError::Harness(_))
        ));
        assert!(matches!(scalar("00"), Err(RunError::Harness(_))));
        assert_eq!(scalar(&"ff".repeat(32)).unwrap().0, [255; 32]);
    }
}
