//! A minimal CBOR (RFC 8949) reader and writer: what the mdoc and the session transcript need.
//!
//! The reader decodes one well-formed item into a tree that keeps each item's byte span in the
//! input, so that callers can locate encoded sub-items (the MSO inside the issuer's payload, the
//! items' encodings inside the namespaces). It accepts definite lengths only (an mdoc's issuer
//! data is deterministic CBOR) and refuses anything else.

use crate::Error;

/// A decoded CBOR item and the span of its encoding in the input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub value: Value,
    /// The item's encoding: `input[start..end]`.
    pub start: usize,
    pub end: usize,
    /// For byte and text strings: where the content starts (after the head).
    pub content: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    Nint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Item>),
    Map(Vec<(Item, Item)>),
    Tag(u64, Box<Item>),
    Simple(u8),
}

impl Item {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match &self.value {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }
    pub fn as_text(&self) -> Option<&str> {
        match &self.value {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Item]> {
        match &self.value {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_map(&self) -> Option<&[(Item, Item)]> {
        match &self.value {
            Value::Map(m) => Some(m),
            _ => None,
        }
    }
    /// The value at text key `k` of a map.
    pub fn get(&self, k: &str) -> Option<&Item> {
        self.as_map()?
            .iter()
            .find(|(key, _)| key.as_text() == Some(k))
            .map(|(_, v)| v)
    }
    /// The value at integer key `k` of a map.
    pub fn get_int(&self, k: i64) -> Option<&Item> {
        self.as_map()?
            .iter()
            .find(|(key, _)| match key.value {
                Value::Uint(u) => k >= 0 && u == k as u64,
                Value::Nint(n) => k < 0 && n == (-1 - k) as u64,
                _ => false,
            })
            .map(|(_, v)| v)
    }
}

const MAX_DEPTH: usize = 32;

/// Decodes exactly one item from `input` (no trailing bytes).
pub fn decode(input: &[u8]) -> Result<Item, Error> {
    let mut at = 0;
    let item = item(input, &mut at, 0)?;
    if at != input.len() {
        return Err(Error::Credential("trailing bytes after a CBOR item"));
    }
    Ok(item)
}

fn take(input: &[u8], at: &mut usize, n: usize) -> Result<usize, Error> {
    let s = *at;
    let e = s.checked_add(n).ok_or(Error::Credential("CBOR length overflow"))?;
    if e > input.len() {
        return Err(Error::Credential("truncated CBOR"));
    }
    *at = e;
    Ok(s)
}

fn head(input: &[u8], at: &mut usize) -> Result<(u8, u64), Error> {
    let b = input[take(input, at, 1)?];
    let (major, info) = (b >> 5, b & 31);
    let arg = match info {
        0..=23 => u64::from(info),
        24 => u64::from(input[take(input, at, 1)?]),
        25 => {
            let s = take(input, at, 2)?;
            u64::from(u16::from_be_bytes([input[s], input[s + 1]]))
        }
        26 => {
            let s = take(input, at, 4)?;
            u64::from(u32::from_be_bytes(input[s..s + 4].try_into().unwrap()))
        }
        27 => {
            let s = take(input, at, 8)?;
            u64::from_be_bytes(input[s..s + 8].try_into().unwrap())
        }
        _ => return Err(Error::Credential("unsupported CBOR head (indefinite length)")),
    };
    Ok((major, arg))
}

fn item(input: &[u8], at: &mut usize, depth: usize) -> Result<Item, Error> {
    if depth > MAX_DEPTH {
        return Err(Error::Credential("CBOR nested too deeply"));
    }
    let start = *at;
    let (major, arg) = head(input, at)?;
    let content = *at;
    let len = |a: u64| usize::try_from(a).map_err(|_| Error::Credential("CBOR length overflow"));
    let value = match major {
        0 => Value::Uint(arg),
        1 => Value::Nint(arg),
        2 => {
            let s = take(input, at, len(arg)?)?;
            Value::Bytes(input[s..*at].to_vec())
        }
        3 => {
            let s = take(input, at, len(arg)?)?;
            Value::Text(
                String::from_utf8(input[s..*at].to_vec())
                    .map_err(|_| Error::Credential("CBOR text is not UTF-8"))?,
            )
        }
        4 => {
            let n = len(arg)?;
            if n > input.len() {
                return Err(Error::Credential("truncated CBOR"));
            }
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                v.push(item(input, at, depth + 1)?);
            }
            Value::Array(v)
        }
        5 => {
            let n = len(arg)?;
            if n > input.len() {
                return Err(Error::Credential("truncated CBOR"));
            }
            let mut v = Vec::with_capacity(n);
            for _ in 0..n {
                let k = item(input, at, depth + 1)?;
                let x = item(input, at, depth + 1)?;
                v.push((k, x));
            }
            Value::Map(v)
        }
        6 => Value::Tag(arg, Box::new(item(input, at, depth + 1)?)),
        _ => {
            if arg > 23 {
                return Err(Error::Credential("unsupported CBOR simple value"));
            }
            Value::Simple(arg as u8)
        }
    };
    Ok(Item {
        value,
        start,
        end: *at,
        content,
    })
}

/// The shortest CBOR head of major type `major` and argument `arg`.
pub fn put_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let m = major << 5;
    if arg < 24 {
        out.push(m | arg as u8);
    } else if arg < 0x100 {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg < 0x1_0000 {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg < 0x1_0000_0000 {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

pub fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_head(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}

pub fn put_text(out: &mut Vec<u8>, t: &str) {
    put_head(out, 3, t.len() as u64);
    out.extend_from_slice(t.as_bytes());
}

pub fn put_array(out: &mut Vec<u8>, n: usize) {
    put_head(out, 4, n as u64);
}

pub fn put_null(out: &mut Vec<u8>) {
    out.push(0xf6);
}

pub fn put_tag(out: &mut Vec<u8>, tag: u64) {
    put_head(out, 6, tag);
}
