//! The bytes of each part of a value as `bincode::serialize` writes it (bincode 1: fixed-width
//! integers, u64 lengths, u32 enum tags, one byte per Option tag), named by its fields. The proof
//! is vega-prover's own type: its fields are private, but it derives `Serialize`, so a serializer
//! that only counts bytes sees them by name without any change to the library.
//!
//! [`breakdown`] returns the fields down to `depth` levels, as `{ name, bytes, children }`; the
//! elements of a list are merged field by field, so a list of instances shows what each part of
//! all of them takes together. The sizes add up to `bincode::serialized_size`, which the caller checks.

use serde::ser::{self, Serialize};
use serde_json::{Value as Json, json};

#[derive(Debug)]
pub struct Error(String);

impl std::fmt::Display for Error {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.0)
  }
}
impl std::error::Error for Error {}
impl ser::Error for Error {
  fn custom<T: std::fmt::Display>(msg: T) -> Self {
    Error(msg.to_string())
  }
}

/// A named part and its bytes.
#[derive(Clone, Debug)]
pub struct Node {
  pub name: String,
  pub bytes: u64,
  pub children: Vec<Node>,
}

/// Adds `more` into `into`, field by field (same names summed, new names appended).
fn merge(into: &mut Vec<Node>, more: Vec<Node>) {
  for m in more {
    match into.iter_mut().find(|n| n.name == m.name) {
      Some(n) => {
        n.bytes += m.bytes;
        merge(&mut n.children, m.children);
      }
      None => into.push(m),
    }
  }
}

/// The value's parts, `depth` levels deep, and its total size.
pub fn breakdown<T: Serialize + ?Sized>(value: &T, depth: usize) -> Result<(u64, Vec<Node>), String> {
  let mut nodes = Vec::new();
  let total = value.serialize(Sizer { left: depth, nodes: &mut nodes }).map_err(|e| e.to_string())?;
  Ok((total, nodes))
}

pub fn to_json(nodes: &[Node]) -> Json {
  // `code`: the name is a field of vega-prover's types, shown as code.
  Json::Array(nodes.iter().map(|n| json!({ "name": n.name, "bytes": n.bytes, "code": true, "children": to_json(&n.children) })).collect())
}

struct Sizer<'a> {
  /// Levels of fields still to name.
  left: usize,
  nodes: &'a mut Vec<Node>,
}

/// A compound value in progress: its bytes so far and its named parts.
struct Compound<'a> {
  left: usize,
  bytes: u64,
  nodes: &'a mut Vec<Node>,
}

impl Compound<'_> {
  /// An element of a list, tuple or map: counted, its fields merged into the parent's.
  fn element<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), Error> {
    let mut sub = Vec::new();
    self.bytes += v.serialize(Sizer { left: self.left, nodes: &mut sub })?;
    merge(self.nodes, sub);
    Ok(())
  }

  /// A named field: counted, and named while levels are left.
  fn field<T: Serialize + ?Sized>(&mut self, name: &'static str, v: &T) -> Result<(), Error> {
    let mut sub = Vec::new();
    let n = v.serialize(Sizer { left: self.left.saturating_sub(1), nodes: &mut sub })?;
    self.bytes += n;
    if self.left > 0 {
      merge(self.nodes, vec![Node { name: name.into(), bytes: n, children: sub }]);
    }
    Ok(())
  }
}

macro_rules! fixed {
  ($($f:ident: $t:ty = $n:expr;)*) => { $(fn $f(self, _: $t) -> Result<u64, Error> { Ok($n) })* };
}

impl<'a> ser::Serializer for Sizer<'a> {
  type Ok = u64;
  type Error = Error;
  type SerializeSeq = Compound<'a>;
  type SerializeTuple = Compound<'a>;
  type SerializeTupleStruct = Compound<'a>;
  type SerializeTupleVariant = Compound<'a>;
  type SerializeMap = Compound<'a>;
  type SerializeStruct = Compound<'a>;
  type SerializeStructVariant = Compound<'a>;

  fixed! {
    serialize_bool: bool = 1;
    serialize_i8: i8 = 1;
    serialize_i16: i16 = 2;
    serialize_i32: i32 = 4;
    serialize_i64: i64 = 8;
    serialize_i128: i128 = 16;
    serialize_u8: u8 = 1;
    serialize_u16: u16 = 2;
    serialize_u32: u32 = 4;
    serialize_u64: u64 = 8;
    serialize_u128: u128 = 16;
    serialize_f32: f32 = 4;
    serialize_f64: f64 = 8;
  }
  fn serialize_char(self, c: char) -> Result<u64, Error> {
    Ok(c.len_utf8() as u64)
  }
  fn serialize_str(self, s: &str) -> Result<u64, Error> {
    Ok(8 + s.len() as u64)
  }
  fn serialize_bytes(self, b: &[u8]) -> Result<u64, Error> {
    Ok(8 + b.len() as u64)
  }
  fn serialize_none(self) -> Result<u64, Error> {
    Ok(1)
  }
  fn serialize_some<T: Serialize + ?Sized>(self, v: &T) -> Result<u64, Error> {
    Ok(1 + v.serialize(self)?)
  }
  fn serialize_unit(self) -> Result<u64, Error> {
    Ok(0)
  }
  fn serialize_unit_struct(self, _: &'static str) -> Result<u64, Error> {
    Ok(0)
  }
  fn serialize_unit_variant(self, _: &'static str, _: u32, _: &'static str) -> Result<u64, Error> {
    Ok(4)
  }
  fn serialize_newtype_struct<T: Serialize + ?Sized>(self, _: &'static str, v: &T) -> Result<u64, Error> {
    v.serialize(self)
  }
  fn serialize_newtype_variant<T: Serialize + ?Sized>(self, _: &'static str, _: u32, _: &'static str, v: &T) -> Result<u64, Error> {
    Ok(4 + v.serialize(self)?)
  }
  fn serialize_seq(self, len: Option<usize>) -> Result<Compound<'a>, Error> {
    len.ok_or_else(|| Error("a sequence without a length".into()))?;
    Ok(Compound { left: self.left, bytes: 8, nodes: self.nodes })
  }
  fn serialize_tuple(self, _: usize) -> Result<Compound<'a>, Error> {
    Ok(Compound { left: self.left, bytes: 0, nodes: self.nodes })
  }
  fn serialize_tuple_struct(self, _: &'static str, _: usize) -> Result<Compound<'a>, Error> {
    Ok(Compound { left: self.left, bytes: 0, nodes: self.nodes })
  }
  fn serialize_tuple_variant(self, _: &'static str, _: u32, _: &'static str, _: usize) -> Result<Compound<'a>, Error> {
    Ok(Compound { left: self.left, bytes: 4, nodes: self.nodes })
  }
  fn serialize_map(self, len: Option<usize>) -> Result<Compound<'a>, Error> {
    len.ok_or_else(|| Error("a map without a length".into()))?;
    Ok(Compound { left: self.left, bytes: 8, nodes: self.nodes })
  }
  fn serialize_struct(self, _: &'static str, _: usize) -> Result<Compound<'a>, Error> {
    Ok(Compound { left: self.left, bytes: 0, nodes: self.nodes })
  }
  fn serialize_struct_variant(self, _: &'static str, _: u32, _: &'static str, _: usize) -> Result<Compound<'a>, Error> {
    Ok(Compound { left: self.left, bytes: 4, nodes: self.nodes })
  }
  fn is_human_readable(&self) -> bool {
    false
  }
}

impl ser::SerializeSeq for Compound<'_> {
  type Ok = u64;
  type Error = Error;
  fn serialize_element<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), Error> {
    self.element(v)
  }
  fn end(self) -> Result<u64, Error> {
    Ok(self.bytes)
  }
}
impl ser::SerializeTuple for Compound<'_> {
  type Ok = u64;
  type Error = Error;
  fn serialize_element<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), Error> {
    self.element(v)
  }
  fn end(self) -> Result<u64, Error> {
    Ok(self.bytes)
  }
}
impl ser::SerializeTupleStruct for Compound<'_> {
  type Ok = u64;
  type Error = Error;
  fn serialize_field<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), Error> {
    self.element(v)
  }
  fn end(self) -> Result<u64, Error> {
    Ok(self.bytes)
  }
}
impl ser::SerializeTupleVariant for Compound<'_> {
  type Ok = u64;
  type Error = Error;
  fn serialize_field<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), Error> {
    self.element(v)
  }
  fn end(self) -> Result<u64, Error> {
    Ok(self.bytes)
  }
}
impl ser::SerializeMap for Compound<'_> {
  type Ok = u64;
  type Error = Error;
  fn serialize_key<T: Serialize + ?Sized>(&mut self, k: &T) -> Result<(), Error> {
    self.element(k)
  }
  fn serialize_value<T: Serialize + ?Sized>(&mut self, v: &T) -> Result<(), Error> {
    self.element(v)
  }
  fn end(self) -> Result<u64, Error> {
    Ok(self.bytes)
  }
}
impl ser::SerializeStruct for Compound<'_> {
  type Ok = u64;
  type Error = Error;
  fn serialize_field<T: Serialize + ?Sized>(&mut self, name: &'static str, v: &T) -> Result<(), Error> {
    self.field(name, v)
  }
  fn end(self) -> Result<u64, Error> {
    Ok(self.bytes)
  }
}
impl ser::SerializeStructVariant for Compound<'_> {
  type Ok = u64;
  type Error = Error;
  fn serialize_field<T: Serialize + ?Sized>(&mut self, name: &'static str, v: &T) -> Result<(), Error> {
    self.field(name, v)
  }
  fn end(self) -> Result<u64, Error> {
    Ok(self.bytes)
  }
}
