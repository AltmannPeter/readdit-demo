//! A minimal CBOR encoder and reader (RFC 8949). The encoder builds the test credentials. The
//! reader takes real credentials apart.

/// A CBOR data item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
  Unsigned(u64),
  /// The integer −1 − n.
  Negative(u64),
  Bytes(Vec<u8>),
  Text(String),
  Array(Vec<Value>),
  /// Entries in the order they are encoded.
  Map(Vec<(Value, Value)>),
  Tag(u64, Box<Value>),
  Bool(bool),
  /// A data item that is already encoded, written as it is.
  Encoded(Vec<u8>),
}

pub fn text(s: &str) -> Value {
  Value::Text(s.to_string())
}

pub fn int(i: i64) -> Value {
  if i >= 0 { Value::Unsigned(i as u64) } else { Value::Negative((-1 - i) as u64) }
}

pub fn tag(number: u64, value: Value) -> Value {
  Value::Tag(number, Box::new(value))
}

/// A map with text keys.
pub fn record(entries: Vec<(&str, Value)>) -> Value {
  Value::Map(entries.into_iter().map(|(k, v)| (text(k), v)).collect())
}

impl Value {
  pub fn encode(&self) -> Vec<u8> {
    let mut out = Vec::new();
    self.write(&mut out);
    out
  }

  fn write(&self, out: &mut Vec<u8>) {
    match self {
      Value::Unsigned(n) => head(0, *n, out),
      Value::Negative(n) => head(1, *n, out),
      Value::Bytes(b) => {
        head(2, b.len() as u64, out);
        out.extend_from_slice(b);
      }
      Value::Text(t) => {
        head(3, t.len() as u64, out);
        out.extend_from_slice(t.as_bytes());
      }
      Value::Array(items) => {
        head(4, items.len() as u64, out);
        items.iter().for_each(|item| item.write(out));
      }
      Value::Map(entries) => {
        head(5, entries.len() as u64, out);
        for (key, value) in entries {
          key.write(out);
          value.write(out);
        }
      }
      Value::Tag(number, value) => {
        head(6, *number, out);
        value.write(out);
      }
      Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
      Value::Encoded(bytes) => out.extend_from_slice(bytes),
    }
  }
}

/// The initial byte of a data item, and the argument in its shortest form.
fn head(major: u8, n: u64, out: &mut Vec<u8>) {
  let major = major << 5;
  match n {
    0..=23 => out.push(major | n as u8),
    24..=0xff => out.extend_from_slice(&[major | 24, n as u8]),
    0x100..=0xffff => {
      out.push(major | 25);
      out.extend_from_slice(&(n as u16).to_be_bytes());
    }
    0x1_0000..=0xffff_ffff => {
      out.push(major | 26);
      out.extend_from_slice(&(n as u32).to_be_bytes());
    }
    _ => {
      out.push(major | 27);
      out.extend_from_slice(&n.to_be_bytes());
    }
  }
}

/// A data item inside encoded bytes. The reader keeps each item's own encoding, because a
/// signature or a digest covers those bytes and not the value they encode. It reads definite
/// lengths only.
#[derive(Clone, Copy, Debug)]
pub struct Item<'a> {
  /// The item's encoding, from its initial byte to its end.
  pub bytes: &'a [u8],
  pub major: u8,
  pub argument: u64,
  /// Where the content starts, after the head.
  content: usize,
}

impl<'a> Item<'a> {
  /// The data item at the start of `bytes`.
  pub fn read(bytes: &'a [u8]) -> Result<Self, String> {
    let initial = *bytes.first().ok_or("no data item")?;
    let (major, info) = (initial >> 5, initial & 31);
    let (argument, content) = match info {
      0..=23 => (u64::from(info), 1),
      24..=27 => {
        let n = 1 << (info - 24);
        let argument = bytes.get(1..1 + n).ok_or("a head cut short")?;
        (argument.iter().fold(0, |v, &b| v << 8 | u64::from(b)), 1 + n)
      }
      _ => return Err(format!("the head {initial:#04x}, which has no definite length")),
    };
    let end = match major {
      2 | 3 => content + argument as usize,
      4..=6 => {
        let children = match major {
          4 => argument,
          5 => 2 * argument,
          _ => 1,
        };
        let mut end = content;
        for _ in 0..children {
          end += Item::read(bytes.get(end..).ok_or("an item cut short")?)?.bytes.len();
        }
        end
      }
      _ => content,
    };
    let bytes = bytes.get(..end).ok_or("an item cut short")?;
    Ok(Item { bytes, major, argument, content })
  }

  /// The content of a byte string or a text string.
  pub fn content(&self) -> &'a [u8] {
    &self.bytes[self.content..]
  }

  /// The elements of an array, the keys and values of a map in turn, or the item a tag wraps.
  pub fn children(&self) -> Vec<Item<'a>> {
    assert!((4..=6).contains(&self.major), "only arrays, maps and tags have children");
    let mut children = Vec::new();
    let mut at = self.content;
    while at < self.bytes.len() {
      let child = Item::read(&self.bytes[at..]).expect("read checked the children");
      at += child.bytes.len();
      children.push(child);
    }
    children
  }

  /// Element `i` of an array.
  pub fn at(&self, i: usize) -> Result<Item<'a>, String> {
    self.children().get(i).copied().ok_or_else(|| format!("no element {i}"))
  }

  /// The value of the map entry whose key encodes as `key` does.
  pub fn get(&self, key: &Value) -> Result<Item<'a>, String> {
    let key = key.encode();
    let children = self.children();
    let entry = children.chunks(2).find(|entry| entry[0].bytes == key);
    entry.map(|entry| entry[1]).ok_or_else(|| format!("no key {key:02x?}"))
  }

  /// The data item that a byte string under tag 24 encodes (RFC 8949, clause 3.4.5.1).
  pub fn embedded(&self) -> Result<Item<'a>, String> {
    if self.major != 6 || self.argument != 24 {
      return Err("not tag 24".to_string());
    }
    Item::read(self.at(0)?.content())
  }
}
