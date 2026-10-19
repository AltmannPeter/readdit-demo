//! The CBOR this crate reads and writes (RFC 8949).
//!
//! The reader works on positions in the encoded bytes, so each item keeps its own encoding: the
//! issuer's signature and digests cover those bytes, and the hash circuit reads them (SPEC.md
//! L4.2). It takes untrusted input: every length is checked against the buffer, nesting is
//! bounded, and indefinite lengths are refused (the mdoc profile has none).

const MAX_DEPTH: usize = 32;

/// (major type, argument, head length) of the item at `p`.
pub fn head(d: &[u8], p: usize) -> Result<(u8, u64, usize), String> {
  let first = *d.get(p).ok_or("CBOR: unexpected end")?;
  let (mt, ai) = (first >> 5, first & 31);
  match ai {
    0..=23 => Ok((mt, u64::from(ai), 1)),
    24..=27 => {
      let n = 1usize << (ai - 24);
      let bytes = d.get(p + 1..p + 1 + n).ok_or("CBOR: unexpected end")?;
      Ok((mt, bytes.iter().fold(0u64, |v, b| (v << 8) | u64::from(*b)), 1 + n))
    }
    _ => Err("CBOR: an indefinite length or a reserved head".into()),
  }
}

fn len(v: u64) -> Result<usize, String> {
  usize::try_from(v).map_err(|_| "CBOR: a length beyond the address space".to_string())
}

fn end_at(d: &[u8], p: usize, depth: usize) -> Result<usize, String> {
  if depth > MAX_DEPTH {
    return Err("CBOR: nested too deep".into());
  }
  let (mt, v, hl) = head(d, p)?;
  let after = match mt {
    2 | 3 => (p + hl).checked_add(len(v)?).ok_or("CBOR: a length beyond the address space")?,
    0 | 1 | 7 => p + hl,
    6 => end_at(d, p + hl, depth + 1)?,
    4 | 5 => {
      let n = len(v)?.checked_mul(if mt == 5 { 2 } else { 1 }).ok_or("CBOR: too many entries")?;
      let mut q = p + hl;
      for _ in 0..n {
        q = end_at(d, q, depth + 1)?;
      }
      q
    }
    _ => return Err("CBOR: an item of an unknown type".into()),
  };
  if after > d.len() {
    return Err("CBOR: unexpected end".into());
  }
  Ok(after)
}

/// The position just past the item at `p`.
pub fn end(d: &[u8], p: usize) -> Result<usize, String> {
  end_at(d, p, 0)
}

/// The encoding of the item at `p`: head and content.
pub fn item(d: &[u8], p: usize) -> Result<&[u8], String> {
  Ok(&d[p..end(d, p)?])
}

/// The content of the byte or text string at `p`.
pub fn content(d: &[u8], p: usize) -> Result<&[u8], String> {
  let (mt, v, hl) = head(d, p)?;
  if mt != 2 && mt != 3 {
    return Err("CBOR: not a byte or text string".into());
  }
  d.get(p + hl..p + hl + len(v)?).ok_or_else(|| "CBOR: unexpected end".to_string())
}

/// The position of the item a tag at `p` wraps, if the tag is `tag`.
pub fn untag(d: &[u8], p: usize, tag: u64) -> Result<usize, String> {
  let (mt, v, hl) = head(d, p)?;
  if mt != 6 || v != tag {
    return Err(format!("CBOR: not tag {tag}"));
  }
  Ok(p + hl)
}

/// A map key this reader looks up: a text string or an integer.
#[derive(Clone, Copy, Debug)]
pub enum Key<'k> {
  Text(&'k str),
  Int(i64),
}

fn key_is(d: &[u8], q: usize, key: Key) -> Result<bool, String> {
  let (mt, v, _) = head(d, q)?;
  Ok(match key {
    Key::Text(t) => mt == 3 && content(d, q)? == t.as_bytes(),
    Key::Int(i) if i >= 0 => mt == 0 && i64::try_from(v).ok() == Some(i),
    Key::Int(i) => mt == 1 && i64::try_from(v).ok().map(|v| -1 - v) == Some(i),
  })
}

/// The entries (key position, value position) of the map at `p`.
pub fn entries(d: &[u8], p: usize) -> Result<Vec<(usize, usize)>, String> {
  let (mt, n, hl) = head(d, p)?;
  if mt != 5 {
    return Err("CBOR: not a map".into());
  }
  let mut out = Vec::new();
  let mut q = p + hl;
  for _ in 0..len(n)? {
    let v = end(d, q)?;
    out.push((q, v));
    q = end(d, v)?;
  }
  Ok(out)
}

/// The position of the value of `key` in the map at `p`; refuses a key that appears twice.
pub fn get(d: &[u8], p: usize, key: Key) -> Result<usize, String> {
  let mut found = None;
  for (k, v) in entries(d, p)? {
    if key_is(d, k, key)? {
      if found.is_some() {
        return Err(format!("CBOR: key {key:?} appears twice"));
      }
      found = Some(v);
    }
  }
  found.ok_or_else(|| format!("CBOR: no key {key:?}"))
}

/// The positions of the elements of the array at `p`.
pub fn elements(d: &[u8], p: usize) -> Result<Vec<usize>, String> {
  let (mt, n, hl) = head(d, p)?;
  if mt != 4 {
    return Err("CBOR: not an array".into());
  }
  let mut out = Vec::new();
  let mut q = p + hl;
  for _ in 0..len(n)? {
    out.push(q);
    q = end(d, q)?;
  }
  Ok(out)
}

// ---- writing ----

/// The head of an item of major type `major` whose argument is `n`.
pub fn write_head(major: u8, n: usize) -> Vec<u8> {
  let m = major << 5;
  let n = n as u64;
  match n {
    0..24 => vec![m | n as u8],
    24..0x100 => vec![m | 24, n as u8],
    0x100..0x1_0000 => [&[m | 25][..], &(n as u16).to_be_bytes()].concat(),
    0x1_0000..0x1_0000_0000 => [&[m | 26][..], &(n as u32).to_be_bytes()].concat(),
    _ => [&[m | 27][..], &n.to_be_bytes()].concat(),
  }
}

/// A byte string.
pub fn bstr(b: &[u8]) -> Vec<u8> {
  [write_head(2, b.len()), b.to_vec()].concat()
}

/// A text string.
pub fn tstr(s: &str) -> Vec<u8> {
  [write_head(3, s.len()), s.as_bytes().to_vec()].concat()
}

/// Tag 24 on a byte string holding an encoded item: `bstr .cbor`.
pub fn embedded(encoded: &[u8]) -> Vec<u8> {
  [write_head(6, 24), bstr(encoded)].concat()
}

/// null.
pub const NULL: u8 = 0xf6;

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn reads_what_it_writes_and_refuses_truncation() {
    // {"a": h'0102', -3: [1, "x"]}
    let d = [&[0xa2][..], &tstr("a"), &bstr(&[1, 2]), &[0x22, 0x82, 0x01], &tstr("x")].concat();
    assert_eq!(end(&d, 0), Ok(d.len()));
    assert_eq!(content(&d, get(&d, 0, Key::Text("a")).expect("a")), Ok(&[1u8, 2][..]));
    let arr = get(&d, 0, Key::Int(-3)).expect("-3");
    assert_eq!(elements(&d, arr).expect("array").len(), 2);
    assert!(get(&d, 0, Key::Int(3)).is_err());
    assert!(end(&d[..d.len() - 1], 0).is_err());
    assert!(end(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0).is_err());
  }
}
