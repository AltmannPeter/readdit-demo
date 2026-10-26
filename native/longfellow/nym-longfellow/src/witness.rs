//! The two input vectors of the Longfellow circuits (SPEC.md L3), the hash circuit's semantic bits
//! (L4.2, mdoc), the signature circuit's verification values (L5), and the MAC that ties the two
//! circuits together (L6.1). Ported from the archive's reference program
//! (`longfellow/reference/src/main.rs`, nymauth-lf), with errors instead of exits.
//!
//! Element encodings (L1): GF(2^128) elements are 16 bytes little-endian; P-256 elements are 32
//! bytes little-endian. A bit is the element 0 or 1.

use std::path::Path;

use p256::elliptic_curve::PrimeField;
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, EncodedPoint, FieldBytes, FieldElement, ProjectivePoint, Scalar};

use crate::circuit::DST;
use crate::mdoc::Mdoc;
use crate::sha::{faces, faces_padded, pad, word};
use crate::sha256;
use crate::x509::PublicKey;

pub type E16 = [u8; 16];
pub type E32 = [u8; 32];

/// One circuit's sizes (`params.tsv`).
#[derive(Clone, Copy, Debug)]
pub struct Side {
  pub ninputs: usize,
  pub npub: usize,
  pub subfield_boundary: usize,
  pub block_enc: usize,
  pub circuit_id: [u8; 32],
}

/// The sizes of both circuits, the mdoc profile (B_sig, B_item, B_ssc) and the placement of the
/// semantic bits (`hash-semantic.tsv`).
#[derive(Clone, Debug)]
pub struct Layout {
  pub hash: Side,
  pub sig: Side,
  pub profile: [usize; 3],
  pub runs: Vec<(usize, usize, usize)>,
}

fn num(s: Option<&str>, what: &str) -> Result<usize, String> {
  s.and_then(|x| x.parse().ok()).ok_or_else(|| format!("{what}: not a number"))
}

impl Layout {
  /// Reads `params.tsv` and `hash-semantic.tsv` in `dir` (`circuits/mdoc`).
  pub fn read(dir: &Path) -> Result<Self, String> {
    let read = |f: &str| std::fs::read_to_string(dir.join(f)).map_err(|e| format!("{}: {e}", dir.join(f).display()));
    Self::parse(&read("params.tsv")?, &read("hash-semantic.tsv")?)
  }

  /// The layout from the text of `params.tsv` and `hash-semantic.tsv` (for a prover that carries
  /// them in its own build rather than reading files), checked as [`Layout::read`] checks it.
  pub fn parse(params: &str, sem: &str) -> Result<Self, String> {
    let side = |name: &str| -> Result<Side, String> {
      let f: Vec<&str> = params
        .lines()
        .find(|l| l.split('\t').next() == Some(name))
        .ok_or_else(|| format!("params.tsv: no {name} row"))?
        .split('\t')
        .collect();
      let what = format!("params.tsv {name}");
      Ok(Side {
        ninputs: num(f.get(2).copied(), &what)?,
        npub: num(f.get(3).copied(), &what)?,
        subfield_boundary: num(f.get(4).copied(), &what)?,
        block_enc: num(f.get(5).copied(), &what)?,
        circuit_id: crate::unhex("params.tsv circuit_id", f.get(6).copied().unwrap_or(""))?,
      })
    };
    let mut lines = sem.lines();
    let profile: Vec<usize> = lines
      .next()
      .filter(|l| l.starts_with("profile"))
      .ok_or("hash-semantic.tsv: no profile line")?
      .split_whitespace()
      .skip(1)
      .map(|x| num(Some(x), "hash-semantic.tsv profile"))
      .collect::<Result<_, _>>()?;
    let profile: [usize; 3] = profile.try_into().map_err(|_| "hash-semantic.tsv: the mdoc profile has 3 words")?;
    let runs = lines
      .filter(|l| l.starts_with(|c: char| c.is_ascii_digit()))
      .map(|l| {
        let v: Vec<&str> = l.split('\t').collect();
        Ok((num(v.first().copied(), "run")?, num(v.get(1).copied(), "run")?, num(v.get(2).copied(), "run")?))
      })
      .collect::<Result<Vec<_>, String>>()?;
    let layout = Layout { hash: side("hash")?, sig: side("sig")?, profile, runs };
    layout.check()?;
    Ok(layout)
  }

  /// The slot ranges this module writes (L3) against the sizes: the runs cover the hash
  /// circuit's private slots before a_p exactly once; the signature circuit has 4,765 slots.
  fn check(&self) -> Result<(), String> {
    let (h, s) = (&self.hash, &self.sig);
    if s.ninputs != 4765 || s.npub != 1155 || h.npub != 586 || h.ninputs < h.npub + 6 {
      return Err("params.tsv: these are not the nym_auth mdoc circuits (L1)".into());
    }
    let mut covered = vec![false; h.ninputs];
    for &(slot, _, len) in &self.runs {
      for c in covered.get_mut(slot..slot + len).ok_or("hash-semantic.tsv: a run past the inputs")? {
        if std::mem::replace(c, true) {
          return Err("hash-semantic.tsv: a slot placed twice".into());
        }
      }
    }
    if covered[h.npub..h.ninputs - 6].iter().any(|c| !c) || covered[..h.npub].iter().any(|c| *c) {
      return Err("hash-semantic.tsv: the runs do not cover the semantic slots exactly".into());
    }
    Ok(())
  }

  /// The length of S.
  pub fn semantic_len(&self) -> usize {
    self.runs.iter().map(|r| r.2).sum()
  }
}

/// The values both sides know (L3, L6.1).
#[derive(Clone, Debug)]
pub struct Public {
  /// T, `YYYY-MM-DDThh:mm:ssZ`.
  pub time: String,
  /// E and C, `YYYY-MM-DD`.
  pub earliest: String,
  pub cutoff: String,
  /// SHA-256(client_id).
  pub verifier_input: [u8; 32],
  /// The issuer key Q.
  pub issuer_key: PublicKey,
  /// e2.
  pub challenge: [u8; 32],
}

fn gbit(b: u8) -> E16 {
  let mut e = [0u8; 16];
  e[0] = b;
  e
}

fn pbit(b: u8) -> E32 {
  let mut e = [0u8; 32];
  e[0] = b;
  e
}

fn bits_of_bytes(b: &[u8]) -> impl Iterator<Item = u8> + '_ {
  b.iter().flat_map(|x| (0..8).map(move |j| (x >> j) & 1))
}

/// Bit i of a 256-bit big-endian integer.
fn bit(b: &[u8; 32], i: usize) -> u8 {
  (b[31 - i / 8] >> (i % 8)) & 1
}

fn reversed<const N: usize>(mut b: [u8; N]) -> [u8; N] {
  b.reverse();
  b
}

/// The pseudonym, SHA-256(DST ‖ secret_seed ‖ 0x00×32 ‖ verifier_input).
pub fn pseudonym(seed: &[u8; 16], verifier_input: &[u8; 32]) -> [u8; 32] {
  sha256(&[DST, &seed[..], &[0u8; 32], &verifier_input[..]].concat())
}

/// The pseudonym halves as the hash circuit's last two public slots: half h = bits 128h … 128h+127
/// of the pseudonym as a big-endian integer (L3.1).
fn nym_halves(nym: &[u8; 32]) -> [E16; 2] {
  let mut lo: E16 = [0; 16];
  let mut hi: E16 = [0; 16];
  lo.copy_from_slice(&nym[16..]);
  hi.copy_from_slice(&nym[..16]);
  [reversed(lo), reversed(hi)]
}

/// The hash circuit's public slots: 1, T, E, C, verifier_input; the tags, a_v and the pseudonym
/// zero until set.
pub fn hash_public(l: &Layout, p: &Public) -> Result<Vec<E16>, String> {
  let npub = l.hash.npub;
  if p.time.len() != 20 || p.earliest.len() != 10 || p.cutoff.len() != 10 {
    return Err("T is 20 bytes, E and C 10 bytes each".into());
  }
  let mut h = vec![[0u8; 16]; npub];
  h[0] = gbit(1);
  let bits: Vec<u8> = [p.time.as_bytes(), p.earliest.as_bytes(), p.cutoff.as_bytes(), &p.verifier_input[..]]
    .into_iter()
    .flat_map(bits_of_bytes)
    .collect();
  if 1 + bits.len() != npub - 9 {
    return Err("the request's sizes do not fit the hash circuit".into());
  }
  for (slot, b) in h[1..].iter_mut().zip(bits) {
    *slot = gbit(b);
  }
  Ok(h)
}

/// The signature circuit's public slots: 1, Qx, Qy, the bits of e2; a_v and the tags zero until set.
pub fn sig_public(l: &Layout, p: &Public) -> Vec<E32> {
  let mut s = vec![[0u8; 32]; l.sig.npub];
  s[0] = pbit(1);
  s[1] = reversed(p.issuer_key.x);
  s[2] = reversed(p.issuer_key.y);
  for i in 0..256 {
    s[3 + i] = pbit(bit(&p.challenge, i));
  }
  s
}

/// Writes the tags, a_v and the pseudonym into the public slots of both circuits (L3).
pub fn set_mac_public(l: &Layout, h: &mut [E16], s: &mut [E32], tags: &[u128; 6], av: u128, nym: &[u8; 32]) {
  let npub = l.hash.npub;
  for (k, tag) in tags.iter().enumerate() {
    h[npub - 9 + k] = tag.to_le_bytes();
    for j in 0..128 {
      s[387 + 128 * k + j] = pbit(((tag >> j) & 1) as u8);
    }
  }
  h[npub - 3] = av.to_le_bytes();
  for j in 0..128 {
    s[259 + j] = pbit(((av >> j) & 1) as u8);
  }
  let [lo, hi] = nym_halves(nym);
  h[npub - 2] = lo;
  h[npub - 1] = hi;
}

// ---- the semantic bits S (L4.2) ----

fn window(out: &mut Vec<u8>, o: usize, m: &[u8], w: usize) {
  word(out, o as u64, 16);
  for i in 0..w {
    word(out, u64::from(*m.get(o + i).unwrap_or(&0)), 8);
  }
}

fn find(hay: &[u8], pat: &[u8], what: &str) -> Result<usize, String> {
  hay.windows(pat.len()).position(|w| w == pat).ok_or_else(|| format!("the credential has no {what}"))
}

/// S, and the device key x and y the hash circuit reads from `sig`.
struct Semantic {
  bits: Vec<u8>,
  x: [u8; 32],
  y: [u8; 32],
}

/// A window of L4.2: where to find the pattern, the pattern, the padded message it reads, its width.
type WindowSpec<'a> = (&'a [u8], &'a [u8], &'a [u8], usize, &'static str);

/// S for an mdoc (L4.2).
fn semantic(l: &Layout, m: &Mdoc, seed: &[u8; 16], vi: &[u8; 32]) -> Result<Semantic, String> {
  let [b_sig, b_item, b_ssc] = l.profile;
  let (sig, item, ssc) = (&m.signed, &m.birth_item, &m.ssc_item);
  let (sp, ip, cp) = (pad(sig, b_sig)?, pad(item, b_item)?, pad(ssc, b_ssc)?);
  let mut s = Vec::with_capacity(l.semantic_len());
  for p in [&sp, &ip, &cp] {
    faces_padded(p, &mut s);
  }
  faces(seed, 1, &mut s)?;
  faces(&[DST, &seed[..], &[0u8; 32], &vi[..]].concat(), 2, &mut s)?;
  for m in [sig, item, ssc] {
    word(&mut s, m.len() as u64, 16);
  }
  let digest_of = |m: &[u8]| [&b"\x58\x20"[..], &sha256(m)].concat();
  let windows: [WindowSpec; 10] = [
    (sig, b"\x67docType", &sp, 38, "docType"),
    (sig, &digest_of(item), &sp, 34, "digest of birth_date"),
    (item, b"\x71elementIdentifier\x6abirth_date", &ip, 29, "birth_date identifier"),
    (item, b"\x6celementValue\xd9\x03\xec\x6a", &ip, 27, "birth_date value"),
    (sig, b"\x69deviceKey\xa4\x01\x02\x20\x01\x21\x58\x20", &sp, 85, "deviceKey"),
    (sig, b"\x69validFrom\xc0\x74", &sp, 32, "validFrom"),
    (sig, b"\x6avalidUntil\xc0\x74", &sp, 33, "validUntil"),
    (sig, &digest_of(ssc), &sp, 34, "digest of ssc"),
    (ssc, b"\x71elementIdentifier\x63ssc", &cp, 22, "ssc identifier"),
    (ssc, b"\x6celementValue\x58\x20", &cp, 47, "ssc value"),
  ];
  let mut dk = 0;
  for (k, (hay, pat, padded, w, what)) in windows.iter().enumerate() {
    let o = find(hay, pat, what)?;
    if k == 4 {
      dk = o;
    }
    window(&mut s, o, padded, *w);
  }
  let coordinate = |from: usize| -> Result<[u8; 32], String> {
    sig.get(from..from + 32).and_then(|b| b.try_into().ok()).ok_or_else(|| "the device key is cut short".to_string())
  };
  let (x, y) = (coordinate(dk + 18)?, coordinate(dk + 53)?);
  if s.len() != l.semantic_len() {
    return Err(format!("{} semantic bits; hash-semantic.tsv places {}", s.len(), l.semantic_len()));
  }
  Ok(Semantic { bits: s, x, y })
}

// ---- one ECDSA verification's 1,037 values D(Q, d, r, s) (L5) ----

fn fe(b: &[u8; 32]) -> Result<FieldElement, String> {
  Option::from(FieldElement::from_bytes(&FieldBytes::from(*b))).ok_or_else(|| "a coordinate is not below p".to_string())
}

fn le(x: &FieldElement) -> E32 {
  reversed(x.to_bytes().into())
}

fn coords(p: &AffinePoint) -> Result<([u8; 32], [u8; 32]), String> {
  let e = p.to_encoded_point(false);
  match (e.x(), e.y()) {
    (Some(x), Some(y)) => Ok(((*x).into(), (*y).into())),
    _ => Err("the point at infinity".into()),
  }
}

type P3 = [FieldElement; 3];

fn dbl(p: &P3, a: FieldElement, b3: FieldElement) -> P3 {
  let (x, y, z) = (p[0], p[1], p[2]);
  let two = FieldElement::from_u64(2);
  let (t0, t1, t2) = (x * x, y * y, z * z);
  let t3 = two * x * y;
  let zz = two * x * z;
  let yz = two * y * z;
  let u = a * zz + b3 * t2;
  let (v, w) = (t1 - u, t1 + u);
  let m = a * t0 - FieldElement::from_u64(9) * t2 + b3 * zz;
  let n = FieldElement::from_u64(3) * t0 + a * t2;
  [t3 * v - yz * m, v * w + n * m, FieldElement::from_u64(4) * yz * t1]
}

fn add(p: &P3, q: &P3, a: FieldElement, b3: FieldElement) -> P3 {
  let (x1, y1, z1, x2, y2, z2) = (p[0], p[1], p[2], q[0], q[1], q[2]);
  let (t0, t1, t2) = (x1 * x2, y1 * y2, z1 * z2);
  let t3 = (x1 + y1) * (x2 + y2) - t0 - t1;
  let t4 = (x1 + z1) * (x2 + z2) - t0 - t2;
  let t5 = (y1 + z1) * (y2 + z2) - t1 - t2;
  let zh = a * t4 + b3 * t2;
  let (xh, zo) = (t1 - zh, t1 + zh);
  let r1 = FieldElement::from_u64(3) * t0 + a * t2;
  let q4 = b3 * t4 + a * (t0 - a * t2);
  [t3 * xh - t5 * q4, xh * zo + r1 * q4, t5 * zo + t3 * r1]
}

/// P-256's b.
const B: [u8; 32] = [
  0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98, 0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0,
  0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e, 0x27, 0xd2, 0x60, 0x4b,
];

/// D(Q, d, r, s): refuses a signature that does not verify.
fn verification(q: &PublicKey, d: &[u8; 32], r: &[u8; 32], s: &[u8; 32]) -> Result<Vec<E32>, String> {
  let a = FieldElement::ZERO - FieldElement::from_u64(3);
  let b3 = FieldElement::from_u64(3) * fe(&B)?;
  let e = <Scalar as Reduce<p256::U256>>::reduce_bytes(&FieldBytes::from(*d));
  let r_s: Scalar = Option::from(Scalar::from_repr(FieldBytes::from(*r))).ok_or("r is not below n")?;
  let s_s: Scalar = Option::from(Scalar::from_repr(FieldBytes::from(*s))).ok_or("s is not below n")?;
  let w: Scalar = Option::from(s_s.invert()).ok_or("s = 0")?;
  let qp: AffinePoint = Option::from(AffinePoint::from_encoded_point(&EncodedPoint::from_affine_coordinates(
    &FieldBytes::from(q.x),
    &FieldBytes::from(q.y),
    false,
  )))
  .ok_or("a key off the curve")?;
  let g = AffinePoint::GENERATOR;
  let rp = (ProjectivePoint::GENERATOR * (e * w) + ProjectivePoint::from(qp) * (r_s * w)).to_affine();
  let (rx, ry) = coords(&rp)?;
  if <Scalar as Reduce<p256::U256>>::reduce_bytes(&FieldBytes::from(rx)) != r_s {
    return Err("a signature that does not verify".into());
  }
  let m = -s_s;
  let (eb, mb): ([u8; 32], [u8; 32]) = (e.to_bytes().into(), m.to_bytes().into());
  let sum = |p1: &AffinePoint, p2: &AffinePoint| (ProjectivePoint::from(*p1) + ProjectivePoint::from(*p2)).to_affine();
  let (gq, gr, rq) = (sum(&g, &qp), sum(&g, &rp), sum(&rp, &qp));
  let grq = sum(&g, &rq);
  let inv = |v: &[u8; 32]| -> Result<E32, String> {
    Ok(le(&Option::from(fe(v)?.invert()).ok_or("a value without an inverse")?))
  };
  let mut out: Vec<E32> = Vec::with_capacity(1037);
  out.push(le(&fe(&rx)?));
  out.push(le(&fe(&ry)?));
  out.push(inv(&rx)?);
  out.push(inv(&mb)?);
  out.push(inv(&q.x)?);
  for p in [&gq, &gr, &rq, &grq] {
    let (x, y) = coords(p)?;
    out.push(le(&fe(&x)?));
    out.push(le(&fe(&y)?));
  }
  let mut table: Vec<P3> = vec![[FieldElement::ZERO, FieldElement::ONE, FieldElement::ZERO]];
  for p in [&g, &qp, &gq, &rp, &gr, &rq, &grq] {
    let (x, y) = coords(p)?;
    table.push([fe(&x)?, fe(&y)?, FieldElement::ONE]);
  }
  let mut acc: P3 = table[0];
  for j in 0..256 {
    let bpos = 255 - j;
    let idx = usize::from(bit(&eb, bpos)) + 2 * usize::from(bit(&rx, bpos)) + 4 * usize::from(bit(&mb, bpos));
    let t = table[idx];
    acc = if j == 0 { [t[0] * t[1], t[1] * t[1], t[1] * t[2]] } else { add(&dbl(&acc, a, b3), &t, a, b3) };
    out.push(le(&(FieldElement::from_u64(2 * idx as u64) - FieldElement::from_u64(7))));
    out.extend(acc.iter().map(le));
  }
  if !bool::from(acc[0].is_zero()) || !bool::from(acc[2].is_zero()) {
    return Err("the ladder does not end at the identity".into());
  }
  Ok(out)
}

/// v mod p, big-endian (v < 2^256 < 2p).
fn mod_p(v: &[u8; 32]) -> [u8; 32] {
  const P: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  ];
  if v[..] < P[..] {
    return *v;
  }
  let mut out = [0u8; 32];
  let mut borrow = 0i16;
  for i in (0..32).rev() {
    let d = i16::from(v[i]) - i16::from(P[i]) - borrow;
    borrow = i16::from(d < 0);
    out[i] = (d + 256 * borrow) as u8;
  }
  out
}

// ---- the vectors and the MAC ----

/// The holder's private values.
pub struct Private<'a> {
  pub mdoc: &'a Mdoc,
  pub secret_seed: [u8; 16],
  /// r ‖ s of the device key's signature on the DeviceAuthentication message.
  pub device_signature: [u8; 64],
}

/// Both input vectors, the pseudonym, and the MAC messages. a_p, a_v and the tags are zero until
/// [`Witness::set_ap`] and [`Witness::set_av`].
pub struct Witness {
  pub h: Vec<E16>,
  pub s: Vec<E32>,
  pub nym: [u8; 32],
  msgs: [u128; 6],
  ap: [u128; 6],
}

/// GF(2^128) multiplication, x^128 + x^7 + x^2 + x + 1.
pub fn gf_mul(a: u128, b: u128) -> u128 {
  let (mut acc, mut cur) = (0u128, a);
  for i in 0..128 {
    if (b >> i) & 1 == 1 {
      acc ^= cur;
    }
    let carry = cur >> 127;
    cur <<= 1;
    if carry == 1 {
      cur ^= 0x87;
    }
  }
  acc
}

/// Builds both vectors. Refuses a credential that does not fit the circuits or whose signatures do
/// not verify (the ECDSA ladders would not close).
pub fn witness(l: &Layout, p: &Public, w: &Private) -> Result<Witness, String> {
  let (hn, hpub) = (l.hash.ninputs, l.hash.npub);
  let Semantic { bits: sem, x, y } = semantic(l, w.mdoc, &w.secret_seed, &p.verifier_input)?;
  let mut h = hash_public(l, p)?;
  h.resize(hn, [0u8; 16]);
  for &(slot, from, len) in &l.runs {
    for k in 0..len {
      h[slot + k] = gbit(sem[from + k]);
    }
  }
  let nym = pseudonym(&w.secret_seed, &p.verifier_input);
  let [lo, hi] = nym_halves(&nym);
  h[hpub - 2] = lo;
  h[hpub - 1] = hi;

  let e = sha256(&w.mdoc.signed);
  let half = |v: &[u8; 32]| {
    let (mut lo, mut hi) = ([0u8; 16], [0u8; 16]);
    lo.copy_from_slice(&v[16..]);
    hi.copy_from_slice(&v[..16]);
    [u128::from_be_bytes(lo), u128::from_be_bytes(hi)]
  };
  let (me, mx, my) = (half(&e), half(&x), half(&y));
  let msgs = [me[0], me[1], mx[0], mx[1], my[0], my[1]];

  let mut s = sig_public(l, p);
  s.resize(l.sig.ninputs, [0u8; 32]);
  for i in 0..256 {
    s[1923 + i] = pbit(bit(&e, i));
    s[2179 + i] = pbit(bit(&x, i));
    s[2435 + i] = pbit(bit(&y, i));
  }
  let issuer = verification(&p.issuer_key, &e, &w.mdoc.r, &w.mdoc.s).map_err(|e| format!("issuer signature: {e}"))?;
  let (mut dr, mut ds) = ([0u8; 32], [0u8; 32]);
  dr.copy_from_slice(&w.device_signature[..32]);
  ds.copy_from_slice(&w.device_signature[32..]);
  let device = verification(&PublicKey { x: mod_p(&x), y: mod_p(&y) }, &p.challenge, &dr, &ds)
    .map_err(|e| format!("device signature: {e}"))?;
  s[2691..3728].copy_from_slice(&issuer);
  s[3728..4765].copy_from_slice(&device);
  Ok(Witness { h, s, nym, msgs, ap: [0; 6] })
}

impl Witness {
  /// Writes a_p (private, fresh for each proof) into both vectors (L6.2 step 1).
  pub fn set_ap(&mut self, l: &Layout, ap: [u128; 6]) {
    let hn = l.hash.ninputs;
    for (k, a) in ap.iter().enumerate() {
      self.h[hn - 6 + k] = a.to_le_bytes();
      for j in 0..128 {
        self.s[1155 + 128 * k + j] = pbit(((a >> j) & 1) as u8);
      }
    }
    self.ap = ap;
  }

  /// Writes a_v and the tags (a_p,k ⊕ a_v)·m_k into both vectors (L6.2 step 6); returns the tags.
  pub fn set_av(&mut self, l: &Layout, av: u128) -> [u128; 6] {
    let tags: [u128; 6] = std::array::from_fn(|k| gf_mul(self.ap[k] ^ av, self.msgs[k]));
    let nym = self.nym;
    set_mac_public(l, &mut self.h, &mut self.s, &tags, av, &nym);
    tags
  }
}
