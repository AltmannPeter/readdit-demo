//! The two circuits' inputs: the hash circuit's (GF(2^128)) and the signature circuit's (P-256's
//! base field), each split into the private inputs the prover commits (before the MAC challenge)
//! and the public inputs both sides compute (after it). Each vector is in the circuit's input
//! order; the circuit's input layer is [1, public..., private...].

use crate::ecdsa;
use crate::gf;
use crate::mdoc::{self, Parsed};
use crate::sha::{self, BlockTrace};
use p256::FieldElement;

/// The pseudonym's domain separation tag (known-offender-matching-ssc).
pub const PSEUDONYM_DST: &[u8] = b"nym_auth/v1/known-offender-matching-ssc";

/// Window lengths (bytes) the hash circuit reads.
const DEVICE_KEY_WINDOW: usize = 85; // deviceKey's key and COSE_Key head, x, y's head, y
const VALID_FROM_WINDOW: usize = 32; // key, tag 0 head, 20 characters
const VALID_UNTIL_WINDOW: usize = 33;
const LISTED_WINDOW: usize = 34; // 58 20 and the digest
const ID_WINDOW: usize = 22;
const VALUE_WINDOW: usize = 47; // 6c "elementValue" 58 20, the 32 bytes
const OFFSET_BITS: usize = 9; // three octal digits

/// The excess of a date-time's 14 digit characters over their values: 48 (10^14 - 1) / 9.
pub const TIME_OFFSET: u64 = 533_333_333_333_328;
/// The excess of a date's 8 digit characters over their values: 48 (10^8 - 1) / 9.
pub const DATE_OFFSET: u64 = 533_333_328;

/// The holder's secret inputs.
pub struct Holder<'a> {
    /// The IssuerSigned CBOR.
    pub credential: &'a [u8],
    pub secret_seed: [u8; 16],
    /// "YYYY-MM-DD", the 10 bytes committed in bsc.
    pub birth_date: [u8; 10],
}

/// The statement's public values, as the verifier computes them.
#[derive(Clone, Debug)]
pub struct Statement {
    pub doc_type: String,
    /// proof_time as YYYYMMDDhhmmss.
    pub now: u64,
    /// E and C as YYYYMMDD (E 0 and C 99999999 for a missing bound).
    pub born_from: u64,
    pub born_by: u64,
    pub verifier_input: [u8; 32],
    /// The issuer key (big-endian x, y).
    pub issuer_x: [u8; 32],
    pub issuer_y: [u8; 32],
    /// e2 = SHA-256 of the bytes the device key signed.
    pub device_digest: [u8; 32],
}

/// The pseudonym of known-offender-matching-ssc: SHA-256(DST || secret_seed || 0^32 ||
/// verifier_input).
pub fn pseudonym(secret_seed: &[u8; 16], verifier_input: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(PSEUDONYM_DST);
    h.update(secret_seed);
    h.update([0u8; 32]);
    h.update(verifier_input);
    h.finalize().into()
}

fn push_bytes_bits(out: &mut Vec<u128>, bytes: &[u8]) {
    for b in bytes {
        for j in 0..8 {
            out.push(u128::from((b >> j) & 1));
        }
    }
}

fn push_words_bits(out: &mut Vec<u128>, words: &[u32]) {
    for w in words {
        for j in 0..32 {
            out.push(u128::from((w >> j) & 1));
        }
    }
}

fn push_low_bits(out: &mut Vec<u128>, v: u64, n: usize) {
    for j in 0..n {
        out.push(u128::from((v >> j) & 1));
    }
}

fn push_block_witness(out: &mut Vec<u128>, t: &BlockTrace) {
    push_words_bits(out, &t.schedule);
    push_words_bits(out, &t.e);
    push_words_bits(out, &t.a);
}

fn window(text: &[u8], at: usize, len: usize) -> Vec<u8> {
    (0..len).map(|i| text.get(at + i).copied().unwrap_or(0)).collect()
}

/// A time's or date's value V: Horner's rule over its digit characters' byte values (the
/// separators of YYYY-MM-DDThh:mm:ssZ skipped).
fn digits_value(text: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, &c) in text.iter().enumerate() {
        let sep = i >= 4 && (i - 4) % 3 == 0;
        if !sep {
            v = v.wrapping_mul(10).wrapping_add(u64::from(c));
        }
    }
    v
}

/// The MAC datum the two circuits share: e (the SHA-256 digest of the Sig_structure, as a
/// 32-byte integer), then the device key's x and y, each 32 bytes little-endian; six words of 16
/// bytes.
pub fn tied_datum(p: &Parsed) -> [u8; 96] {
    use sha2::{Digest, Sha256};
    let mut t = [0u8; 96];
    let mut e: [u8; 32] = Sha256::digest(&p.sig_structure).into();
    e.reverse();
    let mut x = p.device_x;
    x.reverse();
    let mut y = p.device_y;
    y.reverse();
    t[..32].copy_from_slice(&e);
    t[32..64].copy_from_slice(&x);
    t[64..].copy_from_slice(&y);
    t
}

/// The hash circuit's private inputs, in input order.
pub fn hash_private(p: &Parsed, holder: &Holder, st: &Statement, mac_keys: &[u128; 6]) -> Vec<u128> {
    let mut out = Vec::with_capacity(78_100);
    let mut opening = [0u8; 26];
    opening[..16].copy_from_slice(&holder.secret_seed);
    opening[16..].copy_from_slice(&holder.birth_date);

    // The opening, the signed region's padded bits, its chaining values and blocks.
    push_bytes_bits(&mut out, &opening);
    let (text, traces) = sha::hash_trace(&p.sig_structure);
    push_bytes_bits(&mut out, &text);
    for t in &traces {
        push_bytes_bits(&mut out, &sha::state_bytes(&t.out));
    }
    for t in &traces {
        push_block_witness(&mut out, t);
    }

    // The credential's windows: the docType, the device key, the validity; their offsets.
    let tlen = mdoc::doc_type_pattern(&st.doc_type).len();
    push_bytes_bits(&mut out, &window(&text, p.doc_type_at, tlen));
    push_bytes_bits(&mut out, &window(&text, p.device_key_at, DEVICE_KEY_WINDOW));
    let from = window(&text, p.valid_from_at, VALID_FROM_WINDOW);
    let until = window(&text, p.valid_until_at, VALID_UNTIL_WINDOW);
    push_bytes_bits(&mut out, &from);
    push_bytes_bits(&mut out, &until);
    for at in [p.doc_type_at, p.device_key_at, p.valid_from_at, p.valid_until_at] {
        push_low_bits(&mut out, at as u64, OFFSET_BITS);
    }
    // The validity: now - valid_from and valid_until - now, 47 bits each.
    let vf = digits_value(&from[12..32]);
    let vu = digits_value(&until[13..33]);
    let base = st.now.wrapping_add(TIME_OFFSET);
    push_low_bits(&mut out, base.wrapping_sub(vf), 47);
    push_low_bits(&mut out, vu.wrapping_sub(base), 47);

    // The bsc item: its padded bits, its listing, identifier and value windows.
    let (item, itraces) = sha::hash_trace(&p.bsc_item);
    push_bytes_bits(&mut out, &item);
    push_bytes_bits(&mut out, &window(&text, p.bsc_digest_at, LISTED_WINDOW));
    push_bytes_bits(&mut out, &window(&item, p.bsc_identifier_at, ID_WINDOW));
    push_bytes_bits(&mut out, &window(&item, p.bsc_value_at, VALUE_WINDOW));
    for t in &itraces {
        push_bytes_bits(&mut out, &sha::state_bytes(&t.out));
    }
    for t in &itraces {
        push_block_witness(&mut out, t);
    }
    for at in [p.bsc_digest_at, p.bsc_identifier_at, p.bsc_value_at] {
        push_low_bits(&mut out, at as u64, OFFSET_BITS);
    }

    // The opening's hash (bsc) and the pseudonym's two blocks.
    let open_block = sha::pad(&opening);
    let ot = sha::compress(&sha::IV, &open_block);
    let mut msg = Vec::with_capacity(119);
    msg.extend_from_slice(PSEUDONYM_DST);
    msg.extend_from_slice(&holder.secret_seed);
    msg.extend_from_slice(&[0u8; 32]);
    msg.extend_from_slice(&st.verifier_input);
    let nm = sha::pad(&msg);
    let m1 = sha::compress(&sha::IV, &nm[..64]);
    let m2 = sha::compress(&m1.out, &nm[64..]);
    for t in [&ot, &m1, &m2] {
        push_bytes_bits(&mut out, &sha::state_bytes(&t.out));
    }
    for t in [&ot, &m1, &m2] {
        push_block_witness(&mut out, t);
    }

    // The age range: birth - born_from and born_by - birth, 27 bits each.
    let places = [0usize, 1, 2, 3, 5, 6, 8, 9];
    let mut s = 0u64;
    for (k, &pl) in places.iter().enumerate() {
        s += 10u64.pow(7 - k as u32) * u64::from(holder.birth_date[pl]);
    }
    push_low_bits(&mut out, s.wrapping_sub(st.born_from + DATE_OFFSET), 27);
    push_low_bits(&mut out, (st.born_by + DATE_OFFSET).wrapping_sub(s), 27);

    // The MAC datum's words and the MAC keys.
    let tied = tied_datum(p);
    for k in 0..6 {
        out.push(gf::from_le(&tied[16 * k..16 * k + 16]));
    }
    out.extend_from_slice(mac_keys);
    out
}

/// The hash circuit's public inputs, in input order.
pub fn hash_public(st: &Statement, pseudonym: &[u8; 32], challenge: u128, tags: &[u128; 6]) -> Vec<u128> {
    let mut out = Vec::with_capacity(277);
    let pat = mdoc::doc_type_pattern(&st.doc_type);
    let limbs = pat.len() / 16;
    for i in 0..limbs {
        out.push(gf::from_le(&pat[16 * i..16 * i + 16]));
    }
    for &b in &pat[16 * limbs..] {
        out.push(u128::from(b));
    }
    out.push(gf::xpow(st.now + TIME_OFFSET));
    out.push(gf::xpow(st.now + TIME_OFFSET + 1));
    push_bytes_bits(&mut out, &st.verifier_input);
    out.push(gf::from_le(&pseudonym[..16]));
    out.push(gf::from_le(&pseudonym[16..]));
    out.push(gf::xpow(st.born_from + DATE_OFFSET));
    out.push(gf::xpow(st.born_by + DATE_OFFSET));
    out.push(challenge);
    out.extend_from_slice(tags);
    out
}

fn fe_bit(b: u8) -> [u8; 32] {
    let mut x = [0u8; 32];
    x[0] = b;
    x
}

fn push_fe(out: &mut Vec<[u8; 32]>, x: &FieldElement) {
    out.push(ecdsa::le_bytes(x));
}

fn push_straus(out: &mut Vec<[u8; 32]>, w: &ecdsa::StrausWitness) {
    for &b in &w.b {
        out.push(fe_bit(b));
    }
    for x in &w.h {
        push_fe(out, x);
    }
    for x in &w.acc {
        push_fe(out, x);
    }
    push_fe(out, &w.ik);
}

/// The signature circuit's private inputs (each element 32 bytes little-endian), in input order.
pub fn sig_private(p: &Parsed, st: &Statement, device_sig: &[u8; 64], mac_keys: &[u128; 6]) -> Vec<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut out = Vec::with_capacity(4_120);
    let tied = tied_datum(p);
    for b in tied {
        for j in 0..8 {
            out.push(fe_bit((b >> j) & 1));
        }
    }
    for k in mac_keys {
        for j in 0..128 {
            out.push(fe_bit(((k >> j) & 1) as u8));
        }
    }
    let e: [u8; 32] = Sha256::digest(&p.sig_structure).into();
    push_straus(&mut out, &ecdsa::straus(&e, &st.issuer_x, &st.issuer_y, &p.issuer_sig));
    push_straus(&mut out, &ecdsa::straus(&st.device_digest, &p.device_x, &p.device_y, device_sig));
    out
}

/// The signature circuit's public inputs (each element 32 bytes little-endian), in input order.
pub fn sig_public(st: &Statement, challenge: u128, tags: &[u128; 6]) -> Vec<[u8; 32]> {
    let mut out = Vec::with_capacity(1_154);
    let mut x = st.issuer_x;
    x.reverse();
    let mut y = st.issuer_y;
    y.reverse();
    out.push(x);
    out.push(y);
    for j in 0..256 {
        let byte = st.device_digest[31 - j / 8];
        out.push(fe_bit((byte >> (j % 8)) & 1));
    }
    for j in 0..128 {
        out.push(fe_bit(((challenge >> j) & 1) as u8));
    }
    for t in tags {
        for j in 0..128 {
            out.push(fe_bit(((t >> j) & 1) as u8));
        }
    }
    out
}

/// The MAC tags: t_k = a_k + c m_k in GF(2^128), m_k the tied datum's words: the specification's
/// affine MAC a x + b, with the verifier's challenge c as the multiplier and the prover's key a_k
/// as the offset.
pub fn mac_tags(p: &Parsed, keys: &[u128; 6], challenge: u128) -> [u128; 6] {
    let tied = tied_datum(p);
    let mut t = [0u128; 6];
    for k in 0..6 {
        t[k] = keys[k] ^ gf::mul(challenge, gf::from_le(&tied[16 * k..16 * k + 16]));
    }
    t
}
