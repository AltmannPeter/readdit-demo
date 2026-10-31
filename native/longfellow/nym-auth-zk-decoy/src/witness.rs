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

/// The value of a date or date-time's digit characters (YYYY-MM-DD or YYYY-MM-DDThh:mm:ss…),
/// or None when a digit place holds another character.
fn digits_number(text: &[u8]) -> Option<u64> {
    let mut v = 0u64;
    for (i, &c) in text.iter().enumerate() {
        let sep = i >= 4 && (i - 4) % 3 == 0;
        if !sep {
            if !c.is_ascii_digit() {
                return None;
            }
            v = v * 10 + u64::from(c - b'0');
        }
    }
    Some(v)
}

fn verifying_key(x: &[u8; 32], y: &[u8; 32]) -> Option<p256::ecdsa::VerifyingKey> {
    let point = p256::EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
    p256::ecdsa::VerifyingKey::from_encoded_point(&point).ok()
}

/// The holder-side facts of the statement, checked off-circuit so that a refusal names its
/// reason before any proving: the issuer signature under the request's issuer key, the opening
/// of bsc, validity at proof_time (both bounds inclusive), the birth date within [E, C]. The
/// circuits check each of them again.
pub fn holder_checks(p: &Parsed, holder: &Holder, st: &Statement) -> Result<(), crate::Error> {
    use p256::ecdsa::signature::Verifier as _;
    use sha2::{Digest, Sha256};
    use crate::Error::Holder as refuse;
    let vk = verifying_key(&st.issuer_x, &st.issuer_y).ok_or(refuse("the issuer key is not a P-256 point"))?;
    let sig = p256::ecdsa::Signature::from_slice(&p.issuer_sig).map_err(|_| refuse("the issuer signature is malformed"))?;
    vk.verify(&p.sig_structure, &sig)
        .map_err(|_| refuse("the issuer signature does not verify under the issuer key"))?;
    let mut opening = [0u8; 26];
    opening[..16].copy_from_slice(&holder.secret_seed);
    opening[16..].copy_from_slice(&holder.birth_date);
    if <[u8; 32]>::from(Sha256::digest(opening)) != p.bsc {
        return Err(refuse("secret_seed and birth_date do not open bsc"));
    }
    let ss = &p.sig_structure;
    let from = digits_number(&ss[mdoc::VALID_FROM_AT..mdoc::VALID_FROM_AT + 20]);
    let until = digits_number(&ss[mdoc::VALID_UNTIL_AT..mdoc::VALID_UNTIL_AT + 20]);
    match (from, until) {
        (Some(f), Some(u)) if f <= st.now && st.now <= u => {}
        (Some(_), Some(_)) => return Err(refuse("the credential is not valid at proof_time")),
        _ => return Err(refuse("the credential's validity is not a date-time")),
    }
    let b = &holder.birth_date;
    let birth = (b[4] == b'-' && b[7] == b'-').then(|| digits_number(b)).flatten().ok_or(refuse("birth_date is not YYYY-MM-DD"))?;
    if birth < st.born_from || birth > st.born_by {
        return Err(refuse("birth_date is outside the age range"));
    }
    Ok(())
}

/// The device signature (r || s) over the session's device-signed bytes, under the credential's
/// device key.
pub fn device_check(p: &Parsed, st: &Statement, device_sig: &[u8; 64]) -> Result<(), crate::Error> {
    use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
    use crate::Error::Holder as refuse;
    let vk = verifying_key(&p.device_x, &p.device_y).ok_or(refuse("the device key is not a P-256 point"))?;
    let sig = p256::ecdsa::Signature::from_slice(device_sig).map_err(|_| refuse("the device signature is malformed"))?;
    vk.verify_prehash(&st.device_digest, &sig)
        .map_err(|_| refuse("the device signature does not verify under the credential's device key"))
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

/// Google's 4-bit plucker points for GF(2^128): the first four elements of Longfellow's Cantor
/// basis (`core_algebra::proto::CANTOR_BASIS`). Four bits b_0..b_3 are packed as the element
/// b_0 beta_0 + b_1 beta_1 + b_2 beta_2 + b_3 beta_3, an element of the subfield GF(16).
pub const PLUCKER_BASIS: [u128; 4] = [
    0x0000_0000_0000_0000_0000_0000_0000_0001,
    0x295a_c0b1_f473_1af9_676a_ac9f_a4b2_0b08,
    0xa213_4422_cd40_54c9_ff10_99c3_1bbe_8f22,
    0x5003_17bd_159d_73bb_34d2_f7fb_a603_e341,
];

/// The plucker's packing of `bits` (each 0 or 1, a multiple of 4), four to an element.
pub fn pack4(bits: &[u128]) -> Vec<u128> {
    bits.chunks_exact(4)
        .map(|c| c.iter().zip(PLUCKER_BASIS).fold(0u128, |acc, (&b, beta)| if b == 1 { acc ^ beta } else { acc }))
        .collect()
}

/// One compression's trace bits, as the hash circuit unpacks them: the state after (its 32 bytes,
/// bit j of byte d at 8 d + j), W_16 to W_63, each round's new e, each round's new a (each word
/// least significant bit first): 5,888 bits.
fn trace_bits(t: &BlockTrace) -> Vec<u128> {
    let mut v = Vec::with_capacity(5888);
    push_bytes_bits(&mut v, &sha::state_bytes(&t.out));
    push_block_witness(&mut v, t);
    v
}

/// The eight compressions the hash circuit checks: the padded Sig_structure's blocks 2 to 6 from
/// the prefix's state, the opening's block, the pseudonym message's two blocks.
fn compressions(p: &Parsed, opening: &[u8; 26], secret_seed: &[u8; 16], verifier_input: &[u8; 32]) -> Vec<BlockTrace> {
    let mut out = Vec::with_capacity(8);
    let padded = sha::pad(&p.sig_structure);
    debug_assert_eq!(padded.len(), 64 * mdoc::SIGNED_BLOCKS);
    let mut state = mdoc::PREFIX_STATE;
    for blk in padded[mdoc::PREFIX_LEN..].chunks_exact(64) {
        let t = sha::compress(&state, blk);
        state = t.out;
        out.push(t);
    }
    out.push(sha::compress(&sha::IV, &sha::pad(opening)));
    let mut msg = Vec::with_capacity(119);
    msg.extend_from_slice(PSEUDONYM_DST);
    msg.extend_from_slice(secret_seed);
    msg.extend_from_slice(&[0u8; 32]);
    msg.extend_from_slice(verifier_input);
    let nm = sha::pad(&msg);
    let m1 = sha::compress(&sha::IV, &nm[..64]);
    let m2 = sha::compress(&m1.out, &nm[64..]);
    out.push(m1);
    out.push(m2);
    out
}

/// The hash circuit's private inputs, in input order: the bit inputs (the opening, the
/// Sig_structure's private bytes, the validity and age differences), then the compressions'
/// traces packed by the plucker (subfield elements), then the MAC words and keys.
pub fn hash_private(p: &Parsed, holder: &Holder, st: &Statement, mac_keys: &[u128; 6]) -> Vec<u128> {
    let mut out = Vec::with_capacity(13_700);
    let mut opening = [0u8; 26];
    opening[..16].copy_from_slice(&holder.secret_seed);
    opening[16..].copy_from_slice(&holder.birth_date);

    // The opening, then the Sig_structure's 188 private bytes.
    push_bytes_bits(&mut out, &opening);
    let fields = p.fields();
    push_bytes_bits(&mut out, &fields);

    // The validity: now - valid_from and valid_until - now, 47 bits each.
    let vf = digits_value(&fields[148..168]);
    let vu = digits_value(&fields[168..188]);
    let base = st.now.wrapping_add(TIME_OFFSET);
    push_low_bits(&mut out, base.wrapping_sub(vf), 47);
    push_low_bits(&mut out, vu.wrapping_sub(base), 47);

    // The age range: birth - born_from and born_by - birth, 27 bits each.
    let places = [0usize, 1, 2, 3, 5, 6, 8, 9];
    let mut s = 0u64;
    for (k, &pl) in places.iter().enumerate() {
        s += 10u64.pow(7 - k as u32) * u64::from(holder.birth_date[pl]);
    }
    push_low_bits(&mut out, s.wrapping_sub(st.born_from + DATE_OFFSET), 27);
    push_low_bits(&mut out, (st.born_by + DATE_OFFSET).wrapping_sub(s), 27);

    // The eight compressions' traces, 1,472 packed elements each.
    for t in compressions(p, &opening, &holder.secret_seed, &st.verifier_input) {
        out.extend(pack4(&trace_bits(&t)));
    }

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
    let mut out = Vec::with_capacity(268);
    out.push(gf::xpow(st.now + TIME_OFFSET));
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
