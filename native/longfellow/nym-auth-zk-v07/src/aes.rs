//! AES-128 (FIPS 197) for the rulebook v0.7 commitments and pseudonym, with the trace the hash
//! circuit checks: the inverse, in AES's GF(2^8), of every S-box input.
//!
//! Everything here runs on the holder's secret seed, so it is written without secret-dependent
//! table lookups or branches: the S-box is computed as the affine map of x^254 (the inverse, 0 for
//! 0) with a branch-free GF(2^8) multiplication.

/// GF(2^8) product modulo t^8 + t^4 + t^3 + t + 1, without branches on the operands.
fn mul8(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut r = 0u8;
    for i in 0..8 {
        let bit = 0u8.wrapping_sub((b >> i) & 1);
        r ^= a & bit;
        let hi = 0u8.wrapping_sub(a >> 7);
        a = (a << 1) ^ (0x1b & hi);
    }
    r
}

/// x^254: x's inverse in GF(2^8), and 0 for 0.
pub fn inv8(x: u8) -> u8 {
    let x2 = mul8(x, x);
    let x3 = mul8(x2, x);
    let x6 = mul8(x3, x3);
    let x12 = mul8(x6, x6);
    let x15 = mul8(x12, x3);
    let x30 = mul8(x15, x15);
    let x60 = mul8(x30, x30);
    let x120 = mul8(x60, x60);
    let x126 = mul8(x120, x6);
    let x127 = mul8(x126, x);
    mul8(x127, x127)
}

/// The S-box's affine map (FIPS 197, 5.1.1) of the inverse v.
fn affine(v: u8) -> u8 {
    v ^ v.rotate_left(1) ^ v.rotate_left(2) ^ v.rotate_left(3) ^ v.rotate_left(4) ^ 0x63
}

/// The S-box value of x and the inverse it passes through.
fn sbox(x: u8) -> (u8, u8) {
    let v = inv8(x);
    (affine(v), v)
}

const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

fn xtime(b: u8) -> u8 {
    (b << 1) ^ (0x1b & 0u8.wrapping_sub(b >> 7))
}

/// AES-128's round keys (11 x 16 bytes); the key schedule's 40 S-box inputs' inverses go to `trace`
/// (words 4, 8, ..., 40: SubWord(RotWord(w[i - 1]))'s four bytes, bytes 1, 2, 3, 0 of w[i - 1]).
pub fn expand(key: &[u8; 16], trace: &mut Vec<u8>) -> [[u8; 16]; 11] {
    let mut w = [[0u8; 4]; 44];
    for i in 0..4 {
        w[i].copy_from_slice(&key[4 * i..4 * i + 4]);
    }
    for i in 4..44 {
        let mut t = w[i - 1];
        if i % 4 == 0 {
            let rot = [t[1], t[2], t[3], t[0]];
            for (k, &b) in rot.iter().enumerate() {
                let (s, v) = sbox(b);
                trace.push(v);
                t[k] = s;
            }
            t[0] ^= RCON[i / 4 - 1];
        }
        for k in 0..4 {
            w[i][k] = w[i - 4][k] ^ t[k];
        }
    }
    let mut rk = [[0u8; 16]; 11];
    for (r, k) in rk.iter_mut().enumerate() {
        for c in 0..4 {
            k[4 * c..4 * c + 4].copy_from_slice(&w[4 * r + c]);
        }
    }
    rk
}

/// AES-128 of one block under the round keys `rk`; its 160 S-box inputs' inverses go to `trace`
/// (rounds 1 to 10, state bytes 0 to 15).
pub fn encrypt(rk: &[[u8; 16]; 11], block: &[u8; 16], trace: &mut Vec<u8>) -> [u8; 16] {
    let mut s = [0u8; 16];
    for k in 0..16 {
        s[k] = block[k] ^ rk[0][k];
    }
    for (r, k) in rk.iter().enumerate().skip(1) {
        for b in s.iter_mut() {
            let (o, v) = sbox(*b);
            trace.push(v);
            *b = o;
        }
        let mut t = [0u8; 16];
        for i in 0..16 {
            t[i] = s[(i % 4) + 4 * (((i / 4) + (i % 4)) % 4)];
        }
        if r < 10 {
            for c in 0..4 {
                let a = [t[4 * c], t[4 * c + 1], t[4 * c + 2], t[4 * c + 3]];
                let x = [xtime(a[0]), xtime(a[1]), xtime(a[2]), xtime(a[3])];
                t[4 * c] = x[0] ^ x[1] ^ a[1] ^ a[2] ^ a[3];
                t[4 * c + 1] = a[0] ^ x[1] ^ x[2] ^ a[2] ^ a[3];
                t[4 * c + 2] = a[0] ^ a[1] ^ x[2] ^ x[3] ^ a[3];
                t[4 * c + 3] = x[0] ^ a[0] ^ a[1] ^ a[2] ^ x[3];
            }
        }
        for (i, o) in s.iter_mut().enumerate() {
            *o = t[i] ^ k[i];
        }
    }
    s
}

/// The tag of bsc's blocks.
pub const BSC_TAG: &[u8; 5] = b"nym/b";
/// The tag of psc's blocks.
pub const PSC_TAG: &[u8; 5] = b"nym/p";

/// The plaintext blocks of bsc: tag || 01 || birth_date and tag || 02 || 0^10.
pub fn bsc_blocks(birth_date: &[u8; 10]) -> [[u8; 16]; 2] {
    let mut m1 = [0u8; 16];
    m1[..5].copy_from_slice(BSC_TAG);
    m1[5] = 1;
    m1[6..].copy_from_slice(birth_date);
    let mut m2 = [0u8; 16];
    m2[..5].copy_from_slice(BSC_TAG);
    m2[5] = 2;
    [m1, m2]
}

/// bsc = AES-128(secret_seed, tag || 01 || birth_date) || AES-128(secret_seed, tag || 02 || 0^10).
pub fn bsc(secret_seed: &[u8; 16], birth_date: &[u8; 10]) -> [u8; 32] {
    let mut junk = Vec::new();
    let rk = expand(secret_seed, &mut junk);
    let [m1, m2] = bsc_blocks(birth_date);
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&encrypt(&rk, &m1, &mut junk));
    out[16..].copy_from_slice(&encrypt(&rk, &m2, &mut junk));
    out
}

/// psc = AES-128(private_seed, "nym/p" || 01 || 0^10) || AES-128(private_seed, "nym/p" || 02 || 0^10).
pub fn psc(private_seed: &[u8; 16]) -> [u8; 32] {
    let mut junk = Vec::new();
    let rk = expand(private_seed, &mut junk);
    let mut out = [0u8; 32];
    for i in 0..2 {
        let mut m = [0u8; 16];
        m[..5].copy_from_slice(PSC_TAG);
        m[5] = 1 + i as u8;
        out[16 * i..16 * i + 16].copy_from_slice(&encrypt(&rk, &m, &mut junk));
    }
    out
}

/// The pseudonym of algorithm aes-128: AES-128(seed, H[0..16]) || AES-128(seed, H[16..32]).
pub fn pseudonym(seed: &[u8; 16], nym_block: &[u8; 32]) -> [u8; 32] {
    let mut junk = Vec::new();
    let rk = expand(seed, &mut junk);
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&encrypt(&rk, nym_block[..16].try_into().unwrap(), &mut junk));
    out[16..].copy_from_slice(&encrypt(&rk, nym_block[16..].try_into().unwrap(), &mut junk));
    out
}

/// The hash circuit's AES trace (704 bytes): the key schedule of secret_seed (40), bsc's two
/// encryptions (160 each), the pseudonym's two (160 each), then 24 zero bytes.
pub fn trace(secret_seed: &[u8; 16], birth_date: &[u8; 10], nym_block: &[u8; 32]) -> Vec<u8> {
    let mut tr = Vec::with_capacity(704);
    let rk = expand(secret_seed, &mut tr);
    let [m1, m2] = bsc_blocks(birth_date);
    encrypt(&rk, &m1, &mut tr);
    encrypt(&rk, &m2, &mut tr);
    encrypt(&rk, nym_block[..16].try_into().unwrap(), &mut tr);
    encrypt(&rk, nym_block[16..].try_into().unwrap(), &mut tr);
    tr.resize(704, 0);
    tr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips197_appendix_c1() {
        let key: [u8; 16] = core::array::from_fn(|i| i as u8);
        let pt = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ct = encrypt(&expand(&key, &mut Vec::new()), &pt, &mut Vec::new());
        assert_eq!(ct, [0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a]);
    }

    #[test]
    fn sbox_and_inverse() {
        assert_eq!(sbox(0x00).0, 0x63);
        assert_eq!(sbox(0x01).0, 0x7c);
        assert_eq!(sbox(0x53).0, 0xed);
        assert_eq!(inv8(0), 0);
        for x in 1..=255u8 {
            assert_eq!(mul8(x, inv8(x)), 1);
        }
    }

    #[test]
    fn trace_layout() {
        let t = trace(&[7u8; 16], b"2010-05-17", &[9u8; 32]);
        assert_eq!(t.len(), 704);
        assert!(t[680..].iter().all(|&b| b == 0));
    }
}
