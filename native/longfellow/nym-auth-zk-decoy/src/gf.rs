//! GF(2^128) modulo x^128 + x^7 + x^2 + x + 1, an element as a `u128` whose bit i is the
//! coefficient of x^i (Longfellow's encoding: 16 bytes, little-endian).

/// The product a * b.
pub fn mul(a: u128, b: u128) -> u128 {
    let (mut x, mut y, mut r) = (a, b, 0u128);
    while y != 0 {
        if y & 1 == 1 {
            r ^= x;
        }
        y >>= 1;
        let carry = x >> 127;
        x <<= 1;
        if carry == 1 {
            x ^= 0x87;
        }
    }
    r
}

/// x^e, x the element 2.
pub fn xpow(mut e: u64) -> u128 {
    let (mut r, mut b) = (1u128, 2u128);
    while e != 0 {
        if e & 1 == 1 {
            r = mul(r, b);
        }
        b = mul(b, b);
        e >>= 1;
    }
    r
}

/// The element of 16 little-endian bytes.
pub fn from_le(b: &[u8]) -> u128 {
    u128::from_le_bytes(b.try_into().expect("16 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reduction() {
        // x^127 * x = x^7 + x^2 + x + 1.
        assert_eq!(mul(1 << 127, 2), 0x87);
        assert_eq!(xpow(128), 0x87);
        assert_eq!(mul(xpow(1000), xpow(24)), xpow(1024));
    }
}
