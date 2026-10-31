//! The signature circuit's witness for one ECDSA P-256 verification: Straus's ladder of three
//! scalars over a table of eight points, as the circuit checks it.
//!
//! The circuit proves e G + r Q + m R = O with x(R) = r and r, m in [1, n), m = n - s: ECDSA's
//! equation s R = e G + r Q, R = s^-1 (e G + r Q). The prover supplies R's y, the table's sums,
//! two inverses, r's and m's bits and every accumulator of the ladder, which runs from the
//! identity over bits 255 down to 0 with digit e_j + 2 r_j + 4 m_j, each step a doubling then an
//! addition of the table entry. Points are projective (X : Y : Z) under Renes, Costello and
//! Batina's complete formulas for a = -3 (Algorithm 3 for a double, Algorithm 1 for a sum); the
//! circuit checks each step's exact coordinates, so the witness uses exactly these formulas.

use p256::elliptic_curve::bigint::{Encoding, U256};
use p256::elliptic_curve::ops::Reduce;
use p256::elliptic_curve::subtle::ConstantTimeLess;
use p256::{FieldBytes, FieldElement, Scalar};

const P: U256 = U256::from_be_hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
const N: U256 = U256::from_be_hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
const B: U256 = U256::from_be_hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b");
const GX: U256 = U256::from_be_hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
const GY: U256 = U256::from_be_hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");

/// A base-field element from an integer below p.
fn fe(x: &U256) -> FieldElement {
    FieldElement::from_bytes(&FieldBytes::from(x.to_be_bytes())).unwrap()
}

/// x mod p, for x below 2^256 (< 2 p).
fn fe_reduce(x: &U256) -> FieldElement {
    let r = if bool::from(x.ct_lt(&P)) { *x } else { x.wrapping_sub(&P) };
    fe(&r)
}

fn small(k: u64) -> FieldElement {
    fe(&U256::from_u64(k))
}

fn inv0(x: &FieldElement) -> FieldElement {
    Option::<FieldElement>::from(x.invert()).unwrap_or(FieldElement::ZERO)
}

/// The element's integer, little-endian bytes (Longfellow's encoding of a P-256 element).
pub fn le_bytes(x: &FieldElement) -> [u8; 32] {
    let mut b: [u8; 32] = x.to_bytes().into();
    b.reverse();
    b
}

#[derive(Clone, Copy)]
struct Pt {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
}

struct Curve {
    a: FieldElement,
    b3: FieldElement,
    a2: FieldElement,
    three: FieldElement,
    four: FieldElement,
}

impl Curve {
    fn new() -> Curve {
        let a = -small(3);
        let b = fe(&B);
        Curve {
            a,
            b3: b + b + b,
            a2: a * a,
            three: small(3),
            four: small(4),
        }
    }

    /// Algorithm 3: the double of (X : Y : Z).
    fn dbl(&self, p: &Pt) -> Pt {
        let (x, y, z) = (p.x, p.y, p.z);
        let d0 = x * x;
        let d1 = y * y;
        let d2 = z * z;
        let d3 = (x * y).double();
        let d4 = (x * z).double();
        let d5 = (y * z).double();
        let u = self.a * d4 + self.b3 * d2;
        let v = d1 - u;
        let w = d1 + u;
        let m = self.a * d0 - self.a2 * d2 + self.b3 * d4;
        let n = self.three * d0 + self.a * d2;
        Pt {
            x: d3 * v - d5 * m,
            y: v * w + n * m,
            z: self.four * d5 * d1,
        }
    }

    /// Algorithm 1: the sum of (X1 : Y1 : Z1) and (X2 : Y2 : Z2).
    fn add(&self, p: &Pt, q: &Pt) -> Pt {
        let a0 = p.x * q.x;
        let a1 = p.y * q.y;
        let a2 = p.z * q.z;
        let t3 = (p.x + p.y) * (q.x + q.y) - a0 - a1;
        let t4 = (p.x + p.z) * (q.x + q.z) - a0 - a2;
        let t5 = (p.y + p.z) * (q.y + q.z) - a1 - a2;
        let z = self.a * t4 + self.b3 * a2;
        let x = a1 - z;
        let o = a1 + z;
        let k = self.three * a0 + self.a * a2;
        let l = self.b3 * t4 + self.a * (a0 - self.a * a2);
        Pt {
            x: t3 * x - t5 * l,
            y: x * o + k * l,
            z: t5 * o + t3 * k,
        }
    }

    fn affine(&self, p: &Pt) -> (FieldElement, FieldElement) {
        let zi = inv0(&p.z);
        (p.x * zi, p.y * zi)
    }
}

fn pt(x: FieldElement, y: FieldElement) -> Pt {
    Pt {
        x,
        y,
        z: FieldElement::ONE,
    }
}

const IDENTITY: Pt = Pt {
    x: FieldElement::ZERO,
    y: FieldElement::ONE,
    z: FieldElement::ZERO,
};

fn bit(x: &U256, j: usize) -> u8 {
    let limbs = x.to_le_bytes();
    (limbs[j / 8] >> (j % 8)) & 1
}

fn scalar_of(x: &U256) -> Scalar {
    <Scalar as Reduce<U256>>::reduce(*x)
}

fn uint_of(s: &Scalar) -> U256 {
    U256::from_be_slice(&s.to_bytes())
}

/// One verification's witness values, in the circuit's order: B (r's 256 bits, then m's), H (R's y,
/// x(R)^-1, m^-1, G + Q, G + R, R + Q, G + R + Q, x then y each), ACC (the accumulator after each
/// bit, bit 0's first, X, Y, Z each), then the hint 1 / x_Q^2.
pub struct StrausWitness {
    pub b: Vec<u8>,
    pub h: Vec<FieldElement>,
    pub acc: Vec<FieldElement>,
    pub ik: FieldElement,
}

/// The witness of the verification of signature `sig` (r || s, big-endian) on digest `z` (the
/// SHA-256 digest's 32 bytes, read as a big-endian integer) under the key (`qx`, `qy`) (each 32
/// bytes big-endian). Nothing is checked here: a signature that does not hold gives values the
/// circuit refuses.
pub fn straus(z: &[u8; 32], qx: &[u8; 32], qy: &[u8; 32], sig: &[u8; 64]) -> StrausWitness {
    let c = Curve::new();
    let zi = U256::from_be_slice(z);
    let r = U256::from_be_slice(&sig[..32]);
    let s = U256::from_be_slice(&sig[32..]);
    let (zn, rn, sn) = (scalar_of(&zi), scalar_of(&r), scalar_of(&s));
    let rp = fe_reduce(&r);
    let m = -sn; // n - (s mod n), 0 when s = 0 mod n
    let m_int = uint_of(&m);
    let w = Option::<Scalar>::from(sn.invert()).unwrap_or(Scalar::ZERO);
    let u1 = uint_of(&(zn * w));
    let u2 = uint_of(&(rn * w));
    let q = pt(fe_reduce(&U256::from_be_slice(qx)), fe_reduce(&U256::from_be_slice(qy)));
    let g = pt(fe(&GX), fe(&GY));

    // R from u1 G + u2 Q, over the table O, G, Q, G + Q.
    let t0 = [IDENTITY, g, q, c.add(&g, &q)];
    let mut acc = IDENTITY;
    for j in (0..256).rev() {
        let d = (bit(&u1, j) + 2 * bit(&u2, j)) as usize;
        acc = c.add(&c.dbl(&acc), &t0[d]);
    }
    let (_, ry) = c.affine(&acc);
    let rpt = pt(rp, ry);

    let gq = c.affine(&c.add(&g, &q));
    let gr = c.affine(&c.add(&g, &rpt));
    let rq = c.affine(&c.add(&rpt, &q));
    let grq = c.affine(&c.add(&g, &pt(rq.0, rq.1)));
    let h = vec![
        ry,
        inv0(&rp),
        inv0(&fe(&m_int)),
        gq.0,
        gq.1,
        gr.0,
        gr.1,
        rq.0,
        rq.1,
        grq.0,
        grq.1,
    ];
    let tbl = [
        IDENTITY,
        g,
        q,
        pt(gq.0, gq.1),
        rpt,
        pt(gr.0, gr.1),
        pt(rq.0, rq.1),
        pt(grq.0, grq.1),
    ];
    let mut accs = Vec::with_capacity(256);
    let mut a = IDENTITY;
    for j in (0..256).rev() {
        let d = (bit(&zi, j) + 2 * bit(&r, j) + 4 * bit(&m_int, j)) as usize;
        a = c.add(&c.dbl(&a), &tbl[d]);
        accs.push(a);
    }
    accs.reverse();
    let mut acc_out = Vec::with_capacity(768);
    for p in &accs {
        acc_out.extend_from_slice(&[p.x, p.y, p.z]);
    }
    let mut b = Vec::with_capacity(512);
    for j in 0..256 {
        b.push(bit(&r, j));
    }
    for j in 0..256 {
        b.push(bit(&m_int, j));
    }
    let ik = inv0(&(q.x * q.x));
    StrausWitness {
        b,
        h,
        acc: acc_out,
        ik,
    }
}

/// The P-256 group order's big-endian bytes (for callers' range checks).
pub fn order_be() -> [u8; 32] {
    N.to_be_bytes()
}
