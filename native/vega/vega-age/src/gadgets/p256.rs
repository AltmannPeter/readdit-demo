//! P-256 points and ECDSA verification inside the rules.
//!
//! The rules compute in the field of P-256 coordinates, so a point is two slots and each curve
//! formula is a few rules. Points are affine, and the formulas are the incomplete ones: an
//! addition needs two different x-coordinates. Every addition checks that condition, so the
//! rules never compute a wrong sum. Doubling needs y ≠ 0, which holds on P-256 because the
//! curve has no point of order two.

use std::sync::OnceLock;

use bellpepper_core::{ConstraintSystem, SynthesisError, boolean::Boolean};
use ff::{Field, PrimeField};
use group::{Curve, Group, prime::PrimeCurveAffine};
use halo2curves::{
  CurveAffine,
  ff_ext::Legendre,
  secp256r1::{Fq, Secp256r1, Secp256r1Affine},
};
use sha2::{Digest, Sha256};
use vega_prover::provider::pt256::t256;

use super::bits::{alloc_bits, be_bits, less_than, less_than_values, pack};
use super::lc::{Lc, equal, from_be, inverse, inverse_all, mul, mux, nonzero, product, val};
use super::values::Values;

/// The order n of the P-256 group, big-endian.
pub const ORDER: [u8; 32] = [
  0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// A public key: the big-endian coordinates of a P-256 point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
  pub x: [u8; 32],
  pub y: [u8; 32],
}

impl PublicKey {
  pub fn from_point(point: &Secp256r1Affine) -> Self {
    PublicKey { x: super::lc::to_be(&point.x), y: super::lc::to_be(&point.y) }
  }
}

/// An ECDSA signature as the rules take it: r and s⁻¹ mod n, as 32 big-endian bytes each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature {
  pub r: [u8; 32],
  pub s_inv: [u8; 32],
}

impl Signature {
  /// Converts a standard signature (r, s). The prover computes s⁻¹ outside the rules.
  pub fn from_rs(r: &[u8; 32], s: &[u8; 32]) -> Self {
    let s_inv = scalar(s).and_then(|s| Option::from(s.invert())).unwrap_or(Fq::ZERO);
    Signature { r: *r, s_inv: scalar_to_be(&s_inv) }
  }
}

/// The scalar with these big-endian bytes, if it is below n.
pub fn scalar(bytes: &[u8; 32]) -> Option<Fq> {
  let mut repr = <Fq as PrimeField>::Repr::default();
  repr.as_mut().copy_from_slice(bytes);
  repr.as_mut().reverse();
  Option::from(Fq::from_repr(repr))
}

/// The 32 big-endian bytes of a scalar.
pub fn scalar_to_be(s: &Fq) -> [u8; 32] {
  let mut bytes = [0u8; 32];
  bytes.copy_from_slice(s.to_repr().as_ref());
  bytes.reverse();
  bytes
}

/// A point as two weighted sums, its affine coordinates.
#[derive(Clone)]
pub struct Point {
  pub x: Lc,
  pub y: Lc,
}

impl Point {
  pub fn constant(p: &Secp256r1Affine) -> Self {
    Point { x: Lc::constant(p.x), y: Lc::constant(p.y) }
  }

  /// Two new slots that hold a key.
  pub fn alloc<CS: ConstraintSystem<t256::Scalar>>(
    mut cs: CS,
    key: Option<&PublicKey>,
  ) -> Result<Self, SynthesisError> {
    let x = Lc::alloc(cs.namespace(|| "x"), key.map(|k| from_be(&k.x)))?;
    let y = Lc::alloc(cs.namespace(|| "y"), key.map(|k| from_be(&k.y)))?;
    Ok(Point { x, y })
  }
}

/// The point through `p` on the line of slope λ that meets the curve again at x-coordinate
/// `other_x`: x = λ² − x_P − other_x and y = λ · (x_P − x) − y_P, with one rule each.
fn from_slope<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  lambda: &Lc,
  p: &Point,
  other_x: &Lc,
) -> Result<Point, SynthesisError> {
  let x = Lc::alloc(
    cs.namespace(|| "x"),
    val([lambda.value, p.x.value, other_x.value], |[l, a, b]| l * l - a - b),
  )?;
  product(cs.namespace(|| "x rule"), lambda, lambda, &(&x + &p.x + other_x));
  let y = Lc::alloc(
    cs.namespace(|| "y"),
    val([lambda.value, p.x.value, x.value, p.y.value], |[l, a, x, y]| l * (a - x) - y),
  )?;
  product(cs.namespace(|| "y rule"), lambda, &(&p.x - &x), &(&y + &p.y));
  Ok(Point { x, y })
}

/// P + Q, in four rules. A rule checks that x_Q − x_P has an inverse. The slope λ then has
/// exactly one value with λ · (x_Q − x_P) = y_Q − y_P.
pub fn add<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  p: &Point,
  q: &Point,
) -> Result<Point, SynthesisError> {
  let dx = &q.x - &p.x;
  let dy = &q.y - &p.y;
  nonzero(cs.namespace(|| "different x"), &dx)?;
  let lambda =
    Lc::alloc(cs.namespace(|| "slope"), val([dx.value, dy.value], |[dx, dy]| dy * inverse(dx)))?;
  product(cs.namespace(|| "slope rule"), &lambda, &dx, &dy);
  from_slope(cs.namespace(|| "sum"), &lambda, p, &q.x)
}

/// 2P, in four rules. The tangent's slope satisfies λ · 2y = 3x² + a, with a = −3.
pub fn double<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  p: &Point,
) -> Result<Point, SynthesisError> {
  let xx = mul(cs.namespace(|| "x squared"), &p.x, &p.x)?;
  let rise = xx.scale(t256::Scalar::from(3)) - &Lc::small(3);
  let run = p.y.scale(t256::Scalar::from(2));
  let lambda = Lc::alloc(
    cs.namespace(|| "slope"),
    val([rise.value, run.value], |[rise, run]| rise * inverse(run)),
  )?;
  product(cs.namespace(|| "slope rule"), &lambda, &run, &rise);
  from_slope(cs.namespace(|| "double"), &lambda, p, &p.x)
}

/// `if0` when the bit is zero and `if1` when it is one, in two rules.
pub fn choose<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  bit: &Boolean,
  if0: &Point,
  if1: &Point,
) -> Result<Point, SynthesisError> {
  let bit = Lc::bit(bit);
  let x = mux(cs.namespace(|| "x"), &bit, &if0.x, &if1.x)?;
  let y = mux(cs.namespace(|| "y"), &bit, &if0.y, &if1.y)?;
  Ok(Point { x, y })
}

/// Fixed points for the scalar multiplications.
struct Constants {
  /// The start A of the accumulator in [`multiply`], and −2^256 · A, which removes it again.
  start: Secp256r1Affine,
  start_removed: Secp256r1Affine,
  /// For window i of [`multiply_generator`], the points d · 4^i · G + B_i for the digits d = 0..4.
  windows: Vec<[Secp256r1Affine; 4]>,
  /// −(B_0 + … + B_127), which removes the window offsets again.
  offsets_removed: Secp256r1Affine,
}

/// (p + 1)/4 for the field modulus p, least significant limb first: 2^254 − 2^222 + 2^190 + 2^94.
const SQRT_EXPONENT: [u64; 4] = [0, 0x4000_0000, 0x4000_0000_0000_0000, 0x3fff_ffff_c000_0000];

/// A point whose discrete logarithm nobody knows: the first x = SHA-256(label ‖ index ‖ counter)
/// that lies on the curve, with the even y. This is the try-and-increment method.
fn hash_to_point(label: &[u8], index: u64) -> Secp256r1Affine {
  let mut counter = 0u64;
  loop {
    let digest: [u8; 32] = Sha256::new()
      .chain_update(label)
      .chain_update(index.to_be_bytes())
      .chain_update(counter.to_be_bytes())
      .finalize()
      .into();
    let x = from_be(&digest);
    let y_squared = x * x * x + Secp256r1Affine::a() * x + Secp256r1Affine::b();
    // A root exists exactly where the Legendre symbol is not −1, which costs far less than the
    // root. As p ≡ 3 mod 4, the root is y²^((p + 1)/4), the one `sqrt` gives.
    if y_squared.legendre() != -1 {
      let y = y_squared.pow_vartime(SQRT_EXPONENT);
      let y = if bool::from(y.is_odd()) { -y } else { y };
      return Option::from(Secp256r1Affine::from_xy(x, y)).expect("the point is on the curve");
    }
    counter += 1;
  }
}

fn constants() -> &'static Constants {
  static CONSTANTS: OnceLock<Constants> = OnceLock::new();
  CONSTANTS.get_or_init(|| {
    let start = hash_to_point(b"vega-age accumulator start", 0);
    let mut shifted = Secp256r1::from(start);
    for _ in 0..256 {
      shifted = shifted.double();
    }

    // The entries d · 4^i · G + B_i for d = 0..4 by additions of 4^i · G, rather than by scalar
    // multiplications, then all of them in affine coordinates with one inversion.
    let mut base = Secp256r1::generator();
    let mut offsets = Secp256r1::identity();
    let mut entries = Vec::with_capacity(4 * 128);
    for i in 0..128 {
      let offset = Secp256r1::from(hash_to_point(b"vega-age window offset", i));
      let mut entry = offset;
      for _ in 0..4 {
        entries.push(entry);
        entry += base;
      }
      offsets += offset;
      base = base.double().double();
    }
    let mut affine = vec![Secp256r1Affine::identity(); entries.len()];
    Secp256r1::batch_normalize(&entries, &mut affine);
    let windows = affine.chunks_exact(4).map(|w| [w[0], w[1], w[2], w[3]]).collect();

    Constants {
      start,
      start_removed: (-shifted).to_affine(),
      windows,
      offsets_removed: (-offsets).to_affine(),
    }
  })
}

/// k · P for a scalar k given by its bits, most significant first, by double-and-add.
///
/// The accumulator starts at the fixed point A instead of at infinity, which affine
/// coordinates cannot hold. Nobody knows the discrete logarithm of A, so for an honest prover
/// the accumulator never has the x-coordinate of P. After the n bits the accumulator holds
/// 2^n · A + k · P, and one more addition removes 2^n · A. Ten rules per bit.
pub fn multiply<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  bits: &[Boolean],
  p: &Point,
) -> Result<Point, SynthesisError> {
  assert_eq!(bits.len(), 256);
  let constants = constants();
  let mut acc = Point::constant(&constants.start);
  for (i, bit) in bits.iter().enumerate() {
    let cs = &mut cs.namespace(|| format!("bit {i}"));
    let doubled = double(cs.namespace(|| "double"), &acc)?;
    let added = add(cs.namespace(|| "add"), &doubled, p)?;
    acc = choose(cs.namespace(|| "choose"), bit, &doubled, &added)?;
  }
  add(cs.namespace(|| "remove start"), &acc, &Point::constant(&constants.start_removed))
}

/// k · G for the generator G, in windows of two bits.
///
/// Window i covers the bits of weight 2 · 4^i and 4^i. Its four entries d · 4^i · G + B_i are
/// constants, so selecting one costs a single rule, the product of the two bits. Each window
/// has its own offset B_i, a point nobody knows the discrete logarithm of, so for an honest
/// prover no entry has the x-coordinate of the running sum. A last addition removes the
/// offsets. Five rules per window.
pub fn multiply_generator<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  bits: &[Boolean],
) -> Result<Point, SynthesisError> {
  assert_eq!(bits.len(), 256);
  let constants = constants();
  let mut sum: Option<Point> = None;
  for (i, entries) in constants.windows.iter().enumerate() {
    let cs = &mut cs.namespace(|| format!("window {i}"));
    let high = Lc::bit(&bits[254 - 2 * i]);
    let low = Lc::bit(&bits[255 - 2 * i]);
    let both = mul(cs.namespace(|| "both bits"), &high, &low)?;
    // The entry for d = 2 · high + low, as a weighted sum of 1, low, high and both.
    let coordinate = |c: [t256::Scalar; 4]| {
      Lc::constant(c[0])
        + &low.scale(c[1] - c[0])
        + &high.scale(c[2] - c[0])
        + &both.scale(c[3] - c[2] - c[1] + c[0])
    };
    let entry = Point { x: coordinate(entries.map(|e| e.x)), y: coordinate(entries.map(|e| e.y)) };
    sum = Some(match sum {
      None => entry,
      Some(sum) => add(cs.namespace(|| "add"), &sum, &entry)?,
    });
  }
  let sum = sum.expect("there are 128 windows");
  add(cs.namespace(|| "remove offsets"), &sum, &Point::constant(&constants.offsets_removed))
}

/// Adds the rules that `signature` is an ECDSA signature by `key` on a message whose SHA-256
/// digest has the bits `digest`. This is the verification of Figure 6 of the Vega paper.
///
/// Standard ECDSA verification (FIPS 186-5, clause 6.4.2) computes u1 = z · s⁻¹ and
/// u2 = r · s⁻¹ modulo the group order n, which is not the field of the rules. The prover
/// supplies s⁻¹ instead of s, and the rules compute s⁻¹ · (z · G + r · Q), which equals
/// u1 · G + u2 · Q. Both r and s⁻¹ are checked to lie in 1..n.
///
/// The rules then require the x-coordinate of that point to equal r. ECDSA requires equality
/// modulo n, which also accepts x = r + n. Figure 6 covers that case with an extra bit. These
/// rules leave it out, so they reject the signatures whose point has an x-coordinate from n
/// to p − 1, which are 2^126 of the 2^256 possible values.
///
/// A witness generator, which ignores the rules, takes the values natively instead.
pub fn verify<CS: ConstraintSystem<t256::Scalar>>(
  mut cs: CS,
  digest: &[Boolean],
  key: &Point,
  signature: Option<&Signature>,
) -> Result<(), SynthesisError> {
  if cs.is_witness_generator() {
    cs.extend_aux(&verify_values(digest, key, signature)?.0);
    return Ok(());
  }
  let r = alloc_bits(cs.namespace(|| "r"), signature.map(|s| be_bits(&s.r)), 256)?;
  let s_inv = alloc_bits(cs.namespace(|| "s inverse"), signature.map(|s| be_bits(&s.s_inv)), 256)?;
  for (name, bits) in [("r", &r), ("s inverse", &s_inv)] {
    less_than(cs.namespace(|| format!("{name} below n")), bits, &ORDER)?;
    nonzero(cs.namespace(|| format!("{name} not zero")), &pack(bits))?;
  }
  let z_g = multiply_generator(cs.namespace(|| "z G"), digest)?;
  let r_q = multiply(cs.namespace(|| "r Q"), &r, key)?;
  let sum = add(cs.namespace(|| "z G + r Q"), &z_g, &r_q)?;
  let point = multiply(cs.namespace(|| "s inverse times the sum"), &s_inv, &sum)?;
  equal(cs.namespace(|| "x equals r"), &point.x, &pack(&r));
  Ok(())
}

/// The values [`verify`] allocates, computed natively, in its order: the bits of r and s⁻¹, the
/// products of their comparisons with n and the inverses that show them nonzero, then the values
/// of z · G ([`generator_values`]), of r · Q ([`multiply_values`]), of their sum ([`add`]) and of
/// s⁻¹ times the sum.
fn verify_values(
  digest: &[Boolean],
  key: &Point,
  signature: Option<&Signature>,
) -> Result<Values, SynthesisError> {
  let known = || {
    let digest = digest.iter().map(Boolean::get_value).collect::<Option<Vec<bool>>>()?;
    Some((signature?, digest, Affine { x: key.x.value?, y: key.y.value? }))
  };
  let (signature, digest, key) = known().ok_or(SynthesisError::AssignmentMissing)?;
  let (r, s_inv) = (be_bits(&signature.r), be_bits(&signature.s_inv));
  let mut values = Values::with_capacity(VERIFY_VALUES);
  values.bits(&r);
  values.bits(&s_inv);
  for (bits, bytes) in [(&r, &signature.r), (&s_inv, &signature.s_inv)] {
    less_than_values(&mut values, bits, &ORDER);
    values.push(inverse(from_be(bytes)));
  }
  let z_g = generator_values(&mut values, &digest);
  let r_q = multiply_values(&mut values, &r, key);
  let sum = add_values(&mut values, z_g, r_q);
  multiply_values(&mut values, &s_inv, sum);
  Ok(values)
}

/// The values of one verification: the bits, comparisons and inverses of r and s⁻¹, 128 window
/// products and 128 additions, two multiplications of 256 bits and an addition each, and the
/// addition of z · G and r · Q.
const VERIFY_VALUES: usize = 2 * (256 + 256 + 1) + (128 + 4 * 128) + 2 * (10 * 256 + 4) + 4;

/// A point's affine coordinates, as values.
#[derive(Clone, Copy, Debug)]
struct Affine {
  x: t256::Scalar,
  y: t256::Scalar,
}

impl From<&Secp256r1Affine> for Affine {
  fn from(p: &Secp256r1Affine) -> Self {
    Affine { x: p.x, y: p.y }
  }
}

/// A point in Jacobian coordinates, x = X/Z² and y = Y/Z³, for chains of doublings and
/// additions without inversions. The formulas are the rules' slopes over a common denominator and
/// use no curve equation, so they give the rules' points, on the curve or not, whenever the
/// slopes' denominators are not zero.
#[derive(Clone, Copy, Debug)]
struct Jacobian {
  x: t256::Scalar,
  y: t256::Scalar,
  z: t256::Scalar,
}

impl Jacobian {
  fn from_affine(p: Affine) -> Self {
    Jacobian { x: p.x, y: p.y, z: t256::Scalar::ONE }
  }

  /// 2P along the tangent of slope (3x² − 3)/(2y), as [`double`] (dbl-2001-b, a = −3):
  /// Z' = 2YZ, which is zero where 2y is.
  fn double(&self) -> Self {
    let delta = self.z.square();
    let gamma = self.y.square();
    let beta4 = (self.x * gamma).double().double();
    let alpha = (self.x - delta) * (self.x + delta);
    let alpha = alpha.double() + alpha;
    let x = alpha.square() - beta4.double();
    let z = (self.y + self.z).square() - gamma - delta;
    let y = alpha * (beta4 - x) - gamma.square().double().double().double();
    Jacobian { x, y, z }
  }

  /// P + Q for an affine Q along the chord of slope (y_Q − y_P)/(x_Q − x_P), as [`add`]
  /// (madd): Z' = Z · H with H = Z² · (x_Q − x_P), which is zero where x_Q − x_P is.
  fn add_affine(&self, q: &Affine) -> Self {
    let zz = self.z.square();
    let h = q.x * zz - self.x;
    let r = q.y * zz * self.z - self.y;
    let hh = h.square();
    let hhh = hh * h;
    let v = self.x * hh;
    let x = r.square() - hhh - v.double();
    let y = r * (v - x) - self.y * hhh;
    Jacobian { x, y, z: self.z * h }
  }
}

/// Inverts every value with one inversion ([`inverse_all`]), or none if a value is zero, whose
/// inverse the rules take as zero.
fn invert_all(values: &mut [t256::Scalar]) -> Option<()> {
  if values.iter().any(|v| bool::from(v.is_zero())) {
    return None;
  }
  inverse_all(values);
  Some(())
}

/// The affine coordinates of points, with one inversion, or none if a point has Z = 0.
fn normalize(points: &[Jacobian]) -> Option<Vec<Affine>> {
  let mut inverses: Vec<t256::Scalar> = points.iter().map(|p| p.z).collect();
  invert_all(&mut inverses)?;
  let affine = points.iter().zip(&inverses).map(|(p, z)| {
    let zz = z.square();
    Affine { x: p.x * zz, y: p.y * zz * z }
  });
  Some(affine.collect())
}

/// The values of [`add`] for P + Q: the inverse of x_Q − x_P (zero for zero), the slope, and the
/// sum's coordinates.
fn add_values(values: &mut Values, p: Affine, q: Affine) -> Affine {
  let inv = inverse(q.x - p.x);
  let lambda = (q.y - p.y) * inv;
  let x = lambda.square() - p.x - q.x;
  let y = lambda * (p.x - x) - p.y;
  values.0.extend([inv, lambda, x, y]);
  Affine { x, y }
}

/// The values of [`double`] for 2P: x², the slope, and the double's coordinates.
fn double_values(values: &mut Values, p: Affine) -> Affine {
  let xx = p.x.square();
  let lambda = (xx.double() + xx - t256::Scalar::from(3)) * inverse(p.y.double());
  let x = lambda.square() - p.x - p.x;
  let y = lambda * (p.x - x) - p.y;
  values.0.extend([xx, lambda, x, y]);
  Affine { x, y }
}

/// The values of [`choose`]: the coordinates of `if1` when the bit is set, of `if0` otherwise.
fn choose_values(values: &mut Values, bit: bool, if0: Affine, if1: Affine) -> Affine {
  let chosen = if bit { if1 } else { if0 };
  values.0.extend([chosen.x, chosen.y]);
  chosen
}

/// The values of [`multiply`] for k · P with k's bits `bits`, most significant first, and k · P.
fn multiply_values(values: &mut Values, bits: &[bool], p: Affine) -> Affine {
  let constants = constants();
  let start = Affine::from(&constants.start);
  let acc = multiply_chain(values, bits, start, p).unwrap_or_else(|| {
    // A slope's denominator is zero, and the rules take its inverse as zero: their values, one
    // slope after the other.
    let mut acc = start;
    for &bit in bits {
      let doubled = double_values(values, acc);
      let added = add_values(values, doubled, p);
      acc = choose_values(values, bit, doubled, added);
    }
    acc
  });
  add_values(values, acc, Affine::from(&constants.start_removed))
}

/// The values of [`multiply`]'s doublings, additions and choices with two inversions: the chain
/// in Jacobian coordinates, then the affine coordinates of all its points at once, then the
/// inverses of all the slopes' denominators at once. Returns the accumulator after the last bit,
/// or none, before it pushes any value, if a denominator is zero.
fn multiply_chain(values: &mut Values, bits: &[bool], start: Affine, p: Affine) -> Option<Affine> {
  let mut chain = Vec::with_capacity(2 * bits.len());
  let mut acc = Jacobian::from_affine(start);
  for &bit in bits {
    let doubled = acc.double();
    let added = doubled.add_affine(&p);
    acc = if bit { added } else { doubled };
    chain.extend([doubled, added]);
  }
  let points = normalize(&chain)?;
  // The accumulator before each bit, and after the last.
  let chosen = bits.iter().zip(points.chunks_exact(2)).map(|(&b, pair)| pair[usize::from(b)]);
  let accs: Vec<Affine> = std::iter::once(start).chain(chosen).collect();
  // For each bit, 2y of the accumulator and x_P − x of the double.
  let mut inverses: Vec<t256::Scalar> =
    (0..bits.len()).flat_map(|i| [accs[i].y.double(), p.x - points[2 * i].x]).collect();
  invert_all(&mut inverses)?;
  for (i, &bit) in bits.iter().enumerate() {
    let (acc, doubled, added) = (accs[i], points[2 * i], points[2 * i + 1]);
    let xx = acc.x.square();
    let rise = xx.double() + xx - t256::Scalar::from(3);
    let inv = inverses[2 * i + 1];
    values.0.extend([xx, rise * inverses[2 * i], doubled.x, doubled.y]);
    values.0.extend([inv, (p.y - doubled.y) * inv, added.x, added.y]);
    choose_values(values, bit, doubled, added);
  }
  Some(accs[bits.len()])
}

/// The values of [`multiply_generator`] for z · G with z's bits `bits`, most significant first,
/// and z · G: for each window the product of its two bits and, from the second on, the addition
/// of its entry.
fn generator_values(values: &mut Values, bits: &[bool]) -> Affine {
  let constants = constants();
  let digit = |i: usize| (bits[254 - 2 * i], bits[255 - 2 * i]);
  let both = |i: usize| digit(i).0 && digit(i).1;
  let entries: Vec<Affine> = (0..constants.windows.len())
    .map(|i| {
      let (high, low) = digit(i);
      Affine::from(&constants.windows[i][2 * usize::from(high) + usize::from(low)])
    })
    .collect();
  let sum = generator_chain(values, &entries, both).unwrap_or_else(|| {
    // An entry has the running sum's x-coordinate: the rules' values, one slope after the other.
    values.bit(both(0));
    let mut sum = entries[0];
    for (i, entry) in entries.iter().enumerate().skip(1) {
      values.bit(both(i));
      sum = add_values(values, sum, *entry);
    }
    sum
  });
  add_values(values, sum, Affine::from(&constants.offsets_removed))
}

/// The values of [`multiply_generator`]'s windows with two inversions, as [`multiply_chain`]:
/// the running sum after the last window, or none, before any value, if an entry has the running
/// sum's x-coordinate.
fn generator_chain(
  values: &mut Values,
  entries: &[Affine],
  both: impl Fn(usize) -> bool,
) -> Option<Affine> {
  let mut acc = Jacobian::from_affine(entries[0]);
  let chain: Vec<Jacobian> = entries[1..]
    .iter()
    .map(|entry| {
      acc = acc.add_affine(entry);
      acc
    })
    .collect();
  let sums = normalize(&chain)?;
  // The running sum before window i, from the second window on.
  let before = |i: usize| if i == 1 { entries[0] } else { sums[i - 2] };
  let mut inverses: Vec<t256::Scalar> =
    (1..entries.len()).map(|i| entries[i].x - before(i).x).collect();
  invert_all(&mut inverses)?;
  values.bit(both(0));
  for i in 1..entries.len() {
    let (sum, entry, inv) = (before(i), entries[i], inverses[i - 1]);
    values.bit(both(i));
    values.0.extend([inv, (entry.y - sum.y) * inv, sums[i - 1].x, sums[i - 1].y]);
  }
  sums.last().copied()
}
