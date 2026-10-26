//! Pinned parameters.  Four moduli are kept distinct:
//! p (P-256 base field = Tom-256 group order), n (P-256 order),
//! pT (Tom-256 base field), r/ell (BLS12-381 scalar field).
//! Tom constants: hpicrypto/ecdsa_pops@e05148765142b237f369a4336a0898c7f29b78b2,
//! CDLS/t256 (MIT, see THIRD_PARTY_NOTICES.md).

/// Rounds of the scalar-multiplication proof (soundness error 2^-128 per bit).
pub const SM_ROUNDS: usize = 128;

/// Minimum security (bits) every component must reach.  The overall level is
/// bounded by BLS12-381 (≈ 126 bits, Guillevic–Masson–Thomé 2019); no other
/// component may be weaker, so we require the nominal 128.
pub const MIN_SECURITY_BITS: u32 = 128;
/// Transfer responses z must stay below 2^MAX_Z_BITS < ℓ (≈ 2^254.86).
pub const MAX_Z_BITS: u32 = 254;

/// Tom-256 base field prime pT (decimal).
pub const TOM_P_DEC: &str = "115792089210356248762697446949407573530594504085698471288169790229257723883799";
/// P-256 base field prime p (= Tom-256 group order).
pub const P256_P_HEX: &str = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
/// P-256 curve coefficient b.
pub const P256_B_HEX: &str = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
/// BLS12-381 scalar field order.
pub const BLS_R_HEX: &str = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";
