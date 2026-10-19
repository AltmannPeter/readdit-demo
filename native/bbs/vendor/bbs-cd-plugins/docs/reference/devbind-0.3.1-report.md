# Precomputed BBS device binding on ETSI committed disclosures: implementation report and specification, version 0.3.1

**Protocol:** `DEVBIND-BBS-TOM-ECDSA/0.3`  
**Date:** 15 October 2026 (0.3); 16 October 2026 (0.3.1)  
**Status:** **final.** 0.3 was frozen on 15 October 2026 as git tag `devbind-0.3-freeze`. 0.3.1 is an editorial revision of that specification: the protocol, the transcript, the wire format and the accepted language are unchanged (`PROTOCOL_ID` stays `DEVBIND-BBS-TOM-ECDSA/0.3`), so 0.3 and 0.3.1 implementations interoperate. Changes are listed in §0. The document supersedes `devbind-0.2-etsi-report.md`, which describes the earlier P1 implementation; that report is kept for the record.  
**Companion to:** `tom256-python-implementation-report.md` (the *original report*). Sections 1–10 follow its numbering.  
**Decisions:** `ANALYSIS-AND-DECISIONS-0.2.md` (D0–D6). **Options kept for later:** `FUTURE-OPTIONS-0.2.md`.  
**Implementation:** `devbind-rust/` (crate `devbind` 0.3.1). The source-tree SHA-256 is given in Appendix B.  
**BBS layer:** `bbs-committed-disclosures-rust-v0.7/` (crate `bbs_cd`, ETSI profile "BBS with Committed Disclosures" v0.7), unmodified. It is maintained in its own repository and **not** included in the freeze commit. The version used is identified by its tree SHA-256 (sorted `shasum -a 256` of all files, then hashed): `1fdd75dcdfcb7f9d12e124f1a1b9ef886268a6dcd9b31565a315429acd4b6049`.

This is a research specification derived from the code. Where this document and the code disagree, the code is the reference behaviour and the disagreement is a documentation defect.

- **No security claim.** Nothing here is a security claim. §10.4 gives the claim status. The 0.3 analysis is in `analysis-0.3/`; it is self-reviewed, and the remaining proofs are left to an independent cryptographic review.
- **Implementation limits.** The implementation is variable-time, uses a software signing device, and has not been reviewed. The required raw signing is available on Apple and Android hardware (§3.5.4).

**Conventions.**
- `‖` is concatenation. `I2OSP(x, k)` is the k-byte big-endian encoding and `OS2IP` its inverse.
- "uniform" means sampled by a CSPRNG (`OsRng`).
- MUST and SHOULD are used in the RFC 2119 sense.
- "Reject" means the verifier returns an error and stops processing.
- Code references are `module::function` in `devbind-rust/src`.
- k denotes the number of limbs per coordinate and 2k the number of key limbs.

## 0. Changes in 0.3.1

None of these changes the transcript, the wire format or the accepted language.

| Area | Change | Section |
|---|---|---|
| Security status | The 0.3 analysis is done (`analysis-0.3/`) and summarised; the ePrint 2025/1981 review is recorded; remaining proofs go to independent review | §10.4, §10.6 |
| Generator HT (G-1) | New normative requirement: HT MUST come from a publicly verifiable procedure; the prototype constant MUST NOT be used outside testing | §3.3, App. A |
| Device | Raw-digest signing is a MUST; Apple and Android support it | §3.5.4 |
| SM preparation | V = U − Q is an allowed equivalent of (ω − c)·Q′; the retry path cannot occur; the order in which the prover draws randomness is implementation-defined | §4.1.3 |
| Cloning | Corrected: a cloned slot reveals c, Q, the limbs and the openings, not the other hidden attributes | §10.3 |
| Verifier state | Outstanding requests SHOULD be bounded and SHOULD expire (L-2) | §10.3 |
| Batch verification | Implemented as the default `verify`; the bound is ≤ 2⁻¹²⁸ per batch, ≤ 2⁻¹²⁷ per verification | §10.2 |
| F-1 | The composition argument is written up (SMOC-1) | §4.1.6 |
| Implementation | Fixes L-1 (`segments` returns an error instead of panicking), L-2 (bounded, expiring `VerifierSession`), L-3 (single-use prover states). Optimizations A3–A7: fixed-base tables, batch normalisation, batch verification, optional parallelism (`--features parallel`). B4 (uncompressed points) not adopted. Tests 48 → 67 plus one doctest | §5, §6 |
| Measurements | §7 keeps the freeze measurements. After the optimizations, the same Mac measures, shared-bit p50: prepare 59.8 ms (12.7 ms with 10 threads), online 22.3 ms, verify 42.1 ms (25.4 ms with 10 threads) | §7 |

---

## 1. Decision and scope

**Original report.** Build the precomputed blinded-key presentation: BBS linkage, the cross-group transfer, the Tom-256 proof of Q = c·Q′, hardware raw signing and ordinary ECDSA verification under Q′. Then freeze a specification and analyse it. ECDSA-in-Tom is out of scope.

**Implemented in 0.3.**

| Item | Status |
|---|---|
| BBS issuance, presentation and committed-disclosure linkage | **ETSI CD v0.7** (`bbs_cd`). Peter's decision. |
| Presentation header | **P2 (D1): `ph` = the verifier's nonce and request context.** The BBS proof is plain ETSI usage and independent of the device signature. P1 (`ph = M`) is kept as a future option. |
| Security target | **D0: the BLS12-381 ceiling, ≈ 126 bits.** No other component may be weaker, so every component is ≥ 128 nominal bits. |
| Device-key encoding | 2k ETSI `SCALAR` limbs, always `COMMIT`. The **limb size b_x is an issuer parameter (D6)**: 64, 96 (default) or 128 bits. |
| BLS → Tom transfer | **Parametric (D6)**: repetitions R, challenge bits b_c and abort slack b_f are fixed by the verifier's request. The default is R = 1, b_c = 128, b_f = 16; the named alternative for 128-bit limbs is R = 2, b_c = 112, b_f = 8. ETSI generator roles. |
| Tom-256 proof Q = c·Q′ | SM with internal PA, **128 rounds (D2)**, profiles `draft00-shared-bit` and `separate-pa` |
| F-1 | **Closed for the composition by an on-curve proof for the committed key (D5 (b), §4.4)**. Standalone SM is unchanged. |
| Encoding / size changes | **None (D3)**; a size-optimised variant is described in `FUTURE-OPTIONS-0.2.md` §2 |
| Prepared ProofGen split | **Skipped (D4)**; the `prepared-bbs` feature remains for experiments |
| Raw signing | `RawSigner` trait; software device; raw-digest signing on Apple and Android hardware (§3.5.4) |
| Security-review fixes | RV-1 … RV-5 applied (§10.5); analysis findings L-1 … L-3 fixed in 0.3.1 (§0) |

**Trust assumption D-1 (Peter, 2026-10-15).** The issuer is trusted to issue correctly formed credentials and to check the device key: canonical encoding, on curve, non-identity, coordinates < p, and the attestation policy. In 0.3 the on-curve property is also proved inside every presentation (§4.4), so the composition no longer depends on the issuer's on-curve check for soundness. D-1 remains the basis for attestation and limb canonicity.

## 2. Performance context

**Verifier work per presentation** (straightforward, unbatched; default configuration 2k = 6, R = 1):

| Component | Count |
|---|---|
| SM P-256 scalar multiplications (α·Q′) | 128 |
| SM opening checks / PA equations | 256 / 1,024 |
| Tom point decompressions | 1,792 (SM) + 2k (T_j) + 2k·R (K2) + 9 (on-curve) |
| Tom scalar multiplications in `pa_verify` | 23 per round |
| On-curve proof | 6 equations, about 15 Tom scalar multiplications |
| BBS | one ETSI `ProofVerify` with 2k commitments |
| Transfer | 2k·R × (3 G1 + 3 Tom multiplications) |
| ECDSA | one verification |

**Prover preparation per SM round:** 2 P-256 and 26 Tom scalar multiplications. Per slot it adds:
- the on-curve proof (≈ 12 Tom multiplications);
- 2k·R DLEQ preparations per transfer set;
- `PrecomputeCommitment` for the 2k limbs.

Measured results are in §7. These counts are for the straightforward verifier. The implemented optimizations (§0; `devbind-rust/OPTIMIZATIONS.md`) batch the linear equations and use fixed-base tables without changing what is verified.

## 3. Statement and signing protocol

### 3.1 Fields and moduli

The four moduli are distinct types in the code and are never implicitly converted.

| Symbol | Value | Type in code | Used for |
|---|---|---|---|
| p | `ffffffff00000001000000000000000000000000ffffffffffffffffffffffff` | `tom::Fr` | P-256 coordinates; Tom scalars (commitment values, blinds, PA masks and responses, transfer s2) |
| n | `ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551` | `p256::Scalar` | ECDSA r, s; a, c, ω, α; the representative h |
| pT | `ffffffff0000000100000000000000017e72b42b30e7317793135661b1c4b117` (decimal in Appendix A) | `tom::Fq` | Tom-256 point coordinates |
| ℓ | `73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001` | `bls12_381::Scalar` | BBS messages and responses; commitment openings s_j; transfer s1 |

### 3.2 Roles and trust boundaries

| Role | Holds | Trusted for |
|---|---|---|
| Device | P-256 secret d (never exported); `public_key()`, `sign_representative(rep)` | correct ECDSA with hedged or RFC 6979 nonces; logs not shared with verifiers (privacy only) |
| Issuer | ETSI BBS secret key SK | D-1 (§1) |
| Holder software | credential, Q, slots (a, c, all masks), device handle | nothing in soundness and freshness games |
| Verifier | `IssuerParams`, its own `Request` objects | fresh, unpredictable, never-reused nonces |

The device key MUST be dedicated to this protocol, because raw signing makes the device a generic signing oracle for that key.

### 3.3 Public parameters and generators

- **P-256:** SEC 2 parameters (RustCrypto `p256` 0.13). The curve coefficient b is used by the on-curve proof.
- **Tom-256:** y² = x³ − 3x + b_T over F_pT, prime order p, generators GT = (3, …), HT = (5, …). The constants are in Appendix A.
  - **Requirement on HT (G-1).** Binding of every Tom-256 commitment requires that no party knows log_GT(HT). HT MUST be generated by a publicly verifiable procedure, for example HT = hash_to_curve with a dedicated DST (e.g. `"DEVBIND/<version>/Tom-256/HT"`) per RFC 9380, or a documented try-and-increment on a hashed seed.
  - The prototype value HT = (5, …) is copied from the HPI ecdsa_pops code, which documents no derivation. It MUST NOT be used outside testing. Replacing it changes every Tom-256 commitment value and therefore needs a new protocol version.
- **BBS:** ciphersuite `BLS12-381-SHA-256`; `api_id = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_S2S_"`.
  - Message generators: `create_generators(L+1, api_id)`.
  - Commitment generators: `(Y0, Y1) = create_generators(2, "COM_DIS_" ‖ api_id)`. **Y0 multiplies the message, Y1 the opening.**
- **Protocol:** `PROTOCOL_ID = "DEVBIND-BBS-TOM-ECDSA/0.3"`. Profiles `"draft00-shared-bit"` and `"separate-pa"`. Wire magic `DBP\x03`.
- **Fixed security parameters:**
  - R_SM = 128 SM rounds;
  - `MIN_SECURITY_BITS` = 128 (every transfer configuration must satisfy R·b_c ≥ 128);
  - `MAX_Z_BITS` = 254 (b_x + b_c + b_f ≤ 254, so z < ℓ).
- **Limb sizes (credential property):** b_x ∈ {64, 96, 128}, so k = ⌈256/b_x⌉ ∈ {4, 3, 2} limbs per coordinate. The default is 96 (2k = 6).
- **Transfer configurations (verifier policy, `config::TransferConfig`):**
  - R ∈ [1, 4];
  - b_c a multiple of 8 in [64, 128];
  - b_f ∈ [8, 32];
  - b_x + b_c + b_f ≤ 254;
  - R·b_c ≥ 128.

  Recommended: (R, b_c, b_f) = (1, 128, 16) for b_x ∈ {64, 96}, and (2, 112, 8) for b_x = 128. The rationale, with the measured cost comparison, is in `ANALYSIS-AND-DECISIONS-0.2.md`, "Rationale for D0, D2 and D6".
- **Domain-separation tags** (all distinct; `params.rs`):

| Tag | Used for |
|---|---|
| `DEVBIND/0.3/credential-header` | BBS header (§4.2.2) |
| `DEVBIND/0.3/request-context` | ctx (§3.5.3) |
| `DEVBIND/0.3/presentation-header` | ETSI `ph` (§3.5.3) |
| `DEVBIND/0.3/statement` | stmt (§4.3.1) |
| `DEVBIND/0.3/ecdsa-representative` | h input (§4.3.2) |
| `DEVBIND/0.3/device-binding-challenge` | M′ (§4.3.3) |
| `DEVBIND/0.3/transfer-challenge` | c_i (§4.3.4) |
| `DEVBIND/0.3/sm-bits` | b_i (§4.3.5) |
| `DEVBIND/0.3/pa-challenge`, `…/pa-challenge-h2f` | e_i in separate-pa (§4.3.5) |
| `DEVBIND/0.3/on-curve-challenge`, `…/on-curve-challenge-h2f` | e_oc (§4.3.6) |
| `DEVBIND/0.3/device-attestation` | simulated attestation (§3.5.1) |

### 3.4 Encodings

- **Transcript** (every DEVBIND hash):
  ```
  Transcript(dst; l_1 = v_1, …, l_k = v_k) =
      I2OSP(len(dst),1) ‖ dst ‖ ‖_i ( I2OSP(len(l_i),1) ‖ l_i ‖ I2OSP(len(v_i),4) ‖ v_i )
  ```
  Labels are the ASCII strings shown. `digest()` is SHA-256 of the bytes.
- **P-256 point:** SEC1 compressed, 33 bytes. Reject wrong length, a prefix other than 02/03, x ≥ p, x not on the curve, and the identity (`p256x::decode_point`).
- **Tom point:** `(02|03) ‖ I2OSP(x, 32)`, where the parity bit is the parity of y. Reject x ≥ pT, a non-residue, y = 0 with prefix 03, and a wrong prefix or length. The identity is 33 zero bytes. It is accepted **only** where the caller allows it (§10.2), never for U1 (`tom::decode_point`).
- **G1:** ZCash compressed, 48 bytes, decoded by `bbs_cd::primitives::decode_G1`. The point must be on the curve and torsion-free, and its canonical re-encoding must match. The identity is allowed only for the transfer announcement K1.
- **Scalars:** fixed-width 32-byte big-endian, with the explicit range checks of §10.2. The transfer response z is 31 bytes.

### 3.5 Algorithms

#### 3.5.1 Setup and issuance (`issuer.rs`)

1. **Setup.**
   - `SK = KeyGen(SHA-256 suite, 32 uniform bytes, key_info "devbind-issuer", default DST)`; `pk = SkToPk(SK)` (96 bytes).
   - Publish `IssuerParams = (pk, n_attr, b_x)`, with n_attr ∈ [1, 64], b_x ∈ {64, 96, 128}, L = 2k + n_attr.
   - Encoding: `I2OSP(len(pk),1) ‖ pk ‖ I2OSP(n_attr,2) ‖ I2OSP(b_x,1)`.
   - The decoder requires len(pk) = 96, a valid G2 key, n_attr ∈ [1, 64] and an allowed b_x.
2. **Simulated attestation.** Attestation is `"software-device-v0;" ‖ σ`. σ is a 64-byte P-256 ECDSA signature (SHA-256, RFC 6979) by a manufacturer key over `"DEVBIND/0.3/device-attestation" ‖ "software-device-v0;" ‖ Qb`.
3. **`issue(Qb, attestation, attributes)`.** The issuer MUST:
   1. decode Qb with the strict P-256 decoder;
   2. verify the attestation;
   3. check that exactly n_attr attributes are given, each at most 4,096 bytes (RV-1);
   4. compute the limbs (§4.2.1);
   5. form `messages = (Scalar(x_0), …, Scalar(x_{k−1}), Scalar(y_0), …, Scalar(y_{k−1}), Octets(attr_1), …)` and `message_types = (SCALAR ×2k, OCTETS ×n_attr)`;
   6. compute `signature = Sign(suite, SK, pk, header, messages, message_types)` (§4.2.2).
4. **Holder credential validation** (`validate_credential`). Accept iff:
   - Qb equals the device key;
   - there are exactly n_attr attributes, each at most 4,096 bytes;
   - Q decodes from Qb;
   - the limbs equal those of Q for b_x;
   - the messages equal (limbs ‖ attributes);
   - ETSI `Verify` passes.

#### 3.5.2 Slot preparation (offline; `presentation::prepare_slot`)

Inputs: credential, disclosure set I (strictly ascending, I ⊆ [2k, L)), profile, transfer configuration (R, b_c, b_f), spare-set count S. A slot is bound to (profile, I, R, b_c, b_f).

1. **Linkage** (`prepare_linkage`):
   1. Validate the transfer configuration for b_x.
   2. `(D_0..D_{2k−1}, s_0..s_{2k−1}) = PrecomputeCommitment(suite, limb messages, indexes 0..2k−1, message_types, rng)`, with D_j = m_j·Y0 + s_j·Y1.
   3. Disclosed scalars: `messages_to_scalars` (OCTETS).
   4. ρ_j ← Z_p and T_j = m_j·GT + ρ_j·HT, for j < 2k.
   5. For t = 0..S, prepare transfer set t with 2k·R DLEQ preparations, ordered limb-major (entry i belongs to limb ⌊i/R⌋) (§4.2.4).
   6. Disclosure states: COMMIT for j < 2k, DISCLOSE for I, HIDE otherwise.
   7. *Feature `prepared-bbs` only:* `ProofPrepare(…, precomputed_rands = s_j)`.
2. **Key proof** (`prepare_keyproof`):
   1. a ← [1, n−1]; c = a⁻¹ mod n; Q′ = a·Q.
   2. (ρ_x, ρ_y) = (Σ_{i<k} 2^(b_x·i)·ρ_i, Σ_{i<k} 2^(b_x·i)·ρ_{k+i}) mod p, and (C_x, C_y) = (x·GT + ρ_x·HT, y·GT + ρ_y·HT). This MUST equal fold(T) (§4.3.7); otherwise preparation fails.
   3. On-curve proof preparation for (C_x, C_y) with witness (x, ρ_x, y, ρ_y) (§4.4).
   4. 128 SM rounds (§4.1.3).
3. Encode the SM first messages (128 × 14 × 33 bytes) and the on-curve first message (9 × 33 bytes). Draw a 16-byte slot id.

#### 3.5.3 Request (verifier; `Request`)

`Request = (audience, nv, I, pk, profile, R, b_c, b_f)`, with nv ← 32 uniform bytes. `Request::new` uses the recommended transfer configuration for the issuer's b_x.

- **Encoding:**
  ```
  I2OSP(len(aud),2) ‖ aud ‖ I2OSP(len(nv),1) ‖ nv ‖ I2OSP(|I|,1) ‖ ‖_{i∈I} I2OSP(i,2)
  ‖ I2OSP(len(pk),1) ‖ pk ‖ I2OSP(len(profile),1) ‖ profile ‖ I2OSP(R,1) ‖ I2OSP(b_c,2) ‖ I2OSP(b_f,2)
  ```
  Decoding limits: total ≤ 4,096 bytes, aud ≤ 1,024, nv ≤ 64, pk ≤ 96, profile ≤ 64, exact length.
- **Validity:**
  - the profile is known;
  - pk = IssuerParams.pk;
  - 16 ≤ len(nv) ≤ 64;
  - len(aud) ≤ 1,024;
  - |I| ≤ 255;
  - the transfer configuration is valid for b_x (§3.3);
  - I is strictly ascending with every i ∈ [2k, L).
- **Context:**
  ```
  ctx = Transcript("DEVBIND/0.3/request-context"; "audience" = aud, "issuer_pk" = pk, "profile" = profile,
                   "disclosed" = ‖_{i∈I} I2OSP(i,2), "transfer" = I2OSP(R,1) ‖ I2OSP(b_c,2) ‖ I2OSP(b_f,2))
  ```
- **Presentation header (P2):** `ph = Transcript("DEVBIND/0.3/presentation-header"; "nv" = nv, "ctx" = ctx)`. These bytes are passed as ETSI `ph`.

#### 3.5.4 Raw signing (device; `device.rs`)

`sign_representative(rep)` takes rep of exactly 32 bytes. The signing input is e = OS2IP(rep) mod n, with **no hashing**. The device returns (r, s), 1 ≤ r, s < n, with no low-s normalisation. The software device uses hedged RFC 6979 by default (`sign_prehash_with_rng`) and plain RFC 6979 in deterministic mode. After `revoke()` it returns `DeviceUnavailable`. It keeps a log of the representatives it signed (test fixture).

**Device requirements.** A device MUST sign a caller-supplied 32-byte value as the ECDSA input without hashing it, and its key MUST be dedicated to this protocol, because raw signing lets the holder obtain a signature on any 32-byte value. Both mobile platforms provide this:
- Apple: `SecKeyCreateSignature` with `ecdsaSignatureDigestX962SHA256` (https://developer.apple.com/documentation/security/signing-and-verifying; https://developer.apple.com/documentation/security/seckeyalgorithm#Elliptic-curve-signature-digest-X962);
- Android Keystore: `KeyProperties.DIGEST_NONE` (https://developer.android.com/reference/android/security/keystore/KeyProperties#DIGEST_NONE).

That keys held in the Secure Enclave and in StrongBox accept these modes has not been tested on devices.

#### 3.5.5 Presentation (online; `presentation::present`)

1. **Policy checks.** Fail unless:
   - the request is valid;
   - (profile, I, R, b_c, b_f) match the slot;
   - the issuer matches.
2. **Honest checks, before any device call** (RV-1, RV-2). Fail unless:
   - signer.public_key() = Qb;
   - every disclosed attribute is ≤ 4,096 bytes;
   - the exact presentation size (§10.1) is ≤ 262,144 bytes.
3. **BBS proof (P2).** Run `ProofGen(suite, pk, signature, header, ph, messages, types, disclosures, precomputed_rands = s_j, rng)`. On INVALID (ETSI zero response), retry up to 4 calls in total. With `prepared-bbs`, use `complete_fast(ph)`. Fail unless the proof's commitments equal (D_j).
   - This step does not depend on the device and MAY run in parallel with steps 4–5. The code runs it sequentially.
4. **Representative h.** Compute stmt (§4.3.1). Loop: nh ← 32 bytes; hin = HInput(stmt, nv, ctx, nh); h = OS2IP(SHA-256(hin)) mod n; repeat while h = 0.
5. **Device signature.** Compute rep = I2OSP(c·h mod n, 32) and (r, s) = sign_representative(rep). Fail unless (r, s) verifies on rep under Q (RV-2).
6. **Transformation.** s′ = a·s mod n; if s′ > (n−1)/2 then s′ = n − s′. Fail if r = 0 or s′ = 0.
7. **Transfer sets.** For each set t = 0..S in order:
   1. M′ = DBDigest(hin, r, s′, TA_t, OCF, SMA) (§4.3.3).
   2. c_i = TransferChallenge(M′, i) for i < 2k·R.
   3. Compute the responses (§4.2.4). If any entry aborts, discard the set and continue with t + 1.
   4. Compute b = SMBits(M′), e = PAChallenges(M′, profile, b) and e_oc = OCChallenge(M′).
   5. Respond (§4.1.4, §4.4) and serialize (§10.1).
8. **Spare exhaustion.** If every set aborts, fail (slot burned).

The retry rule replaces every transfer announcement of the set. The BBS proof, the device signature and the SM and on-curve first messages are reused across attempts, and only one attempt's responses are released. With the default b_f = 16 an attempt aborts with probability 1 − (1 − 2⁻¹⁶)⁶ ≈ 9·10⁻⁵.

#### 3.5.6 Verification

Verification is fully determined by `IssuerParams`, the verifier's own `Request` and the presentation bytes (§10.2). `VerifierSession` consumes the nonce first, bounds the number of outstanding requests and lets them expire (§10.3).

### 3.6 What the proof does not establish

This is unchanged from the original report. The control that omits Q′ from stmt exists only in `presentation::insecure_test_controls`, behind the cargo feature `insecure-test-controls` (RV-3). Both attacks (retained-signature scaling and zero-query raw forgery) succeed against the control and fail against the candidate. The pre-nonce mode is not implemented.

## 4. Tom relation proof and BBS integration

### 4.1 Scalar-multiplication proof (`sm.rs`, `pa.rs`)

#### 4.1.1 Relation

```
PoK{ c, ρ_x, ρ_y, (x, y) :  C_x = x·GT + ρ_x·HT,  C_y = y·GT + ρ_y·HT,  (x, y) = c·Q′ }
```
Here Q′ is public, (C_x, C_y) is the fold of the T_j, and the witness is c, not d.

#### 4.1.2 Point-addition proof PA(A, B, T)

**Inputs.** Points A + B = T on P-256 with x_B ≠ x_A. Commitments C1..C6 to (x_A, y_A, x_B, y_B, x_T, y_T), with blinds r1..r6.

**Derived commitments.** F1 = C3 − C1, P1 = C4 − C2, P2 = C1 + C3 + C5, F3 = C1 − C5, P3 = C2 + C6.

**Prepare** (`pa_prepare_with_slope`):
```
f = x_B − x_A (≠ 0), g = x_A − x_T, t = (y_B − y_A)/f      (all mod p)
rt ← Z_p;  Ct = t·GT + rt·HT
masks (a_t, a_rt, a_f, a_rf, a_e1, a_e2, a_g, a_rg, a_e3) ← Z_p;  β ← Z_p \ {0};  (b2, b3, b4) ← Z_p
ann = [Ct,
       T1 = a_t·GT + a_rt·HT,   T2 = a_f·GT + a_rf·HT,   T3 = a_t·F1 + a_e1·HT,
       T4 = a_t·Ct + a_e2·HT,   T5 = a_g·GT + a_rg·HT,   T6 = a_g·Ct + a_e3·HT,
       U1 = (β f)·GT,           U2 = b2·F1 + b3·HT,      U3 = b4·GT]
w = (t, rt, f, r3−r1, (r4−r2)−(r3−r1)t, (r1+r3+r5)−rt·t, g, r1−r5, (r2+r6)−rt·g,
     β, −β(r3−r1), β f)
mask vector m = (a_t, a_rt, a_f, a_rf, a_e1, a_e2, a_g, a_rg, a_e3, b2, b3, b4)
```

**Respond.** z = m + e·w (mod p), 12 elements, in the order (z_t, z_rt, z_f, z_rf, z_e1, z_e2, z_g, z_rg, z_e3, v1, v2, v3).

**Verify** (`pa_verify`). Reject if U1 = O. Accept iff:
```
z_t GT + z_rt HT = T1 + e Ct        z_f GT + z_rf HT = T2 + e F1
z_t F1 + z_e1 HT = T3 + e P1        z_t Ct + z_e2 HT = T4 + e P2
z_g GT + z_rg HT = T5 + e F3        z_g Ct + z_e3 HT = T6 + e P3
v3 GT = U3 + e U1                   v1 F1 + v2 HT = U2 + e U1
```

#### 4.1.3 SM round preparation (`sm_prepare_rounds`)

Inputs: Q, c, Q′ with Q = c·Q′, (C_x, C_y), (ρ_x, ρ_y). For each round:
1. ω ← uniform in Z_n \ {0, c, 2c mod n} (resample on an excluded value).
2. U = ω·Q′ and V = (ω − c)·Q′. An implementation MAY compute V = U − Q, which is the same point because Q = c·Q′.
3. ρ_U, ρ_V ← (Z_p)², each component uniform. CU = (x_U·GT + ρ_U,0·HT, y_U·GT + ρ_U,1·HT), and likewise CV.
4. Run PA with (A, B, T) = (Q, V, U), (C1..C6) = (C_x, C_y, CV_x, CV_y, CU_x, CU_y) and (r1..r6) = (ρ_x, ρ_y, ρ_V,0, ρ_V,1, ρ_U,0, ρ_U,1).

The exclusions rule out every exceptional case: U = O ⇔ ω = 0, V = O ⇔ ω = c, and x_V = x_Q ⇔ V = ±Q ⇔ ω ∈ {0, 2c}. The 0.3 text's retry on an exceptional addition therefore cannot occur; implementations check and fail.

**Randomness.** Every value above MUST be sampled uniformly and independently. The order in which a prover draws them, and whether each round uses its own PRG stream seeded from a CSPRNG, is implementation-defined; it is not observable on the wire. The 0.3.1 code draws each round's randomness from its own ChaCha20 stream seeded from the caller's RNG, so seeded outputs differ from 0.3 and are the same for every parallelism setting.

In `draft00-shared-bit`, both response vectors z(e=0) and z(e=1) are computed at preparation.

**First message** (14 Tom points, in this order): `CU_x, CU_y, CV_x, CV_y, Ct, T1, T2, T3, T4, T5, T6, U1, U2, U3`.

#### 4.1.4 SM round response

For bit b and PA challenge e:
- b = 0: (α, ρ1, ρ2) = (ω, ρ_U).
- b = 1: (α, ρ1, ρ2) = (ω − c mod n, ρ_V).

z is the PA response for e. In shared-bit, e = b, and the precomputed vector is used.

#### 4.1.5 SM round verification (`sm_verify_round`)

Accept iff:
1. α ≠ 0, b ∈ {0, 1}, and W = α·Q′ ≠ O;
2. (x_W·GT + ρ1·HT, y_W·GT + ρ2·HT) equals (CU_x, CU_y) when b = 0, or (CV_x, CV_y) when b = 1;
3. `pa_verify` passes with (C1..C6) = (C_x, C_y, CV_x, CV_y, CU_x, CU_y), the 10 announcements and e.

#### 4.1.6 Profiles and restriction F-1

The profiles differ only in e_i (§4.3.5):

| Profile | e_i | Responses computed |
|---|---|---|
| `draft00-shared-bit` | e_i = b_i | both branches offline |
| `separate-pa` | e_i ∈ Z_p | online, field operations only |

**F-1.** When ω = c/2 (U = −V), the PA constraints do not force (C_x, C_y) to open to a curve point. A prover knowing c passes every round with probability 1 with an off-curve pair. **The SM/PA system on its own MUST therefore not be used to conclude that (C_x, C_y) opens to c·Q′.**
- In 0.3 every presentation carries the on-curve proof (§4.4) for the same (C_x, C_y).
- If the committed point is on the curve, SM extraction (0.1 lemma SM-1) applies. In the special case U = −V, a curve point satisfying the PA equations makes the line tangent at V, so the point equals U − V.
- This argument is written up as SMOC-1 in `analysis-0.3/SOUNDNESS_ANALYSIS.md` §3.
- Tests: `finding_f1_offcurve_result_accepted_by_standalone_sm` (SM alone); `oncurve_honest_extraction_and_offcurve_rejected` (on-curve proof); `offcurve_commitment_cannot_be_linked` (end to end: rejected at the transfer, and the on-curve proof fails on its own).

### 4.2 Numeric limbs and the ETSI committed-disclosure link

#### 4.2.1 Limbs

For Q = (x, y) with 0 ≤ x, y < p and limb size b_x:
- k = ⌈256/b_x⌉;
- x = Σ_{i<k} x_i·2^(b_x·i) and y = Σ_{i<k} y_i·2^(b_x·i), with 0 ≤ x_i, y_i < 2^b_x (little-endian limbs).

The credential messages 0..2k−1 are (x_0, …, x_{k−1}, y_0, …, y_{k−1}). Each is an ETSI `SCALAR` whose `ScalarInput` is `I2OSP(limb, 32)`. Attributes are `OCTETS` at indexes 2k..L−1. For b_x = 96 the limbs are 96, 96 and 64 bits.

#### 4.2.2 Header (schema binding, ETSI §3.3.2.2)

```
header = Transcript("DEVBIND/0.3/credential-header";
   "protocol" = PROTOCOL_ID, "api_id" = api_id, "L" = I2OSP(L,2),
   "limb_bits" = I2OSP(b_x,2), "limb_count" = I2OSP(2k,2),
   "limb_encoding" = "x_0..x_{k-1},y_0..y_{k-1};x=sum x_i*2^(b*i);little-endian;SCALAR",
   "attribute_encoding" = "OCTETS")
```

#### 4.2.3 ETSI CD proof as used (P2)

The proof is unchanged ETSI usage with **ph = the request's presentation header** (§3.5.3) and N = 2k commitments D_j = m_j·Y0 + s_j·Y1:
- The challenge (ETSI §3.7.4) hashes c_arr = (R, (i, m_i)_{i∈I}, Abar, Bbar, D, T1, T2, domain, N, (j, D_j, C̃_j)_{j<2k}) followed by `presentation_context(ph, D) = I2OSP(len(ph),8) ‖ ph ‖ I2OSP(N,8) ‖ D_0 ‖ …`. The DST is `api_id ‖ "COM_DIS_ETSI_PROOF_V1_H2S_"`.
- Proof octets: `I2OSP(N,8) ‖ Abar ‖ Bbar ‖ D ‖ ê ‖ r̂1 ‖ r̂3 ‖ m̂_1..m̂_U ‖ D_0..D_{2k−1} ‖ ŝ_0..ŝ_{2k−1} ‖ c`, with U = L − |I|.
- The verifier calls `ProofVerify(pk, P_bbs, header, ph, disclosed OCTETS, commitments = D from the proof, types, disclosures)`.
- The BBS challenge is **not** used by the device-binding proof (P2).

The prepared variant (`prepared-bbs`, not part of ETSI v0.7, skipped for 0.3) uses `ProofPrepare` and `complete_fast(ph)`. The patch is `devbind-rust/etsi-cd-integration/0001-prepared-proofgen-split.patch`.

#### 4.2.4 Transfer (`transfer.rs`)

Parameters (b_x, R, b_c, b_f). Let z_bits = b_x + b_c + b_f (≤ 254) and z_bytes = ⌈z_bits/8⌉. There are 2k·R entries, ordered limb-major; entry i belongs to limb j = ⌊i/R⌋.

**Prepare.**
- k ← [0, 2^z_bits): z_bytes uniform bytes with the excess top bits masked;
- k1 ← Z_ℓ (64 bytes reduced);
- k2 ← Z_p;
- K1 = k·Y0 + k1·Y1;
- K2 = k·GT + k2·HT.

**Respond** with challenge c_i < 2^b_c:
```
z = k + c_i·m_j      (integers)      abort unless 2^(b_x+b_c) ≤ z < 2^z_bits
s1 = k1 + c_i·s_j mod ℓ;   s2 = k2 + c_i·ρ_j mod p
```

**Verify.** Accept iff:
- 2^(b_x+b_c) ≤ z < 2^z_bits and c_i < 2^b_c;
- z·Y0 + s1·Y1 = K1 + c_i·D_j (z < ℓ, no reduction);
- z·GT + s2·HT = K2 + c_i·T_j (z < p).

**Abort and uniformity.** Because c_i·m_j < 2^(b_x+b_c), exactly 2^z_bits − 2^(b_x+b_c) values of k are accepted. Each entry therefore aborts with probability exactly 2^−b_f, and an accepted z is uniform on its interval, independent of m_j.

**Security per limb.** R independent repetitions with b_c-bit challenges give a challenge space of 2^(R·b_c) ≥ 2^128.

### 4.3 Transcript schedule (byte level)

**Dependency order (P2):**
```
[offline] D, T, transfer sets, on-curve first message, SM first messages, Q′
[online]  nv, ctx → ph → BBS proof (ETSI; its own challenge)
                  → nh → h → (r, s′) → M′ → {c_i, b_i, e_i, e_oc} → responses
```
The two proofs share D_j (the identical bytes appear in the BBS proof and in stmt) and the verifier's nonce (in ph, and in h). No response or proof byte is hashed into an earlier value.

#### 4.3.1 Statement
```
stmt = Transcript("DEVBIND/0.3/statement";
  "protocol" = PROTOCOL_ID, "profile" = profile, "issuer_pk" = pk, "header" = header,
  "L" = I2OSP(L,2), "disclosed" = ‖_{i∈I} (I2OSP(i,2) ‖ m_i(32)),
  "committed" = ‖_{j<2k} I2OSP(j,2), "Qprime" = Enc(Q′),
  "D" = ‖_j Enc(D_j), "T" = ‖_j Enc(T_j))
```

#### 4.3.2 Representative
```
hin = Transcript("DEVBIND/0.3/ecdsa-representative"; "statement" = stmt, "nv" = nv, "ctx" = ctx, "nh" = nh)
h   = OS2IP(SHA-256(hin)) mod n          (holder resamples nh if h = 0; verifier rejects h = 0)
rep = I2OSP(c·h mod n, 32)
```

#### 4.3.3 Device-binding digest
```
M′ = SHA-256( Transcript("DEVBIND/0.3/device-binding-challenge";
      "h_input" = SHA-256(hin), "ecdsa_r" = I2OSP(r,32), "ecdsa_s" = I2OSP(s′,32),
      "transfer_announcements" = ‖_{i<2k·R} (Enc(K1_i)(48) ‖ Enc(K2_i)(33)),
      "on_curve_first" = ‖ of the 9 points (33 each),
      "sm_first_messages" = ‖_{i<128} ‖_{k≤14} Enc(pt_{i,k})(33) ) )
```

#### 4.3.4 Transfer challenges
`c_i = OS2IP( SHA-256( Transcript("DEVBIND/0.3/transfer-challenge"; "M" = M′, "i" = I2OSP(i,2)) )[0 .. b_c/8] )`

#### 4.3.5 SM bits and PA challenges
```
out = SHAKE-256( Transcript("DEVBIND/0.3/sm-bits"; "M" = M′), 16 bytes );   b_i = (out[⌊i/8⌋] >> (i mod 8)) & 1
draft00-shared-bit: e_i = b_i
separate-pa: e_i = OS2IP(expand_message_xmd_SHA-256(Transcript("DEVBIND/0.3/pa-challenge"; "M" = M′, "round" = I2OSP(i,2)),
                         "DEVBIND/0.3/pa-challenge-h2f", 48)) mod p
```

#### 4.3.6 On-curve challenge
`e_oc = OS2IP(expand_message_xmd_SHA-256(Transcript("DEVBIND/0.3/on-curve-challenge"; "M" = M′), "DEVBIND/0.3/on-curve-challenge-h2f", 48)) mod p`

#### 4.3.7 Fold
`C_x = Σ_{i<k} 2^(b_x·i)·T_i`, `C_y = Σ_{i<k} 2^(b_x·i)·T_{k+i}`. The weights are computed mod p.

### 4.4 On-curve proof (`oncurve.rs`; decision D5 (b))

**Statement.** (C_x, C_y) = fold(T) opens to (x, y) with y² = x³ − 3x + b (mod p). Tom-256's scalar field is F_p, so this relation is native.

**Prepare.**
- r2, r3, r4 ← Z_p.
- C2 = x²·GT + r2·HT, C3 = x³·GT + r3·HT, C4 = y²·GT + r4·HT.
- Witness, in this order: w = (x, ρ_x, y, ρ_y, σ1 = r2 − x·ρ_x, σ2 = r3 − x·r2, σ3 = r4 − y·ρ_y, τ = r4 − r3 + 3ρ_x).
- Masks a_0..a_7 ← Z_p.
- First message (9 points, in this order):
```
C2, C3, C4,
A1 = a_0·GT + a_1·HT,      A2 = a_2·GT + a_3·HT,      A3 = a_0·C_x + a_4·HT,
A4 = a_0·C2 + a_5·HT,      A5 = a_2·C_y + a_6·HT,     A6 = a_7·HT
```

**Respond.** z_i = a_i + e_oc·w_i (mod p), 8 values.

**Verify.** With L = C4 − C3 + 3·C_x − b·GT, accept iff:
```
z_0 GT + z_1 HT = A1 + e C_x          z_2 GT + z_3 HT = A2 + e C_y
z_0 C_x + z_4 HT = A3 + e C2          z_0 C2 + z_5 HT = A4 + e C3
z_2 C_y + z_6 HT = A5 + e C4          z_7 HT = A6 + e L
```

**Special soundness (sketch).**
- Two accepting transcripts with e ≠ e′ give w.
- Then C2, C3 and C4 open to x², x³ and y².
- L = (y² − x³ + 3x − b)·GT + τ·HT = τ·HT, so by commitment binding (unknown log_GT HT; requirement in §3.3) y² = x³ − 3x + b.

**Size.** 9 × 33 + 8 × 32 = 553 bytes. Identity points are accepted in the encoding.

## 5. Implementation architecture

Rust only (`devbind-rust`, edition 2021, rust-version ≥ 1.85, `#![forbid(unsafe_code)]`).

| Module | Role |
|---|---|
| `params.rs`, `config.rs` | constants, DSTs; limb sizes and `TransferConfig` with validation |
| `tom.rs`, `p256x.rs` | Tom-256 (arkworks 0.5), P-256 helpers and limb splitting |
| `pa.rs`, `sm.rs` | point addition and scalar multiplication proofs |
| `oncurve.rs` | on-curve proof (§4.4) |
| `transfer.rs` | parametric cross-group transfer (`Bounds`) |
| `issuer.rs` | issuer params with limb size, header, attestation, issuance, credential validation |
| `presentation.rs` | request, ph, transcripts, prepare / present / parse / verify, `VerifierSession`, `segments`, `presentation_size`; `insecure_test_controls` behind a feature |
| `device.rs`, `slots.rs` | `RawSigner`, software device; in-memory slot pool |
| `batch.rs` | batch verification of the linear group equations (0.3.1) |
| `comb.rs` | fixed-base tables for GT, HT, Q′, Y0, Y1 (0.3.1) |
| `par.rs` | optional parallelism: `Parallelism::{Off, Max, Threads(n)}` (0.3.1) |
| `bin/devbind-verify.rs`, `bin/devbind-bench.rs` | verifier process (bounded read, no panics); benchmark (`--limb-bits`) |

**API:**
```rust
let cred  = issuer.issue(&device_pub, &attestation, &attributes)?;
let req   = Request::new(&issuer_params, audience, &disclosed, profile, &mut rng);   // recommended transfer config
let slot  = prepare_slot_for(&cred, &req, spare_sets, &mut rng, stats)?;           // or prepare_slot(…, cfg, …)
let bytes = present(slot, &cred, &req, &signer, None, &mut rng, stats)?;
verify(&issuer_params, &req, &bytes, stats)?;                                       // Ok = accept (batch path)
// 0.3.1: prepare_slot_with / prepare_slot_for_with / verify_with take a Parallelism setting;
// verify_individual checks every equation on its own (reference path).
```

**Dependencies** (pinned by `Cargo.lock`):
- `bbs-cd-reference` (path);
- `bls12_381 =0.9.0`;
- `p256 0.13`;
- `ark-ff`, `ark-ec`, `ark-std` 0.5;
- `num-bigint 0.4`, `sha2`, `sha3`, `rand_core 0.6`, `rand_chacha 0.3`, `serde_json`;
- `rayon 1` (optional, feature `parallel`).

**Features:**
- `prepared-bbs`: needs the patched crate copy.
- `insecure-test-controls`: test-only; enabled by the self dev-dependency.
- `parallel` (0.3.1): compiles in `rayon`; without it every `Parallelism` setting runs sequentially.

**Secret handling.** All arithmetic is variable-time, there is no zeroization, and slots are kept in memory only. The 0.3.1 fixed-base tables are indexed by secret scalar digits, which is a cache-timing channel. Prover states (on-curve, SM, PA) are single-use: `respond` consumes them (L-3).

## 6. Tests (67 + 1 doctest, `cargo test --release`)

At the 0.3 freeze there were 48 tests; 0.3.1 adds 19 and a `compile_fail` doctest. All pass in the default build, with `--features parallel`, and with `--features prepared-bbs` against the patched crate copy.

| File | Tests |
|---|---|
| `arith.rs` (8) | moduli, Tom order and generators; encodings and rejections; **limb splitting and fold for b_x = 64, 96, 128**; scalar canonicity and low-s; transcript injectivity; reader limits; raw-signing transformation |
| `sm_transfer.rs` (10) | SM honest rounds, extraction and tampering; F-1 standalone; exceptional additions; ETSI roles; **transfer configuration validation**; transfer honest, extraction, ranges and mismatch for three configurations; abort rates (b_f = 8 and 16); **on-curve proof: honest, extraction, tampering, F-1 off-curve pair rejected** |
| `presentation.rs` (13) | honest (both profiles); independent verifier process; request/params round-trip; replacements (Q′, nonce, audience, issuer, disclosed value, signature, high-s); swaps of T_j and D_j; splicing (incl. the on-curve section); flipping every section; parse ranges (incl. z below range, on-curve z = p, on-curve point x ≥ pT); holder and issuer checks; policy mismatch and replay; **F-1 composition (rejected at the transfer; on-curve proof fails on its own)**; no stable fields |
| `config_p2.rs` (5) | **all named configurations end to end** (96/R1, 128/R2, 64/R1 separate-pa, 96/R2); limb size in issuer params and header; **transfer configuration is verifier-controlled** (weaker, different and incompatible configurations rejected); **P2 binding** (BBS proof of another session, other nonce, other audience rejected); on-curve section checked |
| `freshness_state.rs` (7) | control vs. candidate for both freshness attacks; fixed-point search; device loss; concurrency and slot pool; cloned-slot exposure; device-log linking |
| `review_fixes.rs` (7) | RV-1 attribute limits and size refusal before signing; exact size; RV-2 wrong or faulty device; RV-4/RV-5 CLI input handling; L-1 `segments` on malformed input; L-2 bounded and expiring `VerifierSession` |
| `batch_verify.rs` (6) | batch and individual verifiers agree on honest presentations (five configurations); single-equation tampering of every SM, on-curve and transfer response rejected with the same reason; compensating pairs; RNG independence |
| `batch_unit.rs` (3) | batch accumulator against the individual checks (single perturbations and compensating pairs); MSM against naive sums |
| `comb.rs` (5) | fixed-base tables and wNAF against plain multiplication on edge scalars; Y0/Y1 tables keyed by generators |
| `parallel.rs` (3) | settings and chunking; identical slot and presentation for every setting; same verdict and reason for every setting |
| doctest | L-3: answering a prover state twice does not compile |

Not covered:
- frozen 0.3 test vectors (not generated; Peter's decision at the freeze);
- BBS core fixtures (covered by `bbs_cd`'s own tests);
- toy-soundness experiments;
- online operation counters.

## 7. Benchmarks

The harness is `cargo run --release --bin devbind-bench -- [--quick | --n N] [--profile …] [--limb-bits 64|96|128] [--spare-sets K] [--out PATH]`. Its JSON records the limb size, the transfer configuration and "P2".

**Measured on 0.3**: Peter's MacBook Pro (Apple silicon, macOS, aarch64), release build, single thread, software device, `--n 50`, default configuration (96-bit limbs, R = 1, b_c = 128, b_f = 16), n_attr = 4, one disclosed attribute. The file is `devbind-rust/bench/results/bench-rust-1792095056.json`. Its `implementation` field still reads "0.2.0" because of a stale label in the harness, fixed before the freeze; the run is of the 0.3 code, as its `limb_bits`, `transfer` and `presentation_header` fields show.

| Metric (p50) | draft00-shared-bit | separate-pa |
|---|---|---|
| Offline prepare per slot | 288.2 ms | 294.7 ms |
| — linkage | 17.0 ms | 17.4 ms |
| — key proof (128 SM rounds + on-curve) | 266.1 ms | 272.1 ms |
| Online total (software device) | 21.7 ms | 22.4 ms |
| — BBS ProofGen (before the device call; could run in parallel) | 20.1 ms | 20.5 ms |
| — device sign | 0.09 ms | 0.09 ms |
| — after signing (raw-signature check, responses, encoding) | 0.55 ms | 0.74 ms |
| Verify | 255.5 ms | 299.9 ms |
| — parse / ECDSA / BBS / transfer / on-curve / SM (means) | 1.7 / 0.25 / 15.1 / 4.2 / 1.5 / 233.1 ms | 1.7 / 0.26 / 15.4 / 4.3 / 1.5 / 277.4 ms |
| Cold prepare + present | 315.6 ms | 321.7 ms |
| Presentation | 123,605 B | 123,598 B |
| Transfer attempts | 1 in all 50 runs | 1 in all 50 runs |

Baselines from the same run: ETSI Sign 6.4 ms; `PrecomputeCommitment` (6 limbs) 2.0 ms; `ProofGen` (COMMIT 6) 19.6 ms; `ProofVerify` 14.8 ms; device raw sign 0.09 ms; ECDSA verify 0.15 ms.

**Compared with the 0.2 P1 code (`--quick`):**
- prepare grows from 282 to 288 ms;
- online grows from 17 to 22 ms (ProofGen with 6 instead of 4 commitments);
- verify grows from 250 to 256 ms (on-curve proof 1.5 ms, transfer 2.7 → 4.2 ms, BBS 12 → 15 ms);
- size grows from 122.4 to 123.6 KB.

The 128-bit/R = 2 configuration was not benchmarked. Without the BBS proof, the online work after the request is about 1.6 ms. Under P2 the 20 ms ProofGen can run in parallel with a (slower) hardware signature.

These are the freeze measurements. Measurements after the 0.3.1 optimizations are summarised in §0.

## 8. References and pinned sources

- **ETSI profile "BBS with Committed Disclosures" v0.7** (`bbs-committed-disclosures-rust-v0.7/spec/etsi-bbs-committed-disclosures-v0.7.md`) and its reference crate `bbs_cd`. Sections used: §3.2 (api_id, interfaces), §3.2.2 (commitment generators and roles), §3.3.2.2 (schema in header), §3.3.4 (nonzero scalars, retry), §3.5.3–3.5.4 (ProofGen/ProofVerify), §3.7.4 (challenge), §4.1.3 (PrecomputeCommitment), §4.1.5 (presentation_context), §4.2.4.4 (proof octets).
- **HPI ecdsa_pops @ `e05148765142b237f369a4336a0898c7f29b78b2`**: CDLS/t256 constants; `ec_point_add_protocol_opt.rs` (PA Opt 1–3); `scalar_mul_wc_protocol.rs` (SM); `dleq_rok.rs` / `bls_to_tom.rs` (transfer parameters). The licence notice is in `devbind-rust/docs/LICENSE.hpi-ecdsa_pops`.
- **draft-cllz-cfrg-ecdsa-pop-00**, §§4–10 (shared-bit SM).
- **Chase–Orrù–Perrin–Zaverucha, ePrint 2022/1593** (cross-group equality with aborts).
- **CFRG pairing-friendly curves, draft-irtf-cfrg-pairing-friendly-curves-11**, §4.2.1 and §5: BLS12-381 security ≈ 126 bits [GMT19]; basis of the 0.3 security target.
- **RustCrypto `p256` 0.13** (ECDSA prehash API), **arkworks 0.5**, **zkcrypto `bls12_381` 0.9.0**.
- The 0.1 sources (BBS editor's copies, Blind BBS 56b032e, BBS fixtures 1329e85) are listed in `devbind-rust/docs/SOURCES.lock`. They are no longer used by the code.

## 9. Implementation reference map (what was actually reused)

| Component | Source | How |
|---|---|---|
| Tom-256 constants, GT, HT | HPI CDLS/t256 | copied verbatim (Appendix A); test checks prime order p and on-curve |
| PA equations (Opt 1–3) | HPI `ec_point_add_protocol_opt.rs` | algebra ported; witness/announcement order of §4.1.2. The optimized omission of the y-opening is used only inside SM (F-1 restriction) |
| SM structure, ω exclusion | HPI `scalar_mul_wc_protocol.rs`, draft-00 | base Q′, result (C_x, C_y), scalar c; batched Fiat–Shamir over 128 rounds |
| Transfer | HPI `dleq_rok.rs`, ePrint 2022/1593 | b_x, b_c, b_f and range [2²⁴⁰, 2²⁴⁸); announcements sent rather than the challenge (needed because M hashes them); ETSI generator roles |
| BBS + committed disclosure | `bbs_cd` (ETSI v0.7) | used through its public API: `KeyGen`, `SkToPk`, `Sign`, `Verify`, `PrecomputeCommitment`, `ProofGen`, `ProofVerify`, `commitment_generators`, `messages_to_scalars`, `octets_to_proof`, `decode_G1`, `expand_message` |
| On-curve proof | — | new in 0.3: standard Pedersen multiplication proofs (§4.4) |
| Dock crypto | — | not used; its parametric repetition count informed D6 |

## 10. Specification and analysis status

### 10.1 Wire format (`present`, `parse`)

Every dimension is taken from `IssuerParams` (2k) and the `Request` (|I|, R, b_c, b_f), never from the presentation.
```
"DBP\x03" ‖ I2OSP(len(profile),1) ‖ profile ‖ nh(32) ‖ Enc(Q′)(33) ‖ I2OSP(r,32) ‖ I2OSP(s′,32)
‖ I2OSP(|I|,2) ‖ ‖_{i∈I} ( I2OSP(len(attr_i),4) ‖ attr_i )
‖ I2OSP(len(P_bbs),4) ‖ P_bbs                                                          (§4.2.3)
‖ ‖_{j<2k} Enc(T_j)(33)
‖ ‖_{i<2k·R} ( Enc(K1_i)(48) ‖ Enc(K2_i)(33) ‖ I2OSP(z_i, z_bytes) ‖ I2OSP(s1_i,32) ‖ I2OSP(s2_i,32) )
‖ C2 ‖ C3 ‖ C4 ‖ A1 ‖ … ‖ A6 (9 × 33) ‖ ‖_{i<8} I2OSP(z_i,32)                      (on-curve, §4.4)
‖ I2OSP(128,2)
‖ ‖_{i<128} ( ‖_{k≤14} Enc(pt_{i,k})(33) ‖ I2OSP(α_i,32) ‖ I2OSP(ρ1_i,32) ‖ I2OSP(ρ2_i,32) ‖ ‖_{k≤12} I2OSP(z_{i,k},32) )
```

**Size** (`presentation_size`):
```
size = 4 + 1 + |profile| + 32 + 33 + 64 + 2 + Σ_i (4 + |attr_i|) + 4 + |P_bbs|
       + 33·2k + (145 + z_bytes)·2k·R + 553 + 2 + 120,576
|P_bbs| = 8 + 3·48 + (3 + U)·32 + 2k·(48 + 32) + 32,   U = L − |I|
```

Measured with n_attr = 4, one 16-byte disclosed attribute:

| Configuration | BBS proof | Transfer | Total (shared-bit) |
|---|---|---|---|
| b_x 96, R 1, b_c 128, b_f 16 (default) | 1,048 | 1,050 | **123,605** |
| b_x 128, R 2, b_c 112, b_f 8 | 824 | 1,408 | 123,673 |
| b_x 64, R 1, b_c 128, b_f 16 | 1,272 | 1,368 | 124,213 |

`separate-pa` is 7 bytes shorter (the profile name).

### 10.2 Verifier acceptance predicate (`verify`)

The verifier holds `IssuerParams` and its own `Request`. It MUST recompute ctx and ph from the request. It accepts iff all of the following hold, in this order:

1. **Request.** `request.validate(IssuerParams)`, including the transfer configuration for b_x (§3.5.3).
2. **Parse.** Size ≤ 262,144 bytes and exact consumption, with:
   - magic `DBP\x03`; profile = request.profile, a known profile;
   - Q′ a valid non-identity P-256 point; 1 ≤ r < n; 1 ≤ s′ ≤ (n−1)/2;
   - disclosed count = |I|, each attribute ≤ 4,096 bytes;
   - P_bbs ≤ 8,192 bytes and accepted by `octets_to_proof`, with N = 2k;
   - 2k valid Tom encodings for T_j;
   - 2k·R transfer entries: K1 a valid G1 point (identity allowed), K2 a valid Tom point (identity allowed), 2^(b_x+b_c) ≤ z < 2^z_bits, s1 < ℓ, s2 < p;
   - 9 valid Tom points and 8 values < p for the on-curve proof;
   - round count = 128;
   - per round, 462 first-message bytes (decoded in step 9), 1 ≤ α < n, and ρ1, ρ2, z_k < p.
3. **h.** Disclosed scalars m_i = hash_to_scalar(attr_i, api_id ‖ "MAP_MSG_TO_SCALAR_AS_HASH_"). Compute stmt with D_j from P_bbs, then hin and h. Reject if h = 0.
4. **ECDSA.** Verify (r, s′) under Q′ on I2OSP(h, 32), with no hashing.
5. **BBS.** `ProofVerify(pk, P_bbs, header, ph = request.presentation_header(), disclosed OCTETS, D_j, types, disclosures)` must pass.
6. **Transfer.** Compute M′ (§4.3.3). For every entry i: transfer verification (§4.2.4) with c_i, D_⌊i/R⌋ and T_⌊i/R⌋.
7. **Fold.** (C_x, C_y) = fold(T) (§4.3.7).
8. **On-curve.** On-curve verification (§4.4) with e_oc.
9. **SM.** Decode the 1,792 SM points (identity allowed except U1). For i = 0..127, SM round verification with b_i and e_i must pass.

Checks MAY be reordered only if the accept/reject outcome is unchanged. A verifier MAY check the linear group equations of steps 6, 8 and 9 in a batch: a random linear combination with independent weights of at least 128 bits, drawn after all inputs are fixed, accepts a false equation with probability at most 2⁻¹²⁸ per batch. The per-round non-linear checks (α ≠ 0, U1 ≠ O, W = α·Q′ and its coordinates) stay individual.

*0.3.1:* the default `verify` implements this with one Tom-256 batch and one G1 batch, so a false presentation passes with probability at most 2⁻¹²⁷ per verification. On a failing batch the individual checks run to name the failing equation. The only reason that can differ from the individual path is that an undecodable SM point is reported before a failing transfer or on-curve equation. `verify_individual` is the reference path. Reason strings are `request: …` / `transfer config: …`, `decode: …`, `h == 0`, `ecdsa`, `bbs: …`, `transfer[j.t]`, `on-curve` and `sm[i]`.

### 10.3 State and concurrency

- **Slot contents.** A slot holds a, c, Q′, the openings s_j and ρ_j, the transfer secrets, the on-curve witness and masks, every SM mask and, in shared-bit, both response branches. It is secret holder state, as sensitive as the credential.
- **In-memory pool.** `SlotPool::take` removes the slot under a mutex, and `present` consumes it by value. Any failure after `take` loses the slot (burn-on-reserve).
- **No persistence.** There is no on-disk store, so the crash and backup-restore behaviour of the original report is not applicable.
- **Transfer aborts.** These are handled inside one presentation (§3.5.5).
- **Cloning.** A cloned state (possible to a malicious holder, e.g. via memory) that answers two requests reveals c (reused SM first messages), hence Q, and the limbs and openings (a reused transfer set), and repeats Q′, D_j and T_j. The other hidden attributes are **not** revealed, because ETSI `ProofGen` draws fresh masks on every call (corrected in 0.3.1; 0.3 said "the hidden messages"). This is a holder-privacy failure. Soundness and freshness do not rely on single use.
- **Concurrency.** Independent slots can be presented concurrently through one device; `SoftwareDevice` serialises its own calls.
- **Verifier state.** A verifier SHOULD bound the number of outstanding requests and SHOULD let them expire (`VerifierSession`: at most 10,000, oldest dropped; 300 s lifetime). An expired nonce is rejected before verification.
- **Enforcement.** The verifier enforces only §10.2 and nonce single use. Everything else is honest-wallet behaviour.

### 10.4 Security claims: status for 0.3

The 0.3 analysis is in `analysis-0.3/`: `SECURITY_MODEL.md`, `SOUNDNESS_ANALYSIS.md`, `SECURITY_ANALYSIS.md` and the ledger `SECURITY_CLAIMS.md` (claims C1′–C33). It was reviewed by independent model-based reviewers and an external reviewer, but **not** by an independent cryptographer. The review of ePrint 2025/1981 is `analysis-0.3/O-S3_VISION_2025-1981.md`.

| Status | Claims |
|---|---|
| Proved on paper (self-reviewed) | completeness; the signature transformation E-1; PA and SM extraction; the on-curve proof (special soundness, HVZK); SMOC-1, which closes F-1 for the composition; the parametric transfer lemmas; KR-a; retry privacy |
| Conditional | composed knowledge soundness and credential/key binding (Fiat–Shamir O-K2, joint extraction of the two proofs O-K3, the ETSI proof O-S3); fresh device participation (KR-ECDSA, O-F1); zero knowledge and unlinkability (full hybrid O-P1; the BBS proof is zero-knowledge only in Tessaro–Zhu's L-HVZK sense); session binding |
| Open | the ETSI committed-disclosure proof system itself (O-S3). ePrint 2025/1981 is a vision paper without theorems or proofs, so it cannot close O-S3. ETSI v0.7's proof matches its Fig. 6 up to naming. |
| Refuted (reproducible) | standalone SM soundness (F-1); freshness of the "Q′ not hashed" control; privacy under slot cloning and under a colluding device; replay against the stateless predicate (by design: verifier nonce state) |
| Not claimed | constant-time behaviour; zero online curve operations |

**Security level.** About 125–126 bits for the default configuration and about 126 bits (BLS12-381-limited) for 128-bit limbs with R = 2, before the Fiat–Shamir query factor. The default's composite knowledge error is 7·2⁻¹²⁸ ≈ 2⁻¹²⁵·² (finding N-1). A verifier can request (R = 2, b_c = 72, b_f = 16) with 96-bit limbs to reach about 2⁻¹²⁸ (+966 bytes).

**Generator HT.** Binding of the Tom-256 commitments is stated as the requirement of §3.3 (G-1).

**Issues found in the ETSI comparison** concern the paper's figures, not ETSI v0.7 or this implementation: the paper's Fig. 6 omits the Ā ≠ O check; its scalar-multiplication soundness argument has the F-1 gap; its limb transfers are hashed separately and without the verifier context.

### 10.5 Discrepancies with the original report and their resolution

| # | Original report | 0.3 implementation | Resolution |
|---|---|---|---|
| R-1 | BBS draft-10 + Modular BBS scalars + Blind BBS committed disclosure | ETSI CD v0.7 (`bbs_cd`) | Peter's decision |
| R-2 | Blind-BBS commitment roles | ETSI roles D = m·Y0 + s·Y1 | Transfer adapted; tested |
| R-3 | Profile `reference-separate-pa` (HPI transcript) | `separate-pa` with this protocol's transcript | not byte-compatible with HPI |
| R-4 | HPI transfer sends the challenge | sends announcements | M′ hashes them before the challenges exist |
| R-5 | Offline API must preserve commitments and masks | commitments preserved via `precomputed_rands` and checked; BBS masks are fresh online (ETSI) | under P2 the BBS proof is independent of h, so the masks bind nothing else |
| R-6 | Composed transcript unspecified | **P2**: two Fiat–Shamir proofs sharing D_j and the nonce | D1; analysis item A3 |
| R-7 | "Transfer rejection restarts with fresh masks" | the whole transfer set is replaced; the BBS proof, signature and other first messages are reused | D-11 |
| R-8 | Commitments may be the identity | ETSI rejects identity D_j; Tom points may be identity except U1 | negligible completeness loss |
| R-9 | PA nonzero check only | plus the on-curve proof (§4.4) | F-1 (D5 b) |
| R-10 | Blind issuance may need proofs of key validity | trusted non-blind issuer (D-1) | D-1 |
| R-11 | Context binds disclosed values | ctx binds the indexes; the values are bound in stmt and in the BBS proof | equivalent |
| R-12 | Python reference + native backend | Rust only | Peter's decision |
| R-13 | Real hardware adapter | software device only | limitation |
| R-14 | Persistent slot store with crash/backup tests | in-memory pool | out of scope |
| R-15 | Frozen vectors; p50/p95/p99 | vectors at the freeze; no p99 | open |
| R-16 | Attestation unspecified | simulated P-256 ECDSA attestation | D-1 |
| R-17 | 128-bit limbs, 112-bit transfer ("do not call it 128-bit") | parametric; default 96-bit limbs with b_c = 128; target = the BLS12-381 ceiling | D0, D6 |

**Security-review findings (15 Oct 2026):**
- **RV-1 to RV-5:** fixed (attribute limits and size check, device and raw-signature checks, test-only control, CLI input handling).
- **RV-6 (documentation):** this report.
- **RV-7 (F-1):** on-curve proof added.

**Analysis findings (15–16 Oct 2026; 0.3.1):**
- **L-1 to L-3:** fixed (`segments` panic, unbounded `VerifierSession`, reusable prover states).
- **N-1:** recorded (§10.4); no change to the default.
- **Clone leakage:** §10.3 corrected.

### 10.6 Open obligations and next steps

0.3.1 is the final version of this prototype. Done since the freeze: the 0.3 analysis, the ePrint 2025/1981 review, the L-fixes and the implementation-only optimizations (§0).

**Left to an independent cryptographic review** (the analysis provides the setting and sketches):
- O-S3: knowledge soundness and zero knowledge of the ETSI committed-disclosure proof;
- O-K3 and O-K2: joint extraction of the two Fiat–Shamir proofs, and a Fiat–Shamir theorem for the coordinate-wise structure;
- O-F1: KR-ECDSA, the assumption fresh device participation rests on. If it cannot be established, the device-binding module of ePrint 2025/1981 (ordinary hashed ECDSA on the nonce, verified in zero knowledge) is a fallback design;
- O-P1: the full privacy hybrid.

**Engineering:** confirm raw-digest signing with Secure Enclave and StrongBox keys on devices (§3.5.4); optionally run ETSI `ProofGen` in parallel with device signing.

**Candidates for a future protocol version:** HT from a verifiable procedure (§3.3); allowing b_c up to 136 so that one repetition reaches about 2⁻¹²⁸ (N-1).

**Independent cryptographic review is required before any deployment.**

---

## Appendix A. Constants

```
p  (P-256 base field, Tom order) = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
n  (P-256 order)                 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
ℓ  (BLS12-381 r)                 = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
pT (Tom base field)              = 115792089210356248762697446949407573530594504085698471288169790229257723883799
                                 = 0xffffffff0000000100000000000000017e72b42b30e7317793135661b1c4b117
Tom-256:  y² = x³ + a x + b over F_pT,  a = pT − 3,
          b  = 81531206846337786915455327229510804132577517753388365729879493166393691077718
          GT = (3, 40902200210088653215032584946694356296222563095503428277299570638400093548589)
          HT = (5, 28281484859698624956664858566852274012236038028101624500031073655422126514829)
               (prototype value from HPI ecdsa_pops, no documented derivation; MUST NOT be used outside testing, §3.3)
b_P256   = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b  (P-256 curve coefficient, used by the on-curve proof)
api_id   = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_S2S_"
BBS challenge DST = api_id ‖ "COM_DIS_ETSI_PROOF_V1_H2S_"
OCTETS map DST    = api_id ‖ "MAP_MSG_TO_SCALAR_AS_HASH_"
(Y0, Y1) = create_generators(2, "COM_DIS_" ‖ api_id)
```

## Appendix B. Reproduce and identify

```bash
cd devbind-rust
cargo test --release                                       # 67 tests + 1 doctest
cargo test --release --features parallel                   # same, parallel settings active
cargo run --release --bin devbind-bench -- --n 50          # default configuration
cargo run --release --bin devbind-bench -- --n 50 --limb-bits 128
cargo run --release --features parallel --bin devbind-bench -- --n 50 --threads max
```
Source-tree SHA-256 (sorted `shasum -a 256` of `src/`, `tests/`, `Cargo.toml`, `Cargo.lock`, then hashed):
- 0.3 (git tag `devbind-0.3-freeze`): `d1481a264b29de5d08bb1ca804dbce2c8a4c25cfccd6dcd1b094b16a66e18abd`;
- 0.3.1 (crate 0.3.1): `859d45e872483a261c63c6efcc7285e5d3ec9e8b8ab3d06bdfc066a5fff3cd39`.
