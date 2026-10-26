# `ecdsa-pop/0.1`: proof of possession of a committed P-256 device key

Plugin of the BBS committed-disclosure framework (`docs/ENVELOPE.md`). Crate:
`crates/cd-ecdsa-pop`. Status: research specification, version 0.1. There are no test
vectors yet.

The credential holds a P-256 public key Q of a secure element as a device-key attribute
(§1). The verifier asks for an `ecdsa-pop` proof on that attribute. The holder
commits to the key's limbs in the BBS presentation, has the device sign a value bound to
the request, and proves that the committed key produced that signature. Q itself is never
revealed.

**Modes:**

| Mode | Status | Device call | Assumption | Signature-dependent work |
|---|---|---|---|---|
| `hashed` (1) | default | ECDSA-P256-SHA256 on a message | ECDSA unforgeability (EUF-CMA) | SM proof, after signing |
| `raw` (2) | feature `raw-mode` | raw signature on a 32-byte representative c·h | KR-ECDSA | none; the SM proof is prepared offline |

The raw mode is the DEVBIND 0.3 construction (`docs/reference/devbind-0.3.1-report.md`)
moved into the envelope. The hashed mode is its "H-mode" (`docs/reference/devbind-hashed-mode-exp1.md`).
Wire formats and transcripts are new, so presentations are not compatible with DEVBIND 0.3.1.

## 1. Device-key attribute types

There are two types, one per mode. **A key is usable in exactly one mode** (review finding
H-2): the type fixes it, the issuer checks that the attestation states the same usage,
and the schema, and with it the type, is signed into every credential.

| Type | Permitted signing | Mode |
|---|---|---|
| `p256-point-xy.ecdsa-sha256` | ECDSA-P256-SHA256 only | hashed |
| `p256-point-xy.ecdsa-raw` | raw-representative ECDSA only | raw |

So the hashed-mode argument (ECDSA unforgeability) never has to account for a raw-signing
interface on the same key, and the raw-mode argument (KR-ECDSA) never for a hashing one.
In a deployment the secure element enforces the usage (for example, the digest list of
an Android KeyMint key: SHA-256 only, or NONE only) and the key attestation reports it.

Both types share the `p256-point-xy` layout:

- **Layout.** A `Scalars` attribute with `bits` = b ∈ {64, 96, 128} and `count` = 2k,
  where k = ⌈256/b⌉.
- **Messages.** In order: x₀ … x_{k−1}, y₀ … y_{k−1}, with x = Σ xᵢ·2^(b·i) (little-endian
  limbs, each < 2^b). The same holds for y.
- **Issuance** (`P256KeyHandler`):
  - Input: SEC1-compressed Q (33 bytes) ‖ attestation.
  - The issuer checks that Q is a canonical, on-curve, non-identity point.
  - It checks that an accepted manufacturer attested the key, with the usage of the
    attribute's type.
  - It computes the limbs itself.

  The soundness argument relies on these checks (DEVBIND decision D-1). `Manufacturer`
  is a software simulation of key attestation; it signs DST ‖ policy ‖ usage ‖ Q.
  `SoftwareDevice` refuses the signing interface its key was not created for.

## 2. Request parameters

The parameters are the `PluginRequest::params` bytes, bound into ctx:

```
u8 mode (1 hashed, 2 raw) ‖ u8-len profile ‖ R (u8) ‖ b_c (u16) ‖ b_f (u16)
```

- **profile:** `draft00-shared-bit` (the PA challenge of round i is the SM bit) or
  `separate-pa` (the PA challenges are full field elements).
- **transfer configuration (R, b_c, b_f):** must satisfy
  - b + b_c + b_f ≤ 254;
  - R·b_c ≥ 128;
  - b_c ∈ [64, 128] and a multiple of 8;
  - b_f ∈ [8, 32];
  - R ∈ [1, 4].

  Recommended: (1, 128, 16) for b ≤ 96, and (2, 112, 8) for b = 128.
- **The verifier's `check_request` rejects** non-canonical parameters, an unknown
  profile, a configuration that breaks the rules above, an attribute of another type or
  layout, **a mode the attribute's key type does not permit**, and raw mode unless the
  verifier allows it. The prover's `prepare` applies the same checks.

## 3. Building blocks

All are unchanged from DEVBIND 0.3; the sections refer to `docs/reference/devbind-0.3.1-report.md`.

| Building block | Section | Code |
|---|---|---|
| Tom-256 group and generators GT, HT | §3.1, §3.3 | `cd_tom256::tom` |
| Limb commitments T_j = m_j·GT + ρ_j·HT and the fold C_Q = (Σ 2^(b·i)·T_i, Σ 2^(b·i)·T_{k+i}) | §4.2, §4.3.7 | `transfer::fold` |
| Transfer: equality of the integer committed by the ETSI D_j = m_j·Y0 + s_j·Y1 and by T_j, R repetitions per limb | §4.2.4 | `cd_tom256::transfer` |
| On-curve proof for the pair committed by C_Q | §4.4 | `cd_tom256::oncurve` |
| SM proof: 128 rounds of "the committed point is ω·B" for a public base B, each with one point-addition (PA) proof | §4.1 | `cd_tom256::sm`, `cd_tom256::pa` |

Y0, Y1 are the ETSI commitment generators. Constants are in Appendix A.

## 4. Binding

Let `env`, `nonce`, `plugin_index` come from the envelope (ENVELOPE.md §5), `params` be
the request bytes and `attr` the attribute name. Tr is the length-prefixed transcript of
ENVELOPE.md §1.

```
pstmt = Tr("ECDSA-POP/0.1/statement";
           "plugin" = "ecdsa-pop/0.1", "plugin_index" = u16, "attribute" = attr,
           "params" = params, "env" = env, ["Qprime" = Q′ (raw only)], "T" = T_0 ‖ … ‖ T_{2k−1})
```

Because `env` contains ctx and every credential's D_j, a proof is bound to:
- the request;
- the BBS commitments;
- its own position and parameters;
- its own limb commitments.

## 5. Hashed mode

**Offline (`hashed::prepare`):**
- ρ_j, T_j;
- the transfer sets: a primary set plus spares, each with 2k·R prepared entries;
- C_Q and its openings;
- the on-curve proof's first message.

**Prove:**
1. Check that the slot matches `params` and the D_j, and that the signer's public key is Q.
2. Pick a fresh nh (32 bytes) and set m = Tr("ECDSA-POP/0.1/device-message"; "statement" = pstmt, "nv" = nonce, "nh" = nh).
3. The device returns (r, s) = ECDSA-P256-SHA256(m). Let h = SHA-256(m) mod n.
4. Holder check: K = s⁻¹(h·G + r·Q) ≠ O and x(K) mod n = r.
5. Set z = s/r, Hpt = (h/r)·G and W = Q + Hpt, so W = z·K.
   - **Exceptional** (retry with a fresh nh): h = 0, W = O, Hpt = O, or x(Hpt) = x(Q).
6. Commit C_W = commit(W; r_W).
7. Link proof: PA(Q + Hpt = W) over (C_Q, commit(Hpt; 0, 0), C_W). Hpt must stay public
   with zero blinding; see §9 on the restricted PA.
8. SM proof: 128 rounds of W = z·K (base K, result C_W).
9. Compute M′ = Tr("ECDSA-POP/0.1/hashed-binding-challenge";
   - "message_digest" = SHA-256(m),
   - "K",
   - "transfer_announcements" (K1 ‖ K2 of the chosen set),
   - "on_curve_first",
   - "link_first" (C_W and the link PA announcements),
   - "sm_first_messages")
   → SHA-256.
10. Derive the challenges from M′ (§7). If a transfer response falls outside its
    interval, discard the whole set and use the next spare (each entry aborts with
    probability 2^−b_f).

**Proof encoding:**
```
"EPH" 0x01 ‖ nh (32) ‖ K (33) ‖ T_j (2k × 33)
‖ transfer entries (2k·R × [K1 (48) ‖ K2 (33) ‖ z (⌈(b+b_c+b_f)/8⌉) ‖ s1 (32) ‖ s2 (32)])
‖ on-curve (9 × 33 ‖ 8 × 32) ‖ link (12 × 33 ‖ 12 × 32) ‖ u16 128 ‖ 128 × SM round (942)
```

**Verify:**
1. Parse strictly. Every count comes from the schema and `params`; every scalar is
   canonical; every point is valid. U1 ≠ O in the link section and in every SM round.
2. Recompute pstmt, m, h and r = x(K) mod n. Reject h = 0 or r = 0.
3. Set Hpt = (h/r)·G.
4. Check the link PA.
5. Check the transfer, on-curve and SM proofs. They are batched by default, and a
   failing batch is re-run per equation to name the failure.

**Output:** empty.

## 6. Raw mode

**Offline (`raw::prepare`):**
- everything in the hashed-mode offline step;
- a ≠ 0 and c = a⁻¹;
- Q′ = a·Q;
- 128 SM rounds proving Q = c·Q′ (base Q′, result C_Q).

**Prove:**
1. Check the slot and that the signer's public key is Q.
2. Set h_in = Tr("ECDSA-POP/0.1/raw-representative"; "statement" = pstmt (with Q′), "nv", "nh"),
   and h = SHA-256(h_in) mod n ≠ 0.
3. The device raw-signs rep = c·h (32 bytes, no hashing) and returns (r, s).
4. The holder checks the signature under Q.
5. Set s′ = a·s, normalized to low-s. Then (r, s′) is an ordinary ECDSA signature on h
   under Q′.
6. Compute M′ = Tr("ECDSA-POP/0.1/raw-binding-challenge"; SHA-256(h_in), r, s′, transfer
   announcements, on-curve first message, SM first messages) → SHA-256.

**Proof encoding:**
```
"EPR" 0x01 ‖ nh (32) ‖ Q′ (33) ‖ r (32) ‖ s′ (32) ‖ T_j ‖ transfer entries ‖ on-curve ‖ u16 128 ‖ SM rounds
```

**Verify:**
1. Parse strictly; s′ must be low-s.
2. Recompute pstmt (with Q′), h_in and h.
3. Check ECDSA(r, s′) on h under Q′.
4. Check the transfer, on-curve and SM proofs (base Q′, result C_Q).

**Why Q′ must be in the hash.** If pstmt omitted Q′, a holder with one retained raw
signature (r, s₀) on e₀ could choose a = h/e₀ after seeing the nonce. Even a zero-query
forgery would do. The tests reproduce both attacks against the insecure control (feature
`insecure-test-controls`) and show the real mode rejects them.

## 7. Challenges (both modes, from M′)

| Challenge | Derivation |
|---|---|
| Transfer, entry i (limb-major, R per limb) | first b_c/8 bytes of Tr("ECDSA-POP/0.1/transfer-challenge"; "M" = M′, "i" = u16) → SHA-256 |
| SM bits | SHAKE-256(Tr("ECDSA-POP/0.1/sm-bits"; M′)), 128 bits, LSB-first per byte |
| PA, round i, `draft00-shared-bit` | the SM bit of round i |
| PA, round i, `separate-pa` | hash_to_scalar(Tr("ECDSA-POP/0.1/pa-challenge"; M′, i), "…/pa-challenge-h2f") into Z_p (expand_message_xmd SHA-256, 48 bytes) |
| On-curve | hash_to_scalar(Tr("ECDSA-POP/0.1/on-curve-challenge"; M′), "…-h2f") |
| Link (hashed only) | hash_to_scalar(Tr("ECDSA-POP/0.1/link-challenge"; M′), "…-h2f") |

All challenges are derived after every first message is fixed, so a single SM round
can't be ground.

## 8. Sizes

Plugin proof sizes, in bytes, with the recommended transfer configuration (the envelope
and BBS proof come on top):

| Limb size | Raw | Hashed |
|---|---|---|
| 64 | 122,896 | 123,612 |
| 96 | 122,512 | 123,228 |
| 128 | 122,804 | 123,520 |

`common::segments` gives the exact layout; every honest proof has exactly that size.

## 9. Security notes

- **Assumptions:**
  - hashed mode: ECDSA unforgeability, plus the soundness of the sub-proofs;
  - raw mode: KR-ECDSA (key-randomized raw-representative unforgeability) in place of
    plain ECDSA unforgeability.
- **One key, one mode (H-2):** §1. Without it, a hashed-mode key also reachable through
  raw signing would hand the holder signatures on any 32-byte value, which the hashed
  argument does not cover. No attack is known (a hashed proof needs a signature on
  SHA-256 of a message containing the fresh nonce), but the argument needs the
  separation. `tests/key_usage.rs` covers it.
- **Issuer obligations:** §1. Independently of the issuer's check, the on-curve proof
  closes F-1, the gap where an off-curve committed pair passes the SM/PA proofs. In
  hashed mode the on-curve proof is load-bearing for the link too: the link PA proves
  the chord-formula sum W of the committed pair and Hpt, which need not be a curve point
  when the pair is not one (`tests/hashed_malicious.rs` shows an off-curve pair passing the link
  alone and failing the on-curve proof).
- **Extraction (hashed mode).** The on-curve proof gives Q on the curve; Hpt is public;
  U1 ≠ O in the link enforces x(Q) ≠ x(Hpt); so the link gives W = Q + Hpt, a curve
  point, and W ≠ O. The SM proof then gives z with z·K = W, and z ≠ 0 because W ≠ O.
  With s = z·r and r = x(K) mod n: s·K = h·G + r·Q, so (r, s) is an ECDSA-P256-SHA256
  signature by Q on m.
- **Restricted PA in the link (H-5).** The PA is HPI's optimized variant without the
  proof of knowledge of C2's opening (C2 commits to y of Q), which HPI restricts to the
  SM proof. It is sound in the link because Hpt is public with zero blinding: the
  verifier computes C3 and C4, so C2 = C4 − (C4 − C2) has a known opening. Independently,
  C2 is the y part of C_Q, opened through the transfers and the on-curve proof. Blinding
  Hpt, or reusing the PA with a hidden B and no other proof for C2, would reopen the gap;
  use HPI's standalone variant then. The module header of `cd_tom256::pa` states this.
- **Malleability.** (r, s) and (r, −s) are both valid signatures, with nonce points K and
  −K. A holder can present either (re-proving with z′ = −z). This is not a forgery: both
  need the device's signature on this request's message.
- **Commitment generators (G-1/H-3).** GT and HT are the Tom-256 points with x = 3 and
  x = 5, each with the smaller y root (HPI's values). Points fixed by such small public
  constants cannot have been chosen with a known log_GT(HT). `cd-tom256/tests/arith.rs`
  re-derives both.
- **Raw-mode deployment:** raw-digest signing is needed, and Android KeyMint lists "no
  digest" ECDSA as deprecated. The key must be dedicated to raw mode (§1), because a
  raw signer signs any 32-byte value.
- **Unlinkability:** each presentation reveals a fresh K (hashed) or Q′ and (r, s′)
  (raw).
  - With an honest secure element these are uniformly random per presentation.
  - A subverted secure element could leak through them.
  - In raw mode, a device log shared with a verifier links presentations (c = rep/h).
- **Single use:** prepared slots are single use, and a cloned raw slot reveals c and
  hence Q. Use `VerifierSession` for single-use nonces; it covers both modes.
- **Testing:** `tests/hashed_malicious.rs` builds hashed proofs by hand (feature
  `insecure-test-controls`): another device key, an SM for another point, an off-curve
  key, U1 = O, K → −K with and without re-proving, and a random K with no signature.
  `tests/freshness.rs` does the same for raw mode. Failing attacks are evidence about the
  tested attacks only.
- **Implementation:** not constant-time. Independent review is required before any
  deployment.
