# Basing the P-256 device binding on the ETSI committed-disclosure implementation (v0.7)

Status: analysis and feasibility probe, 15 October 2026. It compares the
DEVBIND-BBS-TOM-ECDSA/0.1 prototype (`devbind/`) with
`bbs-committed-disclosures-rust-v0.7` (crate `bbs_cd`, spec
`etsi-bbs-committed-disclosures-v0.7.md`).

The ETSI crate was built and tested unchanged: 67 tests pass. Probe programs
were then run against it. The proposed crate change is
`etsi-cd-integration/0001-prepared-proofgen-split.patch`. No file in your
`bbs-committed-disclosures-rust-v0.7` folder was modified.

## 1. Recommendation in one paragraph

Sign the device key Q as **four `SCALAR` messages** (x0, x1, y0, y1, each
< 2^128) at schema-fixed indexes. In device-bound presentations, mark all
four **`COMMIT`**. HIDE cannot work with this design. DISCLOSE works, but it
gives up unlinkability (§2). The ETSI public API is enough to build the
protocol: `PrecomputeCommitment`, `ProofGen` with `precomputed_rands`,
`ProofVerify` with caller-supplied commitments, and `commitment_generators`.

What changes is on the device-binding side:
- the generator roles flip (Y0 multiplies the message, Y1 the opening);
- the BBS challenge and proof encoding become the ETSI ones;
- the interface identifier becomes `H2G_HM2S_S2S_` with message types;
- you must decide how `ph` is used (§3.3).

The only change I'd suggest to the ETSI crate is optional: an offline/online
split of `ProofGen`. It cuts the online BBS cost from about 33 ms to about
0.02 ms, with byte-identical output (§4).

## 2. Hidden or committed: the cases

The device-binding proof (BLS→Tom transfer, Tom scalar multiplication
Q = c·Q′, ECDSA under Q′) must be tied to the issuer-signed Q. The only
artefacts a BBS presentation exports for an *external* proof are the public
commitments of `COMMIT` messages. ETSI spec §3.3.1.3 makes this the
integration boundary: the external proof uses the same group, the same
(Y0, Y1) with the same roles, and the same commitment point.

| Option | What the verifier gets | Works for device binding? | Privacy | Cost (Rust, this VM) |
|---|---|---|---|---|
| **DISCLOSE** the key (4 scalars or one octet string) | Q itself | Yes, trivially: verify an ECDSA signature under Q on the nonce. No Tom proof needed. | **Linkable**: Q is a stable identifier across all presentations and known to the issuer | smallest |
| **HIDE** the key limbs | nothing about Q (only knowledge of signed values) | **No.** Nothing in the presentation ties the Tom/ECDSA part to the signed key. A holder could run the device-binding proof for any key it controls. Tying them would mean changing the BBS proof to share the hidden-message responses with the external proof, which v0.7 does not offer. It also cannot work across groups: those responses are mod-ℓ field elements, while the transfer needs bounded integers with rejection sampling and its own challenge. | unlinkable, but no binding | ProofGen 23.5 ms, verify 14.8 ms, 504-byte proof |
| **COMMIT** the 4 limbs (recommended) | 4 fresh Pedersen commitments D_j = Y0·m_j + Y1·s_j | **Yes.** The D_j are exactly what the transfer consumes. The BBS shared-response link proves they hold the issuer-signed limbs, which also closes finding F-1 (the SM proof alone accepts off-curve points). | unlinkable: perfectly hiding commitments, fresh per presentation (ETSI §3.3.3 requires this) | ProofGen 33.5 ms, verify 24.7 ms, 824-byte proof (+320 bytes, negligible next to the ≈120 KB Tom proof) |

Sub-choices within COMMIT:

- **Type must be `SCALAR`, not `OCTETS`.** A hashed key is a ~255-bit hash
  scalar with no numeric relation to the coordinates. The transfer then has
  no in-range witness (`test_hashed_limb_bytes_cannot_transfer`). ETSI §3.3.2.3
  already requires scalars for messages consumed by numeric external predicates.
- **Four 128-bit limbs, not one or two larger scalars.** The coordinates are
  256-bit, larger than r, so they cannot be single scalars. The transfer
  needs b_x + b_c + b_f < 255, so b_x = 128. A 2-limb variant (x only plus a
  y-parity bit) would halve the transfer cost, but it creates a ±Q ambiguity
  that would need its own analysis. I don't recommend it now.
- **Commit to all four limbs in every device-bound presentation.** A
  presentation that doesn't request device binding may HIDE them. Use HIDE,
  not DISCLOSE, there.
- The issuer must sign only validated keys (decision D-1: on-curve,
  non-identity, x, y < p, attested, canonical limbs). With COMMIT, the
  soundness argument relies on this, because it is what makes the committed
  point a valid curve point.

**Conclusion:** COMMIT, with SCALAR limbs. HIDE is not an option for this
construction. DISCLOSE is an option only if unlinkability is not required.

## 3. What has to change in the device-binding protocol (DEVBIND → ETSI v0.7)

### 3.1 Required changes (my prototype must follow the ETSI crate)

| # | DEVBIND 0.1 today | ETSI v0.7 / crate | Change |
|---|---|---|---|
| E-1 | private api_id `…H2G_HM2S_DEVBIND_LIMBS_V0_`, limbs as raw scalars by convention | `api_id = ciphersuite_id ‖ "H2G_HM2S_S2S_"`, explicit `message_types` (`SCALAR`/`OCTETS`) | use the ETSI api_id; limbs `SCALAR`, attributes `OCTETS`; the device-binding profile fixes the limb indexes and puts a schema identifier in `header` (ETSI §3.3.2.2 leaves the schema source open) |
| E-2 | Blind-BBS roles: C = Y0·s + Y1·m | **C = Y0·m + Y1·s** (§3.2.2) | swap the transfer's BLS key: K1 = k·Y0 + k1·Y1; verify z·Y0 + s1·Y1 = K1 + c·D_j. Interop checked: my Python derivation of (Y0, Y1) for this api_id and Y0·m + Y1·s reproduce the Rust bytes exactly |
| E-3 | Blind-BBS challenge (`api_id ‖ "H2S_"`, ph appended) and Blind-BBS proof octets | challenge DST `api_id ‖ "COM_DIS_ETSI_PROOF_V1_H2S_"`; c_arr = (R, (i, m)…, A_bar, B_bar, D, T1, T2, domain, N, (i, C, C~)…) ‖ `presentation_context(ph, commitments)`; proof = I2OSP(N,8) ‖ A_bar ‖ B_bar ‖ D ‖ ê ‖ r̂1 ‖ r̂3 ‖ m̂… ‖ C… ‖ ŝ… ‖ c (§3.7.4, §4.2.4.4) | replace my `bbs.py` committed-disclosure layer with the ETSI procedures (or call the Rust crate) |
| E-4 | BBS commitments made inside my prepare step | `PrecomputeCommitment` returns (D_j, s_j); `ProofGen(…, precomputed_rands)` recomputes the same D_j | slot preparation calls `PrecomputeCommitment`. The D_j bound into the ECDSA representative h are exactly the ones ProofGen recomputes. Messages, types and indexes must be identical (§4.1.3) |
| E-5 | verifier takes D_j from the proof | `ProofVerify` takes the **caller's** commitments and checks equality | verifier: parse once, verify the transfer over D_j, pass the same D_j to `ProofVerify` (§3.5.4) |
| E-6 | BBS proof generation offline except for scalars | public `ProofGen` performs the mandatory signature check, commitment recomputation and ProofInit online | either accept ≈ 33 ms online (Rust, this VM) or adopt the split in §4 |
| E-7 | zero responses negligible but unhandled | every serialized proof scalar nonzero; retry with fresh masks, openings may be kept (§3.3.4) | retry ProofGen (or prepare again) on INVALID. Commitments and the device signature stay valid |

### 3.2 Unchanged

- The Tom-256 PA/SM proof, the BLS→Tom transfer parameters (b_x = 128,
  b_c = 112, b_f = 8), fold weights, ECDSA transformation, slot model and
  device interface.
- The rule that slots are single-use. ETSI §3.3.3 independently requires
  fresh openings per presentation and forbids reusing precomputed external proofs.
- All of this lives outside `bbs_cd`. It becomes a separate crate that depends
  on `bbs_cd` (BBS, Y0/Y1, G1 types from `bls12_381 0.9`), `p256` (or OpenSSL)
  for ECDSA, and a Tom-256 implementation. For Tom-256 there are two choices:
  port HPI's arkworks `t256` module, or reuse my Python arithmetic as the
  reference. Use `bls12_381 0.9` for the G1 side of the transfer so that no
  points cross library boundaries other than via canonical bytes. HPI uses
  halo2curves for BLS.

### 3.3 The one design decision: what goes into `ph`

ETSI binds the BBS proof to `ctx = presentation_context(ph, commitments)`.
It leaves external-proof binding to the external specification (§3.3.5,
NOTE 2). The device binding *must* be context-bound, because freshness needs
the verifier nonce.

- **P1, `ph = M` (my current design).** M is the device-binding digest over
  the nonce, ctx, Q′, D, T, the ECDSA signature and every Tom/transfer
  announcement. There is one composed Fiat–Shamir transcript, and the current
  soundness analysis (fork at the BBS challenge) applies directly. The
  drawback is that `ph` is no longer purely "Verifier-supplied". The verifier
  must recompute it from its own request and the presentation. The BBS proof
  can only be finished after the device signs.
- **P2, `ph` = the verifier's request context (nonce, audience, …).** This is
  the ETSI/[Vision] style. The device-binding representative h then binds
  `ctx = presentation_context(ph, D_0..D_3)` together with Q′ and T, and its
  own challenges are derived from its own digest. The BBS proof is unchanged
  ETSI usage, and it can be computed in parallel with device signing.
  This gives **two separately Fiat–Shamir'd proofs sharing a statement** (D_j
  and nv), so the composition argument in `SOUNDNESS_ANALYSIS.md` §6 must be
  redone. Each extractor rewinds its own hash, and both statements contain D
  and the nonce. I expect this to go through, but it has not been done.

I'd lean towards **P2** for spec alignment, but that needs renewed analysis.
P1 is covered by the existing analysis, with the stated open obligations.

## 4. Optional crate extension: prepared ProofGen

Spec §3.7 allows the proof subroutines to be exposed if the §3.6 checks are
enforced at that boundary and the state comes from a single invocation. The
patch adds `bbs_cd::prepared` (marked PROPOSED, not part of v0.7):

- `ProofPrepare(…)`: identical inputs, validation order and randomness order
  to `ProofGen`. It runs the mandatory `CoreVerify`, commitments and
  `ProofInit`, and precomputes every ph-independent transcript byte.
- `PreparedProof::complete(ph)` / `complete_fast(ph)`: these consume the state
  (not `Clone`), compute the challenge with `ctx`, and return the
  scalar responses and encoding.

Measured (release build, same 2-vCPU Xeon VM, 4 committed limbs, 4 hashed
attributes, 1 disclosed):

| | p50 |
|---|---|
| `PrecomputeCommitment` (4 limbs) | 3.4 ms |
| public `ProofGen` (COMMIT, precomputed openings) | 33.5 ms |
| `ProofPrepare` (offline) | 30.9 ms |
| `complete_fast(ph)` (online) | **0.019 ms** |
| `ProofVerify` (COMMIT) | 24.7 ms |

Output is **byte-identical** to `ProofGen` under the same mocked randomness
stream. The probe asserts this for both `complete` and `complete_fast`. All
67 existing crate tests still pass with the patch.

A persisted prepared state is exactly as sensitive as my slot: two `ph`
values answered from one state reveal the hidden messages, including the key
limbs. The type system enforces single use only within one process.

## 5. Open points to raise with the ETSI spec

1. **Schema source (§3.3.2.2).** The device-binding profile needs a normative
   place for "indexes i..i+3 are the P-256 key limbs, `SCALAR`, issuer-validated".
2. **External-proof context (§3.3.5).** Device binding is an external proof
   that must be context-bound. Choose P1 or P2 above and state it in the
   device-binding specification.
3. **Prepared proof API (§3.7).** Consider standardising an offline/online
   split, given the 33 ms vs 0.02 ms online difference. Precomputing commitments
   alone does not remove the online ProofInit and pairing check.
4. **Commitment roles (§3.2.2)** differ from Blind BBS. Any reuse of HPI or
   Blind-BBS-based transfer code must swap them. A swapped role fails silently
   (the ETSI note says so; my port had exactly this difference).

## 6. Reproduce

```
# in a copy of bbs-committed-disclosures-rust-v0.7
git apply 0001-prepared-proofgen-split.patch
cargo test --release --locked
cargo run --release --locked --example devbind_probe     # COMMIT/HIDE costs, Y0/Y1 roles, commitment interop
cargo run --release --locked --example prepared_probe    # byte equality + prepared latency
```
