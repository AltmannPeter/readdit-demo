> **Provenance.** This note was written for `devbind-rust` 0.2/0.3 (the predecessor of
> this repository) and is kept unchanged below as background. Measurements and status
> lines refer to that code, not to this repository.
>
> **Where the code now lives:**
>
> | devbind-rust | This repository |
> |---|---|
> | Tom-256 field and group, fixed-base combs, transfer, SM, PA, on-curve, batch verification, P-256 helpers, transfer configuration (`tom`, `comb`, `transfer`, `sm`, `pa`, `oncurve`, `batch`, `p256x`, `config`) | `crates/cd-tom256`, same module names |
> | key proof Q = c·Q′, raw signing and the raw-mode presentation | `crates/cd-ecdsa-pop/src/raw.rs` |
> | hashed mode (H-mode) | `crates/cd-ecdsa-pop/src/hashed.rs` |
> | linkage (limb commitments, transfer sets, on-curve), challenges, batched checks | `crates/cd-ecdsa-pop/src/common.rs` |
> | ETSI glue, `ph`, presentation encoding | `crates/bbs-cd-plugin/src/envelope.rs`, `request.rs` |
> | `devbind-bench` | `ecdsa-pop-bench` (`cargo run --release -p cd-ecdsa-pop --bin ecdsa-pop-bench`) |
>
> **Status in this repository:**
> - A3, A4, A5, A7 and A6 (feature `parallel`) are carried over.
> - A1 is built in: the envelope uses ETSI v0.7 `PrecomputeCommitment` and `ProofGen`
>   with precomputed openings, so no crate patch is needed.
> - B5 is built in: ph = Tr(nonce, ctx) depends only on the request, so the BBS proofs
>   and the device signature are independent. The analysis cited for B5
>   (`presentation-header-choice.md`) is not part of this repository.
> - B4 is still not adopted. The other items remain options.

# Optimization options for devbind-rust (0.2-etsi; status updated for 0.3)

**Status (16 Oct 2026):** A4, A5, A3, A7 and A6 (optional, `--features parallel`) are implemented (see the README). **B4 is not adopted** (Peter, 16 Oct 2026): measured decoding of the 1,792 SM points is 21.5 ms on the cloud VM (≈ 10–11 ms of 40.5 ms verify on the Mac), against +57,344 B (+46 %) per presentation and a wire-format change; A6 recovers most of it without a format change. It stays listed as an option. Mac after A4/A5: verify 255.5 → 49.5 ms. Cloud after A3/A7: prepare 564 → 114 ms (key proof 520 → 105, linkage 34 → 8), verify 92 → 81 ms. Profile on Peter's Mac (0.3, before A4/A5): ≈ 78 % of verify time was Tom-256 field arithmetic (`mul_assign`, `square`, Montgomery reduction), i.e. the number of curve operations, not any single slow function. Cloud VM after A4/A5: verify 500 → 92 ms (shared-bit); the remainder is ETSI `ProofVerify` (≈ 31 ms), SM point decoding plus the MSM (≈ 53 ms) and the transfer (≈ 5 ms). Next candidates: A3/A7 for prepare (key proof ≈ 520 ms on the VM, 266 ms on the Mac), then B4/decoding for verify.

The rest of this note is the original 0.2 analysis. The baseline is Peter's Mac run
(`devbind-bench --quick`, n = 5, default build, single thread):

| Phase | Measured (p50) | Dominated by |
|---|---|---|
| Offline prepare (per slot = per Q′) | 282 ms | key proof 265 ms (128 SM rounds, ≈ 2.1 ms/round); linkage 11 ms |
| Online (excl. device) | 17.0 ms | ETSI `ProofGen` 16 ms; everything else ≈ 1.1 ms |
| Verify | 250 ms (shared-bit) / 285 ms (separate-pa) | SM 232 / 269 ms; BBS 12 ms; transfer 2.7 ms; parse 1.3 ms |
| Presentation | 122.4 KB | SM section ≈ 120.6 KB (128 × 942 B) |

The gain estimates below are rough. They come from counting operations in the
code, not from measurements. **Profile first**, for example with
`cargo install samply && samply record target/release/devbind-bench --quick`.

### Operation counts behind the estimates (from the code)

- **Prepare, per SM round:** 26 Tom-256 scalar multiplications. 22 of them use
  the fixed generators GT/HT: the Pedersen commitments to U, V, Ct and the PA
  masks. 4 use variable bases (f1·at, Ct·at, Ct·ag, f1·b2). There are also
  2 P-256 scalar multiplications (ω·Q′, (ω−c)·Q′) and 14 affine conversions
  (each costs a field inversion) when the first message is encoded.
- **Verify, per SM round:**
  - 14 point decompressions (each a square root in F_pT; pT ≡ 3 mod 4).
  - 1 P-256 scalar multiplication α·Q′, always with the same base Q′.
  - 4 fixed-base Tom multiplications for the opening.
  - 23 Tom multiplications in `pa_verify`: 11 fixed-base, 12 variable-base,
    and 8 of those 12 are multiplications by −e.
  - In total ≈ 1 800 square roots and ≈ 3 500 Tom scalar multiplications per
    presentation.

---

## A. Implementation-only changes (same protocol, same wire format, same vectors)

| ID | Change | Affects | Rough gain | Effort |
|---|---|---|---|---|
| A1 | Enable `prepared-bbs` (already implemented, needs the crate patch) | online | 17 ms → ≈ 1 ms; offline +≈ 16–30 ms | none |
| A2 | Don't re-parse the BBS proof online | online | most of the remaining ≈ 1 ms | small |
| A3 | Fixed-base precomputed tables **(done)** | prepare, verify, linkage | prepare ≈ 3× (265 → ≈ 80 ms); verify part of A5 | medium |
| A4 | Cheap path for e ∈ {0, 1} in shared-bit verification **(done)** | verify | ≈ 10–15 % of SM verify | trivial |
| A5 | Batch-verify all SM rounds (and the transfer) as one MSM **(done)** | verify | Tom part ≈ 10–20× (≈ 200 → ≈ 15 ms) | medium |
| A6 | Parallelise rounds (rayon) **(done, optional feature)** | prepare, verify | ≈ number of cores | small |
| A7 | Batch normalisation (Montgomery's trick) **(done)** | prepare, verify | a few ms per slot | small |
| A8 | a = −3 doubling formulas for Tom-256 | everything Tom | ≈ 10–15 % per scalar mult | small–medium |
| A9 | Cache derived constants; avoid double work in `bbs_cd` | prepare, online, verify | ≈ 0.5–1 ms each | small (crate API for part) |
| A10 | Fewer spare transfer sets | linkage | ≈ 5–6 ms offline | trivial |
| A11 | Compact slot state | memory/storage | slot state roughly halved | small |
| A12 | Faster F_pT / F_p arithmetic | everything Tom | modest, uncertain | large |

**A1 – prepared BBS proof.** Already behind `--features prepared-bbs`. It moves
`ProofPrepare` offline, and the online step becomes `complete_fast(M)`
(measured 0.019 ms on the cloud VM). The crate patch is in
`etsi-cd-integration/`. For this to become the default, the patch has to go
upstream into the ETSI crate.

**A2 – online parsing.** `present` calls `octets_to_proof` on its own proof
only to read the challenge cp and compare commitments. That decompresses 7 G1
points with subgroup checks. The prover already knows these values, so it can
read cp from the fixed last 32 bytes, or `complete_fast` could return it
directly. This is probably most of the ≈ 1.1 ms of non-BBS online time;
profile to confirm.

**A3 – fixed-base tables.**
- **GT, HT:** a comb or windowed table built once per process (arkworks
  `BatchMulPreprocessing` / custom comb). Fixed-base multiplication is
  typically 5–10× faster than variable-base. 22 of the 26 prepare
  multiplications per round are fixed-base.
- **Q′:** α·Q′ (verify) and ω·Q′, (ω−c)·Q′ (prepare) share one base per
  presentation, so use `group::WnafBase` for P-256.
- **Y0, Y1:** the same applies to the BLS side of the transfer
  (`bls12_381` implements `group`).

**A4 – trivial challenges.** In shared-bit, `pa_verify` computes `X * (−e)`
with e ∈ {0, 1}. For e = 1, −e = p − 1 is a full 256-bit scalar, so 8 full
scalar multiplications per e = 1 round are wasted. Replace them with 0 / −X.
This also explains why separate-pa verify is only ≈ 15 % slower today.

**A5 – batch verification.** All 128 × (8 PA equations + 2 opening equations)
are linear in Tom-256 points. Check Σ ρ_ij·(LHS_ij − RHS_ij) = O with
independent random 128-bit weights ρ_ij (small-exponent batch test, error
≈ 2⁻¹²⁸; Tom-256 has prime order).
- The GT/HT coefficients collapse to 2 scalar multiplications, and C_Q's
  coordinates are shared by all rounds.
- That leaves ≈ 14 variable bases per round (Ct, T1..T6, U1, U2, U3, CUx,
  CUy, CVx, CVy), so one MSM of ≈ 1 800 points (arkworks `VariableBaseMSM`,
  Pippenger) replaces ≈ 3 500 scalar multiplications.
- Keep the per-round checks that are not linear: U1 ≠ O, α ≠ 0, and the P-256
  computation of W = α·Q′ whose coordinates enter the opening.
- After A5, the ≈ 1 800 point decompressions (≈ 20 ms by estimate) dominate
  the SM verify time (see B2/B4).
- The transfer verify (4 BLS + 4 Tom equations) batches the same way.

**A6 – parallelism.** Rounds are independent in both prepare and verify.
Slots can also be prepared concurrently in the background. On a phone, the
relevant metric for prepare is energy and pool-refill rate, not latency.

**A7 – batch normalisation.**
- `encode_sm_first` converts ≈ 1 800 projective points to affine one at a
  time (one inversion each). `commit_point` and `coords_fr` also convert U, V
  and W individually.
- Use `CurveGroup::normalize_batch`, and the P-256 equivalent.
- Also cache the coordinates of Q: `pa_prepare` recomputes them in every round.

**A8 – Tom-256 point formulas.** arkworks short-Weierstrass arithmetic only
special-cases a = 0. Tom-256 has a = −3, so the dedicated a = −3 Jacobian
doubling (or complete Renes–Costello–Batina formulas) saves a few field
multiplications per doubling.

**A9 – caching.**
- In this crate: `IssuerParams::header()` and `message_types()` are rebuilt
  several times per call, and `pa_prepare` recomputes the coordinates of Q in
  every round. Cache them. Commitment and message generators are already
  cached inside `bbs_cd` (`create_generators` keeps a process-wide cache), so
  there is nothing to gain there.
- In `bbs_cd` (needs an API change or patch):
  - `ProofVerify` parses the proof again after our parser did (7 G1
    decompressions with subgroup checks).
  - `calculate_domain` re-hashes the generators on every call.
  - The issuer key could be kept as `G2Prepared` for the pairing.

**A10 – spare transfer sets.** Each set is 4 DLEQ preparations (BLS + Tom
commitments). The abort probability per set is ≈ 3 % (≈ 2⁻⁸ for z < 2²⁴⁰
plus ≤ 2⁻⁸ for z ≥ 2²⁴⁸, per limb). With 1 + 1 spares instead of 1 + 4,
running out has probability ≈ 10⁻³ and falls back to the cold path. This
saves 60 % of the linkage cost.

**A11 – slot state.** `PaState.ann`, `cu` and `cv` duplicate `sm_ann_bytes`
as projective points. In shared-bit, only z0/z1, ω, ω−c and the blinds are
needed after preparation; masks and slopes can be dropped. Store everything
as canonical bytes.

**A12 – field arithmetic.** arkworks generic Montgomery arithmetic has no
assembly path on aarch64. fiat-crypto-generated or hand-tuned Montgomery code
for pT and p might give a modest gain. Measure before investing.

---

## B. Encoding / protocol-parameter changes (same proof idea; spec, vectors and analysis must be updated)

| ID | Change | Gain | Cost / risk |
|---|---|---|---|
| B1 | 112 SM rounds instead of 128 | −12.5 % prepare, verify, size (≈ −15 KB) | security-target decision |
| B2 | Challenge–response form: omit recomputable announcements | ≈ −42 KB (→ ≈ 80 KB); ≈ 1 300 fewer decompressions | blocks the A5 batching; FS analysis restated |
| B3 | Seed compression of b = 0 rounds (shared-bit only) | with B1+B2 ≈ 45 KB total | new encoding; ZK/soundness argument restated |
| B4 | Uncompressed Tom points **(not adopted)** | ≈ −21 ms verify on the VM, ≈ −10 ms on the Mac (no square roots) | +32 B per point (+57,344 B, +46 %); wire change |
| B5 | ph = verifier context (P2) | online = max(device, BBS) instead of the sum, without the crate patch | needs the composition analysis in `presentation-header-choice.md` |

**B1 – round count.** The composed target is ≈ 110–112-bit because the
transfer challenges are 112-bit (`docs/SOUNDNESS_ANALYSIS.md`). The SM uses
128 rounds with one batched Fiat–Shamir challenge (error ≈ q_H·2⁻ᵏ). Matching
k = 112 does not lower the overall level, but it is a decision about the
security target, not just an optimisation.

**B2 – recompute instead of send.**
- The PA announcements T1..T6, U2, U3 are determined by the responses and the
  challenge (T = f(z) − e·X), and the opened commitment pair (CU if b = 0,
  CV if b = 1) equals `commit_point(α·Q′, rr)`.
- The presentation would carry M (32 B) instead. The verifier derives cp and
  the bits from M, recomputes the omitted points, rebuilds M, and compares.
  This is the standard (challenge, response) form of Fiat–Shamir.
- It saves 10 × 33 B per round (330 B → ≈ 42 KB) and the matching
  decompressions.
- Trade-off: each omitted announcement must now be computed individually, so
  A5's single-MSM batching no longer applies. Size and verify time pull in
  different directions.
- The transfer announcements K1, K2 can be dropped the same way (−324 B).

**B3 – seeds for b = 0 rounds.** In shared-bit with e = b = 0, every value
the round reveals (ω, ru, the PA masks) is uniform randomness. If the prover
derives that randomness from a per-round seed, the response for a b = 0 round
can be the seed. CV, Ct and U1 must still be sent, because they depend on c
and on the slope. This is the seed trick known from cut-and-choose / MPC-in-the-head
proofs. With B1 + B2 the estimate is ≈ 164 B for b = 0 rounds and ≈ 612 B for
b = 1 rounds, about 45 KB in total.

**B4 – uncompressed points.** This removes the square roots but costs size.
It is mainly interesting combined with A5; with B2 there are far fewer
points to decode anyway.

**B5 – presentation header P2.** The BBS proof no longer depends on the device
signature, so it can be computed while the device signs. This is irrelevant
once A1 is in place.

---

## C. Larger protocol changes (research)

- **C1 – replace the binary-challenge SM.**
  - The 128 binary rounds are the reason for the ≈ 120 KB size and most of
    the prepare and verify time.
  - An arithmetic-circuit or inner-product proof over Tom-256 for "C_Q opens
    to c·Q′" (Bulletproofs-style) would give proofs of a few KB. Prover cost
    would probably be higher, and the verifier remains roughly linear.
  - It needs a new soundness analysis. If the circuit includes the on-curve
    check, it also removes finding F-1.
- **C2 – a precomputation-friendly binding.** This is the "different binding
  approach" noted in `../presentation-header-choice.md`. It would let the BBS
  proof and the key proof be prepared fully offline under a spec-aligned `ph`.

## What cannot be optimised away

- **Per-slot work cannot be shared.** Q′, T_j, D_j, the SM first messages and
  the transfer announcements must be fresh per presentation. Reusing any of
  them links presentations or leaks witness values (cloned-slot findings).
  The per-slot cost can be made cheaper, not shared.
- **One bit per round.** The SM opens either U or V, so each round has a
  binary challenge. A larger challenge space per round is not available
  within this construction (see C1).

## Constant-time caveat

Precomputed tables, wNAF and Pippenger MSM are variable-time. That is fine on
the verifier, whose inputs are public. On the prover, most scalars are secret
(ω, ω−c, masks, blinds, a, c), so a production prover needs constant-time
fixed-base combs (constant-time table lookups) and constant-time field
inversion. Expect part of the prepare speed-up to be given back.

## Suggested order

1. Profile on the Mac to confirm the counts above.
2. A4, A2, A9, A10, then enable A1. These are trivial or already done.
   Expected online ≈ 0.1–0.3 ms + device.
3. A3, A7, A5, then A8. Expected (rough): prepare ≈ 70–100 ms, verify
   ≈ 40–60 ms, single thread.
4. A6. Divide the above by roughly the number of cores.
5. Decide B1–B3 together with a 0.2 spec freeze, since they change the wire
   format and test vectors.
