# Experimental: hashed-ECDSA device binding (H-mode)

**Status:** experimental comparison code behind the cargo feature `experimental-hashed`. It is **not** part of DEVBIND-BBS-TOM-ECDSA/0.3 and has no specification, security analysis or review. The default build and the 0.3 protocol are unchanged.

**Protocol id:** `DEVBIND-BBS-TOM-ECDSA-H/exp1`. **Wire magic:** `DBH\x01`. **Module:** `src/hmode.rs`.

## Idea

H-mode follows the device module of ePrint 2025/1981 (Vision).
- The device signs a message containing the verifier nonce with **ordinary ECDSA-P256-SHA256**. There is no raw signing and no key randomisation.
- The holder proves in zero knowledge that the committed credential key verifies that signature.
- Freshness then rests on standard ECDSA EUF-CMA instead of KR-ECDSA, **provided the device key is used only through the hashed interface**.

## Construction

1. **Offline** (`prepare_slot_h`). Prepare everything that does not depend on the signature:
   - the ETSI `PrecomputeCommitment` limb commitments D_j;
   - the Tom commitments T_j and the transfer sets;
   - the on-curve proof for the fold (C_x, C_y), which commits to Q.

   All of these are the 0.3 code. There is no key proof yet.
2. **Online** (`present_h`):
   1. Run the ETSI `ProofGen` with `ph_H = Tr("DEVBIND-H/exp1/presentation-header"; nv, ctx)`.
   2. Build `stmt_H = Tr("DEVBIND-H/exp1/statement"; protocol, profile, pk, header, L, disclosed, committed, D, T)`. Q′ is not used.
   3. Build `m = Tr("DEVBIND-H/exp1/device-message"; stmt_H, nv, ctx, nh)`.
   4. The device returns an ordinary ECDSA signature (r, s) on m. Let h = SHA-256(m) mod n.
   5. The holder checks the signature and computes:
      - K = s⁻¹(h·G + r·Q), checking that x(K) mod n = r;
      - z = s/r;
      - Hpt = (h/r)·G;
      - W = Q + Hpt = z·K.
   6. Commit to W as (CW_x, CW_y). Then prove:
      - **link PA:** Q + Hpt = W, with Q committed by the fold, Hpt public (zero-blinded commitment) and W committed;
      - **SM (128 rounds):** W = z·K, with base K and result CW. This reuses `sm_prepare_rounds_with` unchanged.
   7. `M′_H = SHA-256(Tr("DEVBIND-H/exp1/device-binding-challenge"; SHA-256(m), Enc(K), transfer announcements, on-curve first message, link first message, SM first messages))`.
   8. Derive the transfer, SM-bit, PA and on-curve challenges from M′_H with the 0.3 derivation functions, and the link challenge with its own tag.
3. **Verifier** (`verify_h`):
   1. Recompute stmt_H, m and h. Reject if h = 0.
   2. Set r = x(K) mod n and reject if r = 0. Compute Hpt = (h/r)·G.
   3. Run the ETSI `ProofVerify` with ph_H.
   4. Check the link PA individually.
   5. Check the transfer, on-curve and SM equations in one G1 batch and one Tom-256 batch, as in 0.3. `TomBatch::absorb_shared` merges the fold-based and CW-based accumulators.

   `verify_h_individual` is the reference path.

**Why the SM extraction is sound here (sketch).** OC-1 puts Q on the curve. Hpt is a public curve point and x(Hpt) ≠ x(Q). So the chord equations of the link PA force W = Q + Hpt, a curve point, and SM-1 then gives z with z·K = W. That is the ECDSA verification equation s·K = h·G + r·Q with s = z·r. This argument has not been reviewed.

## What the verifier sees

| | 0.3 | H-mode |
|---|---|---|
| Public device-side values | Q′, r, s′ | K (r = x(K) mod n) |
| ECDSA check | in the clear, under Q′ | inside the proof (link PA + SM over base K) |
| Extra proof | — | link PA + CW: 780 bytes |

## Wire format

```
"DBH\x01" ‖ profile ‖ nh(32) ‖ Enc(K)(33) ‖ disclosed attributes ‖ P_bbs ‖ T_j
‖ transfer entries ‖ on-curve (9 points, 8 scalars)
‖ link: CW_x, CW_y, PA announcements (12 points) ‖ PA responses (12 scalars)
‖ I2OSP(128,2) ‖ 128 SM rounds (as 0.3)
```

## Trade-off

- **Precomputation is lost.** The SM base K exists only after the device signs, so the 128 SM rounds and the link PA run after the signature, on the online critical path.
- **Comparable costs.** Verification cost and size are about the same as in 0.3.

## Running

```
cargo test --release --features experimental-hashed --test hmode
cargo run --release --features experimental-hashed,parallel --bin devbind-bench-modes -- --n 20 --threads off
cargo run --release --features experimental-hashed,parallel --bin devbind-bench-modes -- --n 20 --threads max
```

The benchmark prints the CPU components of both modes. It also prints the online critical path for simulated device latencies (`--latency 0,50,150,300`), assuming that CPU work that does not depend on the signature runs while the device works. Results go to `bench/results/` (gitignored).
