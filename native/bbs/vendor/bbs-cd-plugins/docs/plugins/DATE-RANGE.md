# `date-range/0.1`: a committed date in a requested range

Plugin of the BBS committed-disclosure framework (`docs/ENVELOPE.md`). Crate:
`crates/cd-date-range`. Status: research specification, version 0.1. There are no test
vectors yet.

The credential holds a date, typically the birth date, as a one-scalar attribute (§1).
The verifier asks "born on or after X", "born on or before Y", or both, with X and Y given
as `YYYYMMDD` (§2). The holder commits to the date in the BBS presentation and proves, in
zero knowledge, that it lies in the range (§3). The date itself is never revealed, and one
credential answers every cutoff and every range: there is no per-threshold issuance or
precomputation.

Age checks are the defining use: "at least 18 on 2026-10-18" is `le: 20081018`; "younger
than 25" is `ge: 20011019`; "between 18 and 25" sends both.

The range proof is the bit-decomposition proof of the IETF Privacy Pass range proof for
arbitrary values (§5.4, "Range Proof for Arbitrary Values"): the same bases for an
arbitrary limit and the same bit proof, here run natively in BLS12-381 G1 with the ETSI
commitment generators, so the attribute commitment D needs no transfer to another group.

## 1. Date attribute type `date-packed`

- **Layout.** A `Scalars` attribute with `count` = 1 and `bits` = b ∈ [16, 32].
  Recommended: b = 17 (dates up to the year 2252).
- **Encoding.** A calendar date (Y, M, D) is the integer

  ```
  pack(Y, M, D) = (Y − 1900)·372 + (M − 1)·31 + (D − 1)
  ```

  Every month gets 31 slots and every year 12·31 = 372. So pack is strictly increasing in
  (Y, M, D), whatever the month lengths or leap years, and comparing packed values
  compares dates. Days that don't exist (2010-02-30, 2010-04-31) are unused values.
  1900-01-01 is 0; 2026-10-18 is 47,168.
- **Issuance** (`DateHandler`):
  - Input: the date as ASCII `YYYY-MM-DD` (10 bytes), the `full-date` form of a PID
    `birth_date`.
  - The issuer checks that it is a real Gregorian date (leap years: divisible by 4, not
    by 100 unless by 400), that Y ≥ 1900, and that pack(Y, M, D) < 2^b.
  - The issuer computes the scalar itself.

  Partial dates (unknown day or month) are an issuer policy. For age checks the
  conservative choice is the latest possible date: day 31 or month 12, which pack accepts
  (the handler in this crate takes complete dates only).

## 2. Request parameters

The parameters are the `PluginRequest::params` bytes, bound into ctx:

```
u8 flags ‖ [u32 ge] ‖ [u32 le]          (big-endian; ge present iff flags & 1, le iff flags & 2)
```

- **flags** ∈ {1, 2, 3}: at least one bound. Any other value, or a length that does not
  match flags, is rejected.
- **ge, le:** a date written as the decimal number YYYYMMDD (2008-10-18 is 20,081,018).
  Valid when Y ∈ [1900, 9999], M ∈ [1, 12] and D ∈ [1, 31]. **There is no calendar
  check.** A day that doesn't exist is still a correct bound: "on or before 2010-02-29"
  means on or before 2010-02-28, which is exactly who turns 18 on 2028-02-29. So a
  verifier can compute "today minus N years" by subtracting N from the year.
- **Semantics** (both bounds inclusive): `ge` = born on or after, `le` = born on or before.
- **Range** for an attribute with b bits:

  ```
  lo = pack(ge)                 if ge is present, else 0
  hi = min(pack(le), 2^b − 1)   if le is present, else 2^b − 1
  ```

  Clamping `le` at 2^b − 1 states a stronger claim than asked: every issued value is below
  2^b.
- **The verifier's `check_request` rejects** non-canonical parameters, an invalid date
  field, lo ≥ hi, and an attribute of another type or layout. The prover applies the same
  checks.

The statement proven is lo ≤ m ≤ hi, where m is the committed attribute value.

## 3. Range proof

**Notation.**
- Y0, Y1: the ETSI commitment generators (`commitment_generators` of the suite).
- D = m·Y0 + s·Y1: the attribute's commitment from the BBS proof, with the opening s
  known to the holder.
- C′ = D − lo·Y0 = v·Y0 + s·Y1, a commitment to v = m − lo.
- N = hi − lo ≥ 1, the largest allowed v, and k = bitlen(N) ≥ 1.

**Bases** (Privacy Pass ComputeBases for the limit N + 1):

```
β_i     = 2^i                       for i = 0 … k − 2
β_{k−1} = N − 2^(k−1) + 1           (1 ≤ β_{k−1} ≤ 2^(k−1))
```

Every combination Σ b_i·β_i with bits b_i lies in [0, N], since the maximum is
(2^(k−1) − 1) + β_{k−1} = N, and every v ∈ [0, N] has one:
- if v < 2^(k−1): b_{k−1} = 0 and b_0 … b_{k−2} are the bits of v;
- otherwise b_{k−1} = 1 and b_0 … b_{k−2} are the bits of v − β_{k−1}, which lies in
  [0, 2^(k−1) − 1].

**Bit commitments.** For i < k − 1 the holder picks a uniform s_i; the last one makes the
sum exact:

```
s_{k−1} = (s − Σ_{i<k−1} β_i·s_i) · β_{k−1}^(−1)
D_i     = b_i·Y0 + s_i·Y1           so that   Σ β_i·D_i = C′
```

**Bit proofs.** For each i, a Schnorr proof of knowledge of (b_i, s_i, t_i) with
t_i = (1 − b_i)·s_i such that

```
D_i = b_i·Y0 + s_i·Y1
D_i = b_i·D_i + t_i·Y1
```

The second relation gives (b_i − b_i²)·Y0 = (t_i − (1 − b_i)·s_i)·Y1, so b_i ∈ {0, 1}
unless the prover knows log_Y0(Y1).

- **Prover:** uniform ρ_i, σ_i, τ_i; A_i = ρ_i·Y0 + σ_i·Y1 and B_i = ρ_i·D_i + τ_i·Y1;
  the challenge c (§4); then
  z_{b,i} = ρ_i + c·b_i, z_{s,i} = σ_i + c·s_i, z_{t,i} = τ_i + c·t_i.
- **Verifier:** recomputes
  A_i = z_{b,i}·Y0 + z_{s,i}·Y1 − c·D_i and B_i = (z_{b,i} − c)·D_i + z_{t,i}·Y1,
  then recomputes c from them and compares.

One challenge covers all k bit proofs.

## 4. Challenge

Tr is the length-prefixed transcript of ENVELOPE.md §1, and env, nonce, plugin_index come
from the envelope (ENVELOPE.md §5).

```
tr = Tr("DATE-RANGE/0.1/challenge";
        "plugin" = "date-range/0.1", "plugin_index" = u16, "attribute" = attribute name,
        "params" = params, "env" = SHA-256(env), "nonce" = nonce,
        "lo" = u32 lo, "hi" = u32 hi, "D" = D,
        "Di" = D_0 ‖ … ‖ D_{k−1}, "A" = A_0 ‖ … ‖ A_{k−1}, "B" = B_0 ‖ … ‖ B_{k−1})
c  = hash_to_scalar(tr, "DATE-RANGE/0.1/challenge-h2s")     (the suite's hash_to_scalar)
```

This follows the binding rules of ENVELOPE.md §5: the plugin id, env, the position, the
parameters, the nonce and every revealed value (D_i, and A_i and B_i through c) are in the
transcript.

## 5. Proof encoding

```
"DRP\x01" ‖ c ‖ ( D_i ‖ z_{b,i} ‖ z_{s,i} ‖ z_{t,i} )  for i = 0 … k − 1
```

Points are 48-byte compressed G1, scalars 32 bytes big-endian. The length is
36 + 144·k bytes, fixed by the parameters and b. The verifier rejects any other length, a
wrong magic, a point that is not a canonical encoding of a G1 subgroup point, and a
non-canonical scalar (≥ r).

## 6. Verifier

Given the view (one commitment D), the parameters and the proof:

1. `check_request`: attribute type `date-packed`, `count` = 1, `bits` ∈ [16, 32]; params
   valid (§2); compute lo, hi, N, k and the bases.
2. Parse the proof (§5).
3. Check Σ β_i·D_i = D − lo·Y0.
4. Recompute every A_i and B_i (§3) and c′ = the challenge of §4. Accept iff c′ = c.
5. Output the parameters (the statement that was proven).

## 7. Sizes

| Question | lo, hi (b = 17) | k | Proof bytes |
|---|---|---|---|
| `le: 20081018` (18+ on 2026-10-18) | 0, 40,472 | 16 | 2,340 |
| `ge: 20011019` (under 25) | 37,869, 131,071 | 17 | 2,484 |
| `ge: 20011019, le: 20081018` (18 to 24) | 37,869, 40,472 | 12 | 1,764 |

k grows by one bit when a one-sided `le` cutoff passes 2076-03-02 (16 → 17), so 18+ checks
stay at 16 bits until about 2094. A one-sided `ge` costs b bits; send an `le` of today to
make it cheaper.

Time is roughly linear in k. Single-threaded on the cloud VM, an 18+ check (k = 16) takes
about 5.1 ms to prove and 9.4 ms to verify, plus a one-time 19 ms per process to build
the generator tables (below). `cargo run --release -p cd-date-range --bin
date-range-bench` measures them.

**Implementation.** None of the following changes the proof bytes or the verification
equations; a test checks proofs against a textbook verifier with plain scalar
multiplication.

- **Generator tables** (`src/fixed.rs`): for Y0 and Y1, b·256^j·Y for the 32 byte
  positions j and b = 1 … 255, in affine form. A multiple is then at most 32 complete
  mixed additions, one per nonzero byte of the scalar, and no doublings. The tables
  depend only on the suite's public generators and keep nothing about any proof. They
  take about 1.5 MB and are built once per process, on first use or earlier with
  `cd_date_range::precompute()` (at app start, or when a request arrives).
- **Per-proof points:** multiples of D_i use wNAF. Per bit, the prover does about 3 table
  multiplications and one variable-base multiplication (ρ·D_i); the verifier does 3
  table multiplications and two variable-base ones (c·D_i and (z_b − c)·D_i), which
  dominate its cost.
- **Encoding for the challenge:** the D_i, A_i and B_i are converted to affine form in
  one batch (one field inversion, Montgomery's trick) instead of one inversion per
  point.
- **Sum check:** Σ β_i·D_i is computed with Horner's rule over the power-of-two bases
  (one doubling and one addition per digit) plus one small multiple for the last base.

## 8. Security and privacy notes

- **Soundness.** From two accepting transcripts with different challenges, each bit proof
  yields (b_i, s_i, t_i) with b_i ∈ {0, 1}, or log_Y0(Y1). The sum check then gives
  v ≡ Σ β_i·b_i (mod r), with Σ β_i·b_i ∈ [0, N]. Since lo + N = hi < r and m is a
  canonical scalar, m = lo + v as integers, so lo ≤ m ≤ hi. The ETSI proof binds D to the
  signed m. The argument does not use the issuer's bit width; the width only defines the
  default and clamped upper bound.
- **Assumption:** discrete logarithms between Y0 and Y1 are unknown (the same assumption
  that makes the ETSI commitments binding; both are hash-to-curve generators).
- **Zero knowledge.**
  - The D_i are Pedersen commitments.
  - s_{k−1} is uniform because s is a fresh, uniform, hidden opening (a new one for every
    presentation).
  - The bit proofs are honest-verifier zero knowledge Schnorr proofs, made
    non-interactive with Fiat–Shamir.
  - The proof length depends only on the parameters and b.
- **Malicious holder.** `tests/malicious.rs` builds proofs by hand (feature
  `insecure-test-controls`):
  - a date outside the range, with any digits;
  - a digit of 2 or −1;
  - commitments that don't sum to C′;
  - a proof moved to other parameters, another request or another plugin position;
  - bit flips across the whole proof.

  All are rejected. Failing attacks are evidence about the tested attacks only.
- **What the verifier learns: one bit per request,** plus the fact that the holder
  answered (an honest holder refuses when the date is out of range). Dynamic cutoffs make
  this bit adjustable, so a verifier that sends many requests can binary-search the
  date: about 16 requests give the exact day, and one narrow two-sided window gives it
  at once. The cryptography can't prevent this; the holder's wallet must:
  - **Narrow windows:** this crate's prover refuses windows narrower than 372 slots
    (about a year) by default (`DateRangeProver::with_min_window`).
  - **Recommended wallet policy:** show the question; accept only cutoffs of the form
    "today minus N whole years" (± 1 day for time zones); rate-limit per verifier.
- **Tagging and linking.** m is never revealed, and D, the D_i and the responses are fresh
  per presentation, so an issuer colluding with a verifier can't link presentations
  through this plugin. The parameters are the verifier's own choice and carry nothing
  from the holder.
- **Dates and time zones** are the verifier's responsibility: the plugin proves the
  comparison with the bounds it is given.
- **Implementation:** not constant-time. Independent review is required before any
  deployment.
