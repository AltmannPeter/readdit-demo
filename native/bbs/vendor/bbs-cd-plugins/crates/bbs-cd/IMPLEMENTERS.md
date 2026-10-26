# Reviewer and Implementer Guide

This standalone repository implements the **ETSI BBS committed-disclosure profile, v0.7**, in Rust. This guide maps its tests and fixture conventions for reviewers and for third parties building another implementation.

The crate is not constant-time and is not for production use. Passing the supplied vectors checks concrete algorithm and encoding behavior; it does not establish the security of a deployment or an external predicate protocol.

## Contents

1. Review and independence
2. What to read
3. What "passing" means
4. Building the implementation
5. The fixture runner
6. Operations and their fixtures
7. Mocked randomness
8. Conventions you must match
9. Review boundaries
10. The BBS cross-check
11. Reporting results

## 1. Review and independence

Reviewers can read the Rust source and tests alongside the specification. The local code is organized by spec procedure: `src/interface.rs` covers the interface, `src/core.rs` the core operations, `src/proof_protocol.rs` the internal proof subroutines, and `src/utils.rs`, `src/helpers.rs` and `src/primitives.rs` their supporting contracts. Source comments identify spec sections; fixture runner comments also refer to this guide's numbered sections.

For a separately developed implementation, preserve independence by implementing from the spec before reading this repository's source or harness. The supplied profile fixtures originated from a Python implementation. This Rust implementation's profile operations were written without reading that implementation, its tests or its fixture generation and runner tools; its fixture runner was written after those operations.

- **Use the specification.** The source of truth is the ETSI BBS committed-disclosure profile, working draft v0.7 (the draft text is not redistributed here; a local copy at `spec/etsi-bbs-committed-disclosures-v0.7.md` is ignored by git). For deferred behavior, use BBS-12 (`draft-irtf-cfrg-bbs-signatures-12`).
- **For independent work, check fixtures after implementing each operation.** Agreement with a copied implementation cannot expose a shared misreading.
- **Investigate each mismatch.** Distinguish an implementation bug, a specification ambiguity and a suspected fixture defect. Report the latter two with evidence (Section 11), preserving the spec and frozen fixtures.

## 2. What to read

| File | Use |
| --- | --- |
| ETSI CD v0.7 draft (not redistributed; local copy in `spec/`) | The specification. Notation is in Section 1.4. Inclusive slices `[a..b]` and `FOR … UP TO` loops follow BBS-12. |
| `fixtures/bbs/source/draft-irtf-cfrg-bbs-signatures-13.txt` | The BBS draft. It is used only for the BBS test vectors (Section 10). Appendix G records no cryptographic changes since -12. |
| `fixtures/README.md` | Fixture JSON format, encodings, mocked randomness, and the map from spec Section 5 items to fixtures. |
| `fixtures/profile/<suite>/<Operation>/NNN_*.json` | 336 profile fixtures: 168 for `BLS12-381-SHA-256` and 168 for `BLS12-381-SHAKE-256`. |
| `fixtures/bbs/` | BBS draft vectors as JSON. See `fixtures/bbs/SOURCE.md`. |
| `REVIEW_NOTES.md` | Current review boundaries and remaining questions. |
| `src/profile_vectors/`, `src/bbs_vectors.rs` | Rust fixture harnesses; read these when reviewing this implementation. |
| `tests/data/PROFILE_SOURCE.md`, `tests/data/profile_manifest.json` | Provenance and frozen hashes of the supplied profile cases. |

## 3. What "passing" means

The profile corpus contains 336 unchanged cases, 168 per suite across 17 operations. Their `specVersion: "v0.5"` records the version that generated them. It is preserved as provenance, together with their hashes. The current implementation target is v0.7; the spec's Section 5 explains the unchanged wire format and the additional local tests for injected hash outputs.

Your implementation agrees with this repository when it meets all three conditions:

1. All 336 profile fixtures pass, for both ciphersuites.
2. The BBS vectors in `fixtures/bbs/` reproduce as described in Section 10.
3. Every fixture satisfied by an input-boundary rejection is listed in your report (Section 5), and implementation-specific exceptional-hash tests also pass (Section 9).

If you implement only one ciphersuite, say so and run that suite's fixtures. The fixtures directory is split by suite.

## 4. Building the implementation

**Curve**

You need BLS12-381 with three things:

- the optimal Ate pairing;
- compressed point encoding (BBS-12 Appendix B.2);
- RFC 9380 `hash_to_curve` for G1 (SSWU, random oracle) with both expanders:
  - `expand_message_xmd` with SHA-256 for the SHA-256 suite;
  - `expand_message_xof` with SHAKE-256 (k = 128, L = 64) for the SHAKE-256 suite (BBS-12 Appendix A.1).
  
  Test these against the RFC 9380 vectors before anything else.

This crate uses `bls12_381` for group and pairing operations, with the SHAKE-256 expansion and hash-to-field support in `src/primitives.rs`. `tests/rfc9380.rs` checks the primitive vectors independently of the profile corpus.

**Decoding**

Implement the acceptance checks of spec 4.2.4.6 explicitly:

- canonical encoding: re-encode the point and compare with the input;
- subgroup membership;
- identity exclusion.

Do not assume the library performs them. Several fixtures depend on these checks.

**Scalars and messages**

- **Scalar inputs.** Inputs that may be out of range must be representable as 256-bit integers, because fixtures pass `r` and `2^256 - 1` to test rejection. Never reduce them silently (spec 1.4.3).
- **Messages.** A message is either an octet string or a scalar (spec 3.3.2.1), so model it as an enum. The type vector (`OCTETS`/`SCALAR`) is a separate input, and a mismatch between the two must give `INVALID`.

**Randomness**

`calculate_random_scalars` must be injectable, because fixtures replace it with the mocked stream in Section 7. Normal operation uses the system random source. Keep deterministic fixture sources confined to test use.

**Constant time**

Constant-time code is not required to pass the fixtures. State in your report whether your implementation is constant-time.

## 5. The fixture runner

Run the included Rust harness from the repository root:

```sh
cargo test --locked
cargo test --locked profile_vectors::all_profile_fixtures -- --nocapture
cargo test --locked bbs_vectors:: -- --nocapture
```

The profile harness enumerates files independently of the manifest, checks all hashes and suite/operation counts, compares outcomes, and checks supplied positive trace fields. It reports input-boundary rejections separately. Set `BBS_PROFILE_REPORT` to an output file path to save its JSON report, for example:

```sh
BBS_PROFILE_REPORT=/tmp/bbs-profile-report.json cargo test --locked profile_vectors::all_profile_fixtures -- --nocapture
```

For another implementation, write a runner in its own language. For each JSON file it must:

1. Read `operation`, `ciphersuite`, `input` and, where present, `mockedRng`.
2. Decode the inputs (encodings in `fixtures/README.md`):
   - octet strings are lowercase hex;
   - scalars are 32-octet big-endian hex;
   - points are compressed hex;
   - a scalar message is `{"scalar": "<hex>"}`, and an octet-string message is a plain hex string.
3. Call your operation and compare the result with `expected`:
   - `{"output": …}` must match exactly. `ProofGen` and `CoreProofGen` also return `addZkpInfo`, which must match too.
   - `{"result": {"valid": b}}` must match your VALID/INVALID outcome. For a generation or utility operation, `valid: false` means it returned `INVALID`.
   - `{"abort": true}` means your operation must abort, not return `INVALID`.
   
   `reason` is informative only.
4. On a mismatch, compare the `trace` values in order and report the first one that differs (Section 11).

**Inputs your types cannot represent.** Some negative fixtures carry inputs a typed language rejects while parsing:

- the message type `"UNKNOWN"` and the disclosure state `"SHOW"`;
- non-integer indexes such as `1.5` and `4.5`.

The spec requires these to be rejected (spec 4.1.4 and Section 5). If your runner maps a parse failure to `INVALID`, list every fixture satisfied this way in your report. The Rust types preserve unknown enum values and noninteger indexes for validation; its harness separately inventories point-decoding input rejections. Malformed fixture schema is a harness failure, rather than an accepted negative result.

## 6. Operations and their fixtures

`api_id` below is the profile identifier, `ciphersuite_id || "H2G_HM2S_S2S_"`. Interface operations use it implicitly. Core operations and utilities take `apiId` explicitly, and some use the BBS-12 `api_id`.

| `operation` | Spec | Notes |
| --- | --- | --- |
| `KeyGen` | 3.4.1, 3.4.2 | `keyDst` is absent, so use the default `ciphersuite_id \|\| "KEYGEN_DST_"`. The output is `{SK, PK}`, with `PK = SkToPk(SK)`. |
| `Sign`, `Verify` | 3.5.1, 3.5.2 | |
| `ProofGen` | 3.5.3 | `precomputedRands: null` means `NONE`. The output is the proof, plus `addZkpInfo` = (`committedMessages`, `commitmentRands`). |
| `ProofVerify` | 3.5.4 | `commitments` are compressed G1 points (see Section 8 for how to decode them). Each successful `ProofGen` fixture has a `… (verify)` companion. |
| `PrecomputeCommitment` | 4.1.3 | The output is `{commitments, commitmentRands}`. |
| `CoreSign`, `CoreVerify` | 3.6.1, 3.6.2 | Generators are passed explicitly. `CoreSign/001` uses the BBS-12 `api_id` and must reproduce the BBS draft's multi-message signature. |
| `CoreProofGen`, `CoreProofVerify` | 3.6.3, 3.6.4 | Index-validation cases; `CoreProofVerify/001` is a valid mixed proof. |
| `ProofInit` | 3.7.1 | The signature is passed as octets: decode it with `octets_to_signature`, and return `INVALID` if decoding fails. The output is `init_res` with fields `A_bar`, `B_bar`, `D`, `T1`, `T2`, `domain`, `C_tildes`. |
| `ProofFinalize` | 3.7.2 | `initRes` is given in the same field form. |
| `MessagesToScalars` | 4.1.2 | |
| `PresentationContext` | 4.1.5 | |
| `HashToScalar` | 4.2.2 | A 256-octet `dst` must abort. |
| `CreateGenerators` | 4.1.1 | The commitment generators are `create_generators(2, "COM_DIS_" \|\| api_id)`. |
| `OctetsToProof` | 4.2.4.4, 4.2.4.5 | The output is `proof_to_octets(octets_to_proof(x))`. Negative cases must return `INVALID`. |

## 7. Mocked randomness

Proof fixtures are deterministic only if your `calculate_random_scalars` is replaced, for that fixture, by this stream:

```
SEED = mockedRng.seed     (32-octet ASCII "3.141592653589793238462643383279")
dst  = mockedRng.dst      (= api_id || "COM_DIS_MOCK_RANDOM_SCALARS_DST_")
k    = 0 at the start of every fixture

calculate_random_scalars(count):
  k = k + 1
  if count == 0: return ()                     (k is still consumed)
  if count * 48 > 65535: ABORT
  out = expand_message(SEED || I2OSP(k, 8), dst, count * 48)
  return (OS2IP(out[48*i .. 48*i+47]) mod r  for i in 0 .. count-1)
```

`expand_message` is the suite's own: XMD/SHA-256 or XOF/SHAKE-256.

If `mockedRng.overrides` is present, then after computing call `k`, replace scalar `index` with `value` for each entry whose `call` equals `k`. This is used only by the injected `r1 = 0` and `r2 = 0` cases.

**Call order is part of the fixture.** `ProofGen` and `CoreProofGen` draw, in this order:

1. `commitment_rands` (`N` scalars), only when `precomputed_rands` is `NONE`;
2. `random_scalars` (`5 + U`);
3. `s_tildes` (`N`).

This is the order of spec 3.6.3. `PrecomputeCommitment` draws once (`N`).

Appendix B of v0.7 defines this stream as informative test machinery. The SEED is pi truncated to 30 decimal places (31 digits plus the decimal point), encoded as the exact 32-octet ASCII string above. The suite expander's own limits also apply. Deterministic streams and hash-output overrides must not be enabled in normal operation.

## 8. Conventions you must match

These are runner-level choices the spec leaves to the caller.

- **Caller-supplied points** arrive as compressed octets. Spec 4.2.4.6 applies the same acceptance conditions to them as to decoded points.
  - `ProofVerify` and `CoreProofVerify` commitments: decode with identity excluded. A point that fails to decode makes the operation return `INVALID`.
  - Generators, `init_res` points and `PresentationContext` commitments: decode with identity allowed. The procedure then decides; for example, `presentation_context` rejects an identity commitment, and `valid_generators` rejects identity and `P1`.
- **Indexes** are JSON integers, apart from the non-integer negative cases in Section 5.
- **Index outputs** do not occur. Every output is octets, scalars or points.

## 9. Review boundaries

The implementation follows the explicit v0.7 checks: failed proof subroutines and generator derivations propagate `INVALID`, and indexes must be integers. `L = 0` is deliberately allowed by the profile's `calculate_domain`, unlike BBS-12.

Frozen JSON cases cover the supplied outcomes and traces. `src/exceptional_hash_tests.rs` supplements them for both suites with injected zero derived keys, exceptional signature scalars (`e = 0` and `SK + e = 0`), zero generated or recomputed challenges, and zero final responses. These tests check propagation through interface operations, absence of partial outputs, invocation targeting, and successful controls before and after injection. The hash override is compiled only for tests. `tests/profile_roundtrip.rs` adds local disclosure-pattern, precomputation, commitment, context and randomness-failure checks.

The spec contains review notes on construction and integration assumptions. Read those notes and `REVIEW_NOTES.md` when assessing guarantees; fixture agreement cannot resolve them. The source defects in the BBS vector text are recorded in `fixtures/bbs/SOURCE.md` and Section 10 below.

## 10. The BBS cross-check

The fixtures in `fixtures/bbs/` use the BBS-12 `api_id = ciphersuite_id || "H2G_HM2S_"` and octet-string messages only. Reproduce:

- the key pair. `keyDst` is given explicitly in the fixture.
- the mapped scalars, the 11 generators, `hash_to_scalar`, and the draft's own Section 8.1 mock (`seeded_random_scalars`). That mock restarts on every call and is used only here.
- every signature vector. Valid ones must re-sign exactly. Invalid ones must fail `CoreVerify`. Check the `B` and `domain` trace values too.
- every proof vector, but only through `ProofInit`. The profile's challenge and encoding differ from BBS by design. So:
  1. call `ProofInit` with no commitments, using `seeded_random_scalars(SEED, DST, 5 + U)`;
  2. check `T1`, `T2` and `domain`;
  3. check `A_bar`, `B_bar` and `D` against the first 144 octets of the proof.
  
  The draft's D.2.2.1 lists no `T1`/`T2` (a defect in the draft), so check only the rest of that vector.

## 11. Reporting results

Report:

- **Counts:** pass and fail, per suite and per operation, for both fixture sets.
- **Each failure:** the fixture path, expected versus actual, and the first diverging `trace` field:
  - `messageScalars`, then `domain`, `commitments`, `A_bar`, `B_bar`, `D`, `T1`, `T2`, `C_tildes`, `challenge` for proofs;
  - `messageScalars`, then `domain`, for signatures.
- **Classification of each failure:**
  - **your bug** — fix it;
  - **spec ambiguity** — give the section, the exact text, the two readings, and which one the fixture assumes;
  - **suspected fixture bug** — explain why your reading follows the spec.
- **Parse-failure cases:** the fixtures satisfied by mapping a parse failure to `INVALID` (Section 5).
- **Review boundaries:** local exceptional-value tests run, any omitted suites or tests, and the limitations relevant to your results (Section 9).

Report specification disagreements to the spec author with the section, exact text, observed behavior and proposed resolution. Preserve the supplied specification, fixture JSON and manifests. Any proposed fixture change needs explicit review and a documented effect on interoperability; do not silently regenerate or relabel it.
