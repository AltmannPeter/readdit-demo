# Fixtures

Two sets of frozen fixtures live here:

- `bbs/`: BBS vectors extracted from the draft text bundled at `bbs/source/draft-irtf-cfrg-bbs-signatures-13.txt`. `bbs/SOURCE.md` records its SHA-256 digest, source sections and known source defects. These vectors cross-check the BBS-12 baseline; the draft's later number does not change that baseline.
- `profile/<ciphersuite>/<Operation>/NNN_description.json`: 336 profile cases, 168 per suite across 17 operations, supplied from the original Python reference implementation.

This Rust package targets the ETSI CD working draft v0.7 (not redistributed here). The profile cases retain `specVersion: "v0.5"` because that is their generation provenance. The v0.7 specification's Section 5 states that they remain valid unchanged. Their JSON bytes and the SHA-256 digests in `tests/data/profile_manifest.json` are preserved. No fixture generator is bundled in this standalone package.

## Running the fixtures

From the repository root:

```sh
cargo test --locked
cargo test --locked profile_vectors::all_profile_fixtures -- --nocapture
cargo test --locked bbs_vectors:: -- --nocapture
```

The Rust runner in `src/profile_vectors/` checks the complete directory against the manifest, metadata and per-operation counts before comparing outputs and positive trace values. It distinguishes `INVALID`, `ABORT`, input-decoding rejection and malformed harness data. It prints one PASS or FAIL line per case and per-suite/per-operation totals. Set `BBS_PROFILE_REPORT` to a file path to save its JSON report.

For a runner in another language, use the JSON contract below and `IMPLEMENTERS.md` Sections 5–11. No Python adapter or external workspace is required.

## File format

```json
{
  "caseName": "…", "specVersion": "v0.5", "baseline": "BBS-12",
  "ciphersuite": "BLS12-381-SHA-256", "operation": "ProofGen",
  "input": { … },
  "mockedRng": { "seed": "…", "dst": "…", "overrides": [ … ] },
  "trace": { … },
  "expected": { … }
}
```

**Encodings**

| Value | JSON form |
| --- | --- |
| Octet string | Lowercase hex, no `0x` prefix. |
| Scalar | 32-octet big-endian lowercase hex. |
| Point | Compressed encoding (`point_to_octets_E1`/`E2`), hex. |
| Message | An octet-string message is a hex string. A scalar message is `{"scalar": "<64 hex>"}`. The JSON form records what kind of value the caller supplies, so type-mismatch cases can be expressed. Whether the call accepts it is decided by `messageTypes`. |
| Message type, disclosure state | `"OCTETS"`, `"SCALAR"`, `"DISCLOSE"`, `"COMMIT"`, `"HIDE"`. Unknown values such as `"UNKNOWN"` appear in negative cases. |
| Indexes | JSON numbers. A non-integer such as `1.5` appears in negative cases. |

Interface operations (`Sign`, `Verify`, `ProofGen`, `ProofVerify`, `PrecomputeCommitment`) use the profile `api_id = ciphersuite_id || "H2G_HM2S_S2S_"`, which is recorded as `trace.apiId`. Core operations and utilities take `apiId` explicitly.

`expected` takes one of four forms:

- `{"output": …}` for a successful generation. `ProofGen` also has `addZkpInfo` (`committedMessages`, `commitmentRands`), which is Prover-local and never sent to a Verifier.
- `{"result": {"valid": true|false, "reason": …}}` for verification. Verification returns `VALID` or `INVALID`.
- `{"result": {"valid": false, "reason": …}}` for a generation or utility that returns `INVALID`.
- `{"abort": true}` for `ABORT`.

Negative cases are made by mutating a positive case, and `reason` says what was changed.

**`trace`** holds intermediate values for locating a divergence:

- message scalars and `domain`;
- for proofs: the index vectors, committed scalars, every random vector drawn (`commitmentRands`, `randomScalars`, `sTildes`), `commitments`, `A_bar`, `B_bar`, `D`, `T1`, `T2`, `C_tildes` and `challenge`.

### Operations

| Operation | Inputs |
| --- | --- |
| `KeyGen` | `keyMaterial`, `keyInfo` → `{SK, PK}` |
| `Sign` / `Verify` | `SK`, `PK`, `header`, `messages`, `messageTypes`, `signature` |
| `ProofGen` | `PK`, `signature`, `header`, `presentationHeader`, `messages`, `messageTypes`, `messageDisclosures`, `precomputedRands` (`null` = `NONE`) |
| `ProofVerify` | `PK`, `proof`, `header`, `presentationHeader`, `disclosedMessages`, `commitments`, `messageTypes`, `messageDisclosures` |
| `PrecomputeCommitment` | `committedMessages`, `commitmentIndexes`, `messageTypes` → `{commitments, commitmentRands}` |
| `CoreSign` / `CoreVerify` | `SK`, `PK`, `generators`, `header`, `messageScalars`, `apiId` |
| `CoreProofGen` / `CoreProofVerify` | as the spec, with explicit `generators`, index vectors and `apiId` |
| `ProofInit` | `signature` octets (decoded with `octets_to_signature`), `randomScalars`, `sTildes`, … → `init_res` |
| `ProofFinalize` | `initRes`, `challenge`, `eValue`, … |
| `MessagesToScalars`, `PresentationContext`, `HashToScalar`, `CreateGenerators`, `OctetsToProof` | the utility's inputs; `OctetsToProof` outputs `proof_to_octets(octets_to_proof(x))` |

Caller-supplied points (commitments and generators) must pass the decoding checks of spec 4.2.4.6. A point that fails them makes the operation return `INVALID`. Commitments must not be the identity; generators, `init_res` points and `presentation_context` inputs may be, and the procedure itself then decides.

## Mocked randomness

Proof generation and `PrecomputeCommitment` are randomized. Each such fixture replaces `calculate_random_scalars` (spec 4.2.1) with this advancing stream:

```
SEED = h'332e313431353932363533353839373933323338343632363433333833323739'
       (32-octet ASCII "3.141592653589793238462643383279": pi truncated to 30 decimal places)
dst  = api_id || "COM_DIS_MOCK_RANDOM_SCALARS_DST_"   (api_id = the profile api_id)

call k (k = 1, 2, ... ; k restarts at 1 for each fixture) with argument count:
  if count == 0: return ()            (the call still consumes k)
  if count * expand_len > 65535: ABORT
  out = expand_message(SEED || I2OSP(k, 8), dst, count * expand_len)
  scalar i = OS2IP(out[i*expand_len .. (i+1)*expand_len - 1]) mod r
```

`expand_message` and `expand_len` (48) are the ciphersuite's own. Because of the call counter, the stream never restarts within a fixture, as spec 4.2.1 requires.

The order of calls is part of the fixture:

- `ProofGen`/`CoreProofGen` call it for `commitment_rands` (only when `precomputedRands` is `null`), then `random_scalars` (`5 + U`), then `s_tildes` (`N`).
- `PrecomputeCommitment` calls it once (`N`).

`overrides` (`[{"call": k, "index": i, "value": "<scalar>"}]`) replaces scalar `i` of call `k`. It is used only by the injected exceptional-randomness cases.

Appendix B of v0.7 defines this stream as informative test machinery. The underlying expander's output-length limits also apply. Deterministic sources and hash overrides must not be enabled in normal operation. The BBS vectors use their separate, restarting Section 8.1 `seeded_random_scalars` source.

## Spec Section 5 coverage

The table maps the supplied JSON cases for both suites. Injected hash outputs are covered by Rust tests in `src/exceptional_hash_tests.rs`, rather than by portable JSON cases. Local round-trip tests are in `tests/profile_roundtrip.rs`. These are checks of concrete cases, not an exhaustive rejection or security claim.

| Section 5 item | Where |
| --- | --- |
| Unchanged core signature results for supplied scalars, generators, header, `api_id` | `CoreSign/001` reproduces the BBS draft's multi-message signature; `CoreSign/002`, `CoreVerify` |
| `L = 0`, all disclosed, all hidden, all committed, mixed | `ProofGen/001–006` and their `ProofVerify` companions; `Sign/004` |
| A single committed scalar at index 0 and at the final index | `ProofGen` "single committed scalar …" |
| Zero and `r-1` scalars, repeated values, empty headers, nonempty `ph` | `MSGS8` in every mixed case; "empty header …"; "empty presentation header" |
| Nonzero unequal message and opening values, committed indexes separated by disclosed ones, empty vectors, cross-branch equal outputs | `ProofGen/001`, "empty message vector", "cross-branch …"; `MessagesToScalars` |
| Advancing deterministic random stream | `mockedRng` (above) |
| Mixed octet/scalar messages, committed octet strings, committed scalars at the first and last index, out-of-range scalar rejected | `ProofGen` "committed octet-string …", "committed scalars at the first and last index"; `Sign`/`Verify`/`ProofGen`/`PrecomputeCommitment`/`MessagesToScalars` "out-of-range …" |
| Type enforcement (unknown type at any position, including hidden or unselected and an empty selection; mismatch; wrong length at every operation; original-index subset checks) | `Sign`, `Verify`, `ProofGen`, `ProofVerify`, `PrecomputeCommitment` negatives; `PrecomputeCommitment` "subset with original indexes 1 and 3" |
| Context encoding | `PresentationContext/*` |
| Context binding in `ProofVerify` | `ProofVerify` "changed presentation header", "changed expected commitment", "reordered …", "changed committed-index assignment" |
| Precomputation equality, wrong opening counts, invalid scalars, wrong ordering, repeated values | `PrecomputeCommitment/*`; `ProofGen` "precomputed openings …", "wrong number of precomputed openings", "precomputed opening out of range" |
| Rejection of changed commitments, disclosure choices, disclosed messages, headers, public keys and commitment responses | `ProofVerify` negatives |
| Duplicate, unsorted, intersecting, noninteger and out-of-range core indexes | `CoreProofGen/*`, `CoreProofVerify/002–006` |
| Encoding round trips and rejections | `OctetsToProof/*`, plus `ProofVerify` "proof with identity A_bar" |
| Injected exceptional randomness and zero responses | JSON: `ProofGen/025–026` (`r1 = 0`, `r2 = 0`); `ProofFinalize/001`, where a chosen challenge and mask make a response zero. |
| Injected hash outputs and failure propagation | Local `src/exceptional_hash_tests.rs`: zero derived SK; `e = 0`; `SK + e = 0`; zero generated/recomputed challenge; zero final response; interface propagation, no partial outputs, targeted invocation and successful controls. Both suites; overrides exist only in test builds. |
| `U = 0` and `N = 0` | "all disclosed", "no commitments", "empty message vector" |
| `ABORT` on `Length(dst) > 255` and on invalid `undisclosed_indexes` in `ProofInit` | `HashToScalar/003`, `ProofInit/002` |
| Undecodable signatures, proofs and public keys | `Verify` "signature: …", "public key: …"; `ProofVerify` "public key undecodable"; `OctetsToProof` negatives |
