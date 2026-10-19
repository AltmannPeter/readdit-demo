# Security review of `bbs-cd-plugins`

Reviewed 2026-10-18 against the threat model and goals G1–G5 in the review request. The review traced the BBS proof and committed-disclosure boundary, framework request and envelope binding, and the three plugin verifier paths from source. **No reportable break was confirmed under the clarified deployment assumptions.** Every issued attestation must be publicly registered in a catalogue that enforces a shared schema ID and issuer key for each anonymity set, and wallets check that rule. This catalogue is outside the repository and was not independently reviewed. This is a bounded adversarial code review, not a proof of the protocols: the added deterministic parser and mutation tests cover the cases described below, not all byte strings or all cryptographic transcripts. The known and accepted behaviors in the request are not repeated as findings.

| ID | Severity | Component | Title |
|---|---|---|---|
| — | — | — | No reportable findings under the clarified deployment assumptions |

## Findings

No finding met the stated threshold after the catalogue enforcement rule was supplied.

**Deployment boundary tested:** `colluding_issuer_can_tag_holders_with_distinct_schema_ids` in `crates/cd-ecdsa-pop/tests/review_issuer_tag.rs` demonstrates that the library, in isolation, can issue two credentials under one key with distinct schema IDs and that a verifier can distinguish them through `CredentialRequest::schema_digest` (`crates/bbs-cd-plugin/src/request.rs:18`). Run `cargo test --release -p cd-ecdsa-pop --test review_issuer_tag`. Under the clarified deployment rule, those per-holder schemas are rejected by the catalogue and wallet, so the test does **not** demonstrate a reachable G3 break. The catalogue and wallet checks are external to this workspace and were not tested here.

The intentionally vulnerable raw-mode control is compiled in some test and all-targets builds, but the normal `EcdsaPopVerifier` calls the candidate verifier with `Q′` in the signed hash; accepting the control attack requires explicitly registering the separate `VariantVerifier(VulnerableControlNoQprime)`. The existing `retained_signature_scaling_breaks_control_but_not_candidate` and `zero_query_forgery_breaks_control_only` tests show that distinction. This is a build and API exposure worth controlling, but it is not a demonstrated break of G1–G5 by a correctly configured verifier.

## Checked and found sound within the reviewed paths

- **Core point validation:** `decode_G1` checks canonical encoding, curve, subgroup and identity policy (`crates/bbs-cd/src/primitives.rs:58`); `octets_to_proof` bounds dimensions before allocation and decodes all external proof points (`crates/bbs-cd/src/utils.rs:494`). The internal `*_in_g1` paths consume decoded or validated points, and the cached-generator path compares the whole vector against the suite/API-specific cache before skipping repeated subgroup checks (`crates/bbs-cd/src/helpers.rs:228`).
- **Core arithmetic and G5:** the Straus MSM uses complete projective operations and canonical scalar windows (`crates/bbs-cd/src/helpers.rs:198`); the combined Miller loop checks the same pairing product (`crates/bbs-cd/src/core.rs:25`); B is reused only after a domain equality check (`crates/bbs-cd/src/core.rs:267`). The existing adversarial arithmetic, reconstructed-verifier, pairing, B-reuse and conformance tests passed, including 336 profile cases. I did not reconstruct a separate complete, unoptimized verifier for every possible mutated proof.
- **Framework binding:** `Request::context` includes audience and the length-delimited credential and plugin request body; `presentation_header` adds the nonce (`crates/bbs-cd-plugin/src/request.rs:189`). The credential statement includes issuer key, schema header, disclosures, committed indexes and commitment bytes (`crates/bbs-cd-plugin/src/envelope.rs:50`). `Verifier::verify` verifies BBS before constructing plugin views, and `ProofVerify` compares caller-supplied commitments with those decoded from the proof (`crates/bbs-cd-plugin/src/envelope.rs:490`, `crates/bbs-cd/src/interface.rs:135`).
- **Framework parsing and issuer:** request, schema and envelope counts and lengths are bounded; trailing bytes are rejected (`crates/bbs-cd-plugin/src/request.rs:208`, `crates/bbs-cd-plugin/src/schema.rs:177`, `crates/bbs-cd-plugin/src/envelope.rs:336`). The issuer checks handler output count, bit width and scalar canonicality before signing (`crates/bbs-cd-plugin/src/issuer.rs:237`). The new `review_parsers` test sampled 2,048 arbitrary lengths through four decoders without a panic and rejected a one-bit change at every byte of a valid simple envelope.
- **Nonce lifecycle:** `VerifierSession::accept` removes the nonce before verification and checks expiry (`crates/bbs-cd-plugin/src/session.rs:76`); the API requires `&mut self`, so concurrent acceptance through one session needs caller synchronization.
- **ECDSA mode and binding:** the signed hashed-mode message includes the envelope, request nonce, plugin position, parameters and limb commitments (`crates/cd-ecdsa-pop/src/hashed.rs:44`, `crates/cd-ecdsa-pop/src/common.rs:204`). The raw candidate includes `Q′` (`crates/cd-ecdsa-pop/src/raw.rs:146`, `crates/cd-ecdsa-pop/src/raw.rs:282`). Attribute type fixes the permitted mode and layout (`crates/cd-ecdsa-pop/src/common.rs:36`); `EcdsaPopVerifier::verify` repeats request checks and uses the candidate raw verifier (`crates/cd-ecdsa-pop/src/lib.rs:194`). Existing malicious tests rejected off-curve, wrong-key, wrong-SM, U1-identity and replay/control attacks on the normal verifier.
- **Tom-256 transfer and batching:** verifier-controlled transfer settings enforce `z_bits <= 254` and at least 128 challenge bits across repetitions (`crates/cd-tom256/src/config.rs:63`). The parser checks transfer response ranges, canonical points and scalars before verification (`crates/cd-ecdsa-pop/src/common.rs:331`). Batch weights are 128 bits from verifier RNG, drawn after parsing; parallel SM weights are drawn before parallel work (`crates/cd-tom256/src/batch.rs:43`, `crates/cd-ecdsa-pop/src/common.rs:507`). Existing batch-versus-individual and parallel-verdict tests passed. These tests do not replace a formal soundness proof for the transfer, PA or SM arguments.
- **Date range:** schema type and width are checked before `DateRangeParams::bounds`; `lo`, `hi`, parameters, env, nonce, D and all digit proof points enter the challenge (`crates/cd-date-range/src/lib.rs:133`, `crates/cd-date-range/src/lib.rs:149`). The verifier checks the weighted sum and recomputed bit relations (`crates/cd-date-range/src/range.rs:234`). The new `review_params` test sampled malformed parameter bytes and checked representation and maximum sums for every N from 1 to 4,096 and the boundaries 2^16 and 2^31 ± 1 through `u32::MAX`. Existing tests compared fixed-base and batch encoding against plain multiplication/encoding, including identity points.
- **Pseudonym:** the accepted configuration and identifier are strictly decoded; the holder checks the identifier supplied from the access certificate; the verifier can enforce its own identifier and repeats `check_request` inside `verify` (`crates/cd-pseudonym/src/lib.rs:140`, `crates/cd-pseudonym/src/lib.rs:278`, `crates/cd-pseudonym/src/lib.rs:297`). The proof challenge binds D, nym, OP-derived parameters, env, nonce and plugin position, and decoding rejects identity nym (`crates/cd-pseudonym/src/lib.rs:166`, `crates/cd-pseudonym/src/lib.rs:312`). Type checks prevent using date-range on a seed or pseudonym on a date.
- **Randomness:** holder masks and openings use independent wide samples; verifier batch weights use its RNG; the fallback verifier RNG is seeded from `OsRng` (`crates/bbs-cd-plugin/src/envelope.rs:34`, `crates/bbs-cd-plugin/src/envelope.rs:506`). The stated assumption of unpredictable verifier RNG is essential to the batch bound.

### `insecure-test-controls` build trace

| Build | `cd-ecdsa-pop` effective features | Verifier consequence |
|---|---|---|
| `cargo build -p cd-ecdsa-pop` or its ordinary examples/bench binary without extra features | `default` | Hashed mode only; test controls absent. |
| Ordinary build with `--features raw-mode,parallel` | `default,raw-mode,parallel` | Candidate raw verifier available; test controls absent. |
| `cargo test -p cd-ecdsa-pop` | `default,insecure-test-controls,raw-mode` through the self dev-dependency | Test-only malicious prover and `VariantVerifier` API compiled. Normal verifier still uses the candidate. |
| `cargo build --workspace --all-targets` | `default,insecure-test-controls,raw-mode` through the self dev-dependency | Same test API is compiled into the build; `EcdsaPopVerifier::new()` also defaults to permitting valid raw-mode requests because `raw-mode` is active. |
| `--all-features` | Includes `insecure-test-controls` and `raw-mode` | Same test API; normal verifier still uses the candidate. |
| `cargo test -p cd-date-range` or `cargo test -p cd-pseudonym` | Their dependency on `cd-ecdsa-pop` requests only `default` | Their dev-dependencies do not activate `cd-ecdsa-pop`'s own self dev-dependency. |

The feature graph is in `crates/cd-ecdsa-pop/Cargo.toml:10` and `:37`; the all-targets result was checked against Cargo's generated library fingerprint. Only explicit registration of `raw::insecure_test_controls::VariantVerifier(VulnerableControlNoQprime)` changes the raw verification equation. The normal `EcdsaPopVerifier` always selects `HMode::Candidate` (`crates/cd-ecdsa-pop/src/lib.rs:209`). The benchmark binary constructs this normal verifier, so compiling it with the test feature does not select the broken predicate.

## Verification run

- `cargo test --release --workspace` — passed.
- `cargo test --release --workspace --all-features` — passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — passed.
- `bash crates/bbs-cd/ci/check.sh stable` — passed; 336 profile cases, 0 failures.
- `cargo +1.85.0 test --locked --release --workspace` — passed.
- `cargo build --locked --workspace --all-targets` and `cargo fmt --all -- --check` — passed.
- New tests: `cargo test --release -p bbs-cd --test review_proof_decode`; `cargo test --release -p bbs-cd-plugin --test review_parsers`; `cargo test --release -p cd-date-range --test review_params` — passed. They are separate files under each crate's `tests/` directory.
- `cargo test --release -p cd-ecdsa-pop --test review_issuer_tag` — passed; demonstrates the code-level schema-tagging boundary with mandatory device binding, outside the enforced catalogue policy.

## Open questions for the authors

1. Can release packaging exclude `insecure-test-controls` artifacts built with `--all-targets` or `--all-features`, and keep the test-only `VariantVerifier` out of production plugin registries? The normal verifier did not accept the control attack, but the exported test verifier is deliberately unsound.
2. Which certificate field and canonical encoding supply `PseudonymProver::new` and `PseudonymVerifier::for_verifier` in deployments? The library accepts opaque identifier bytes, so cross-party isolation relies on that wallet/profile mapping.
3. Can the authors provide independent external vectors or a formal argument for the plugin transfer, PA and SM compositions? The repository tests check many attacks and equivalences, but they are not an independent proof of G1 or G3.
