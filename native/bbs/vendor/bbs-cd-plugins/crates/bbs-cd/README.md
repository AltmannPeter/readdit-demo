# bbs-cd: BBS committed-disclosure reference implementation

Core crate of the `bbs-cd-plugins` workspace. The code is the standalone
`bbs-committed-disclosures-rust-v0.7` package, with the packaging helper, the
standalone CI workflow and the bundled draft text removed, and performance
changes (October 2026) that keep every output and every acceptance condition:

- **Faster multiplication on the holder and verifier paths.** `CoreVerify`,
  `ProofInit`, `ProofVerifyInit` and `compute_commitments` compute every sum
  of scalar multiples with `helpers::msm_vartime`: Straus' method with shared
  doublings, plain unsigned 4-bit windows and only the curve library's
  complete projective addition, so adversarial points and scalars from a
  proof have no exceptional cases. Single products use the library's wNAF
  (`group::Wnaf`). Both are variable-time. The issuer's `CoreSign` keeps the
  constant-time multiplication. `helpers::msm_vartime` and
  `helpers::mul_vartime` are public, for plugins (`cd-date-range` uses them).
- **Subgroup checks once per point.** Each external point is checked once, at
  decoding or at the public entry point. Cached generators (from
  `create_generators`) and points the crate computes from checked points are
  not re-checked. The public functions (`serialize`, `calculate_domain`,
  `presentation_context`, `valid_proof_tuple`, `proof_to_octets`, the `Core*`
  operations) keep their full checks. Internal variants (`*_in_g1`,
  `valid_generators_cached`) are used where the provenance is known, and
  assert the condition in debug builds.
- **One pairing product and B computed once.** The two pairing checks use one
  combined Miller loop and a single final exponentiation (identical verdict).
  `CoreProofGen` reuses B from its mandatory signature check in `ProofInit`.
  The domain is still computed in both places, as the spec requires, and B is
  reused only when the two domains are equal. No state is kept between calls.

The supplied fixtures pass unchanged. `src/optimization_tests.rs` checks that
the fast paths equal the code they replace, on adversarial scalars, points and
malformed proofs, and that every public entry point still rejects points
outside G1. To measure the core alone, run
`cargo run --release -p bbs-cd-plugin --example cd-bench` from the workspace
root.

An independent Rust implementation of the **ETSI BBS committed-disclosure
profile, working draft v0.7**, for interoperability testing and review.
Both BLS12-381-SHA-256 and BLS12-381-SHAKE-256 are implemented, with BBS-12 as
the pinned normative baseline.

**This implementation is not constant-time and is not for production use.**
Passing the tests establishes agreement with the supplied cases, not a security
proof or security audit.

## Start here

- Read the ETSI BBS committed-disclosure profile, working draft v0.7 (the draft text is not redistributed here; a local copy at `spec/etsi-bbs-committed-disclosures-v0.7.md` is ignored by git).
- Follow [IMPLEMENTERS.md](IMPLEMENTERS.md) to check another implementation
  against the fixtures.
- Read [REVIEW_NOTES.md](REVIEW_NOTES.md) for review boundaries, known limitations,
  and how to report a discrepancy.
- See [fixtures/README.md](fixtures/README.md) for fixture encodings, randomness,
  and coverage.

## Run the checks

Install Rust 1.85 or later with Cargo, rustfmt, and Clippy. From the repository
root, run:

```sh
cargo test --locked
```

For the complete CI check, including formatting, Clippy, and saved conformance
reports:

```sh
bash ci/check.sh stable
# Also test the minimum supported Rust version, if installed:
bash ci/check.sh 1.85.0
```

The Makefile provides equivalent `make test`, `make check`, `make fmt`, and
`make ci-check` commands. No Python installation is needed to build the crate or
run the Rust tests. Cargo downloads the locked dependencies on the first run.

The suite currently contains **67 Rust tests** and exercises:

| Checks | SHA-256 | SHAKE-256 | Total |
| --- | ---: | ---: | ---: |
| Profile fixtures | 168 | 168 | 336 |
| BBS vector cases | 19 | 19 | 38 |
| RFC 9380 vectors | 25 | 10 | 35 |

The vectors run within the Rust tests, rather than as separate test functions.
Profile checks compare exact outputs, private opening outputs, and 726 supplied
positive trace fields. Exceptional-hash tests use scoped test-only substitution.
BBS proofs are checked through their shared initialization; their full transcript
and encoding intentionally differ from this profile.

To run a narrower check:

```sh
cargo test --locked --lib profile_vectors::all_profile_fixtures -- --exact --nocapture
cargo test --locked --lib bbs_vectors -- --nocapture
cargo test --locked --lib exceptional_hash_tests
cargo test --locked --test profile_roundtrip
cargo test --locked --test rfc9380
```

## Specification and fixture versions

The specification is v0.7. The frozen profile fixtures retain their original
`specVersion: "v0.5"` metadata: v0.6 and v0.7 preserve the relevant protocol
outputs and encodings. The metadata records provenance and is not a request to
use an older specification. Fixtures have not been regenerated or relabelled.
Their SHA-256 manifest is checked on every fixture-suite run.

The BBS vector source is retained under [fixtures/bbs/source/](fixtures/bbs/source/).
Its draft revision is 13, used only as a source of vectors applicable to the
BBS-12 baseline; see [SOURCE.md](fixtures/bbs/SOURCE.md).

## Working with the code

The library is named `bbs_cd`. Public entry points in `interface` include
`KeyGen`, `SkToPk`, `Sign`, `Verify`, `ProofGen`, `ProofVerify`, and
`PrecomputeCommitment`. Function names and section references follow the spec.

Outcomes use `Result<T, BbsError>` with distinct `Invalid` and `Abort` variants.
Successful verification is `Ok(())`. Scalars, message types, disclosure states,
and indexes have explicit representations in `types`. Serialization fields
are explicitly typed. See the round-trip tests for complete API examples.

`ProofGen` returns the encoded proof and private `add_zkp_info`; the latter is
not part of the transmitted proof. `ProofVerify` takes the caller's expected
commitments. The Section 3.7 proof-state subroutines are internal to the crate;
the fixture harness can exercise them in test builds.

`ProofGen` and `PrecomputeCommitment` accept an optional `ScalarSource`; `None`
selects OS randomness. The public `mock_rng` module is fixture machinery.
It implements the advancing Appendix B stream and the separate BBS mock.

| Directory | Contents |
| --- | --- |
| `spec/` | Local copy of the ETSI draft (git-ignored, not distributed) |
| `src/` | Rust implementation and internal conformance tests |
| `tests/` | Round trips, RFC vectors, and fixture provenance manifest |
| `fixtures/` | Frozen profile and BBS cases, format guide, BBS source |
| `ci/` | Shared local and CI check script |

## CI and reports

In this workspace the repository-level CI runs `ci/check.sh` for this crate.

Reports are written to `target/conformance/<toolchain>/`:

- `profile.json`: all 336 profile cases, outcomes, and first-divergence details;
- `bbs-sha256.json` and `bbs-shake256.json`: all 19 BBS cases per suite;
- `check.log`: the complete check output.

A failed test, missing report, malformed fixture, or changed frozen fixture
causes a failure. Logs and reports should accompany review findings.
