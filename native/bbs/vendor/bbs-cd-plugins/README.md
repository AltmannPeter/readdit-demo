# bbs-cd-plugins

BBS credentials with **committed disclosures** (ETSI working draft v0.7) as a core, and
**plugins** that prove statements about committed attributes inside the same
presentation.

Plugins:
- **`ecdsa-pop`** binds a credential to a hardware key: the credential holds a P-256
  device public key, and a presentation proves that this key signed the request, without
  revealing the key.
- **`date-range`** proves that a committed date, such as the birth date, lies in the range
  the verifier asks for (`ge`, `le` or both, as YYYYMMDD), without revealing it: any age
  threshold or age range from one credential.
- **`pseudonym`** reveals a per-relying-party pseudonym computed from a committed seed,
  and proves it came from the signed seed. Version 0.1 supports the configuration
  `known-offender-matching-ssc`: an issuer-known seed (the issuer can map a pseudonym
  back to the person) and the relying party's identifier from its access certificate.

Pseudonyms from a seed the issuer doesn't know need blind issuance, which the framework
reserves but doesn't implement yet (see `docs/DESIGN.md` §14). Deployment requirements
(shared issuer keys and schemas, verifier randomness, nonces, pseudonym identifiers) are
in `docs/DESIGN.md` §13.

> **Research code.** Not constant-time, not audited, not for production. The security
> arguments are informal and await review by cryptographers.

## Crates

| Crate | What it is |
|---|---|
| `crates/bbs-cd` | ETSI BBS committed disclosures v0.7, reference implementation with its conformance tests, and output-preserving performance changes (see its README) |
| `crates/bbs-cd-plugin` | the framework: typed schemas, issuer, request, presentation envelope, plugin traits, single-use nonces |
| `crates/cd-tom256` | toolkit for statements over P-256: Tom-256, BLS12-381 → Tom-256 transfer, scalar-multiplication, point-addition and on-curve proofs, batch verification |
| `crates/cd-ecdsa-pop` | the `ecdsa-pop` plugin: hashed mode (default) and raw mode (feature `raw-mode`) |
| `crates/cd-date-range` | the `date-range` plugin: `date-packed` dates, range proof on the committed date |
| `crates/cd-pseudonym` | the `pseudonym` plugin: issuer-known seed, pseudonym per relying party |

A plugin that works in the BLS12-381 scalar field (date range, pseudonym) needs only
`bbs-cd-plugin`. The smallest template is the `example-eq` plugin in
`crates/bbs-cd-plugin/tests/common/mod.rs`; `cd-date-range` is a complete one.

## Quick start

Requires Rust 1.85 or later.

```sh
cargo test --release --workspace --all-features         # all tests (raw mode and attack tests included)
cargo run --release -p cd-ecdsa-pop --example quickstart  # issue, present, verify
cargo run --release -p cd-date-range --example age-check  # device binding + 18+ in one presentation
```

`crates/cd-ecdsa-pop/examples/quickstart.rs` is the whole flow in about 80 lines:

```rust
let slot = prepare_credential(&cred, &["device_key"], &mut OsRng)?;           // offline
let input = slot.committed_input(&cred, 0, "device_key")?;
let plugin_slot = prepare(&input, &params, 4, Parallelism::Off, &mut OsRng)?; // offline
let prover = EcdsaPopProver::new(plugin_slot, Signer::Hash(&device));
let presentation = present(&request, &[&cred], vec![slot],
                           vec![Box::new(prover) as Box<dyn PluginProver>], &mut OsRng, None)?;

let verifier = Verifier::new().register(Box::new(EcdsaPopVerifier::new()));
let verified = verifier.verify(std::slice::from_ref(&issuer.params), &request, &presentation, None, None)?;
```

## Build options

| Feature (crate) | Effect |
|---|---|
| `parallel` (`cd-ecdsa-pop`, `cd-tom256`, `bbs-cd-plugin`) | rayon worker pool for preparation and verification; outputs are identical for every thread count |
| `raw-mode` (`cd-ecdsa-pop`) | enables the raw-signing mode; verifiers accept it only with this feature |
| `insecure-test-controls` (`cd-ecdsa-pop`, `cd-tom256`, `cd-date-range`, `cd-pseudonym`) | intentionally vulnerable variants and malicious-holder hooks for the attack tests; never enable in a build you ship. Only the attack-test targets require it (`required-features`), so examples, binaries and ordinary builds never contain it; it does not turn on `raw-mode` |

## Checks and benchmarks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --release --workspace                         # default features: skips raw-mode and attack tests
cargo test --release --workspace --all-features
bash crates/bbs-cd/ci/check.sh stable          # ETSI conformance reports

cargo run --release -p bbs-cd-plugin --example cd-bench -- --n 30 --out results/now.tsv
cargo run --release -p cd-ecdsa-pop --features raw-mode,parallel --bin ecdsa-pop-bench -- --n 20
cargo run --release -p cd-date-range --bin date-range-bench -- --n 30 --out results/date-range.tsv
cargo run --release -p cd-date-range --features cd-ecdsa-pop/parallel --example full-flow-bench -- --n 20 --threads max
```

- **`cd-bench`** measures the committed-disclosure core alone: Sign, Verify,
  PrecomputeCommitment, ProofGen, ProofVerify and proof decoding, for credential
  shapes `--shapes L:C:D,...` (L messages, the first C committed, the next D
  disclosed; default `10:6:1,40:6:10,128:6:60`). `--out FILE` writes a TSV;
  `--compare FILE` prints the change against an earlier run. The `primitives`
  lines are library costs that the code doesn't change, so they serve as a noise
  check.
- **`ecdsa-pop-bench`** measures the plugin end to end: offline preparation,
  online proving and verification times and the presentation size, for each
  mode. Options: `--n`, `--limb-bits {64,96,128}`,
  `--profile {shared-bit,separate-pa}`, `--threads {off,max,N}` (needs
  `parallel`), `--out FILE`.
- **`date-range-bench`** measures the date-range plugin: the one-time generator-table
  build, proof and verification times and sizes for an 18+ threshold, an "under 50"
  threshold and a range, and one full presentation (BBS proof + plugin). `--out` and
  `--compare` work as in `cd-bench`.
- **`full-flow-bench`** measures one complete presentation on one credential: the ETSI
  BBS proof, `ecdsa-pop` (hashed mode), `date-range` (18+ by default; `--le`, `--ge`
  take YYYYMMDD) and `pseudonym` (`known-offender-matching-ssc`), each part timed on the holder (offline and online) and the verifier,
  with the presentation size per part. Options: `--n`, `--limb-bits`, `--threads`
  (ecdsa-pop only; needs `--features cd-ecdsa-pop/parallel`), `--out`, `--compare`.

Results go to `results/`, which is not committed.

## Documentation

| Document | Contents |
|---|---|
| `docs/DESIGN.md` | architecture, plugin model, holder and verifier flows, future plugins |
| `docs/ENVELOPE.md` | framework specification: encodings, ctx, ph, statements, presentation, algorithms |
| `docs/plugins/ECDSA-POP.md` | `ecdsa-pop` specification: both modes, encodings, challenges, sizes, security notes |
| `docs/plugins/DATE-RANGE.md` | `date-range` specification: date encoding, request parameters, range proof, sizes, security and privacy notes |
| `docs/plugins/PSEUDONYM.md` | `pseudonym` specification: seed type, configurations, pseudonym, proof, holder rule for the relying-party identifier, privacy notes |
| `docs/OPTIMIZATIONS.md` | performance options and their status |
| `docs/reference/` | background from the DEVBIND prototype: 0.3.1 report, hashed-mode experiment, implementation decisions, ETSI integration |
| `crates/bbs-cd/README.md` | the ETSI core and its conformance fixtures |

The ETSI draft text is not redistributed. A local copy at
`crates/bbs-cd/spec/etsi-bbs-committed-disclosures-v0.7.md` is ignored by git.

## Status

Version 0.1:
- framework, `ecdsa-pop` (both modes), `date-range`, `pseudonym` and the example plugin
  implemented and tested;
- the committed-disclosure core has output-preserving performance changes on the
  holder and verifier paths, with the supplied conformance fixtures unchanged
  (`crates/bbs-cd/README.md`);
- no external test vectors for the framework or the plugin yet;
- wire formats are new; presentations are not compatible with DEVBIND 0.3.1.

## License

MIT (`LICENSE`). Third-party material and its licenses: `THIRD_PARTY_NOTICES.md`.
