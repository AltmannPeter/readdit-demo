# Supplied profile fixture provenance

`profile_manifest.json` records the relative path and SHA-256 digest of every
supplied profile JSON case: 336 files, 168 per ciphersuite across 17 operations.
The snapshot was captured on 15 October 2026 before running the Rust profile
harness. At capture, all fixture files were compared by SHA-256 digest with the
supplied original corpus. This standalone package includes that complete corpus
and manifest; it requires no parent repository.

The cases were generated for v0.5 with the BBS-12 baseline. Their
`specVersion: "v0.5"` metadata records that provenance and is intentionally
unchanged. The implementation targets the ETSI CD working draft v0.7 (not redistributed here);
its Section 5 explains why the earlier cases remain valid without a wire-format
change. No supplied fixture or manifest digest was modified or regenerated.

The Rust runner independently enumerates the directory, requires an exact
manifest match, checks file hashes and metadata, and asserts per-suite and
per-operation counts. Positive supplied trace fields are also conformance
assertions; input-boundary rejections are inventoried separately.

The Rust profile operations were implemented before the JSON runner and mocked
RNG were written from `IMPLEMENTERS.md` and the fixture format documentation.
The original Python implementation, its tests, and its generation and runner
tools were not read. The v0.7 exceptional hash-output cases are covered by local
Rust tests in `src/exceptional_hash_tests.rs`; these do not alter the frozen JSON
corpus. See `fixtures/README.md` for the corpus format and test commands.
