# Changes

## 0.1.0 (2026-11-02)

First release: the nym_auth mdoc presentation (age range and the known-offender-matching-ssc
pseudonym with `prf` `aes-128`) for **rulebook v0.7**, a new circuit set with its own system_id,
`urn:circuits:sha256:218a72dea317cfcde2e715860e6b3a5dda2c67260f4cf9e8311c62ef900c34bd`.

Against `nym-auth-zk-decoy` 0.1.0 (rulebook v0.6):

- **Credential:** the valueDigests namespace is `eu.nym_auth.v1`; the device key is compressed
  (COSE_Key `-3` a bool); `bsc` and `psc` are two AES-128 blocks each; a fixed 350-byte MSO and
  375-byte Sig_structure (6 SHA-256 blocks). `mdoc::parse` refuses any deviation from the layout
  and decompresses y.
- **Pseudonym:** `AES-128(secret_seed, H[0..16]) ‖ AES-128(secret_seed, H[16..32])`, H =
  SHA-256(`"nym_auth/v1/aes-128/known-offender-matching-ssc"` ‖ 0^32 ‖ verifier_input), a public
  input the verifier computes. Values differ from v0.6's for the same seed.
- **Hash circuit:** 4 SHA-256 compressions (was 8) and AES-128 (one key schedule, four
  encryptions, 680 S-boxes, each checked by its inverse); 9,183 inputs (was 13,917); H in place of
  verifier_input as a public input.
- **Signature circuit:** the device key tied by its x only (the MAC has 4 words, was 6); y is a
  private input on the curve; 4,508 inputs (was 5,275).
- **Transcript domain:** `"nym_auth/v1/mdoc-v07/longfellow"`.
- **Runtime:** the Ligero table stores rows with GF(2^16) messages as 2-byte encodings (as Google's
  C++ prover does); proof bytes unchanged. Feature `aes-ctr-rng`: an AES-256-CTR generator for
  benchmarks, off by default.
- **API:** as `nym-auth-zk-decoy` 0.1.0; new `aes` module, `witness::nym_block`,
  `mdoc::decompress`, `witness::MAC_WORDS`; `Statement::nym_block`.
