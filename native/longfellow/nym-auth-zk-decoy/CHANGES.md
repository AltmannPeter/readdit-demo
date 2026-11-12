# Changes

## Package fix (2026-10-31)

Test data only. No change to code, circuits, system_id or proofs.

- `tests/data/decoy_test_vectors.json` and `decoy_test_vectors_zero_psc.json`:
  `sessions.redirect.device_response` and `sessions.dcapi.device_response` held the rulebook v0.5
  item-layout credential, copied from the v0.5 vectors. They now embed this file's decoy-layout
  `issuer_signed_cbor` (no `nameSpaces`). The DeviceSigned part, and so the device signature, is
  unchanged: DeviceAuthentication does not depend on the credential.

## 0.1.0 (2026-10-30)

First release: the nym_auth mdoc presentation (age range and the known-offender-matching-ssc
pseudonym) for **nym_auth rulebook v0.6**, whose credential is the **decoy-digest layout with the
precomputed prefix**. The docType stays `eu.europa.ec.eudi.nym_auth.1`. This is a new circuit set with its
own system_id, `urn:circuits:sha256:5d7d2b5d094032df5b02f576d2ae7b99d3f0932d47516336693f8d670cfd63ac`.

Against `nym-auth-zk` (the compact profile with IssuerSignedItems):

- **Credential:** `bsc` and `psc` are the MSO's valueDigests; no IssuerSignedItems, no
  `nameSpaces`; a fixed 423-byte Sig_structure. `mdoc::parse` takes the credential alone and
  refuses any deviation from the layout.
- **Hash circuit:** SHA-256 from the constant state after the first 128 bytes, over blocks 2 to 6;
  constant bytes are constants of the circuit; no read windows, no docType input, one proof_time
  element (no F2). The eight compressions' traces are packed four bits per input with Google's
  4-bit bit plucker.
- **Signature circuit:** unchanged, byte for byte.
- **Transcript domain:** `"nym_auth/v1/mdoc-decoy/longfellow"`.
- **Runtime:** Google's ZK prover and verifier with their independent work in parallel on the
  caller's rayon pool (`src/rt`, feature `parallel`, default); `threads()`; the feature `reference`
  uses Google's own `ZkProver` / `ZkVerifier`. Proof bytes are identical either way.
- **API:** as `nym-auth-zk` 0.2.0, but `mdoc::parse(credential)` and `mdoc::Parsed` (the fields at
  fixed offsets); `witness::Statement` has no `doc_type`.
