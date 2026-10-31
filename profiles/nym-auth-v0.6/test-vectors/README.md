# Rulebook v0.6 test vectors (provisional)

`nym_auth_mdoc_decoy/` holds the TEST vectors of Peter's circuit package
`nym-auth-longfellow-decoy-v1` (rulebook v0.6 revision, fix1), copied unchanged. They are
provisional: the v0.6 rulebook will publish its own, which replace them. TEST ONLY: every key in
them is the rulebook v0.5 vectors' TEST key, derived from a public label.

They are the rulebook v0.5 vectors (`../../nym-auth-v0.5/test-vectors/nym_auth_mdoc`) with the
credential re-issued in the decoy-digest layout (the package's INTEGRATION.md §5): the same keys,
holder openings, sessions, expected pseudonyms and age cases; `bsc` and `psc` are the MSO's
valueDigests 0 and 1, with no IssuerSignedItems.

- `decoy_test_vectors.json`, `decoy_test_vectors_zero_psc.json`: from the package's
  `nym-auth-zk-decoy/tests/data/`. Per variant, the holder's openings, the decoy-layout
  IssuerSigned (`issuer_signed_cbor`), the keys, two sessions (redirect, OpenID4VP 1.0 B.2.6.1, and
  the DC API), the expected pseudonyms and age ranges, and under `decoy` the Sig_structure, its
  SHA-256 `e`, `bsc`, `psc` and the validity.
- From the package's `test-credentials/`: `decoy_A.cbor` (the vectors' holder), `decoy_A0.cbor`
  (the same with a zero `psc`), `decoy_B.cbor`, `decoy_C.cbor`, `decoy_D.cbor` (edge holders),
  `holders.json` (each holder's seed, birth date, commitments, validity, Sig_structure and `e`),
  `issue_decoy.py` (which issued them) and `README.md` (the holders' table).

`npm run vectors:check` (`scripts/vectors-check.mjs`) runs the site's code against
`decoy_test_vectors*.json` under the v0.6 profile: the fixture read with `readIssuerSigned`
(`shared/utils/mdoc.ts`: the decoy layout, `bsc` and `psc` from the valueDigests) against the
profile's mdoc encoding, the commitments, the pseudonyms, the `age_check` operator and the range
bounds.
