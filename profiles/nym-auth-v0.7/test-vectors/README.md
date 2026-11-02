# Rulebook v0.7 test vectors (provisional)

`nym_auth_mdoc_v07/` holds the TEST vectors of Peter's circuit package `nym-auth-longfellow-v07-v1`,
copied unchanged. They are provisional: the v0.7 rulebook will publish its own, which replace
them. TEST ONLY: every key in them is the rulebook v0.5 vectors' TEST key, derived from a public
label, except holder E's device key, which is TEST only too.

They are the rulebook v0.5 vectors' keys, holder openings and sessions, with the credential issued
in the v0.7 layout (the package's INTEGRATION.md §5): the valueDigests namespace `eu.nym_auth.v1`,
`bsc` and `psc` as two AES-128 blocks each at digestIDs 0 and 1, no IssuerSignedItems, and the
device key compressed (COSE_Key `-3` the sign of y). The pseudonym is `prf` `aes-128`, so it
differs from the v0.5 and v0.6 vectors'.

- `nym_auth_v07_test_vectors.json` (the package's `nym-auth-zk-v07/tests/data/v07_test_vectors.json`)
  and `v07_test_vectors_zero_psc.json`: per variant, the holder's openings, the v0.7 IssuerSigned
  (`issuer_signed_cbor`), the keys, two sessions (redirect, OpenID4VP 1.0 B.2.6.1, and the DC API),
  H (`expected.nym_block`), the `aes-128` pseudonym (`expected.pseudonyms_aes128`), the age cases,
  and under `v07` the Sig_structure (375 bytes), its SHA-256 `e`, `bsc`, `psc`, the sign of y and
  the validity.
- From the package's `test-credentials/`: `v07_A.cbor` to `v07_E.cbor`, `holders.json` (each
  holder's seed, birth date, commitments, validity, device key, Sig_structure, `e` and pseudonym),
  `issue_v07.py` (the script that issued them) and its `README.md`. Holder E has a device key with
  an odd y.

`npm run vectors:check` runs the site's AES-128 commitments and pseudonym, its reading of the
layout, the `age_check` operator and the range bounds against them.
