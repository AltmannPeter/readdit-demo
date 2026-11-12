# Rulebook v0.5 test vectors

`nym_auth_mdoc/` is copied unchanged from the nym_auth rulebook repository
(`test-vectors/nym_auth_mdoc`, 2026-10-27), without its `.venv/` and `out/`. TEST ONLY: every
key in it is derived from a public label.

It is a deterministic `mso_mdoc` fixture in the compact profile (`bsc` at digestID 0, `psc` at 1),
in two variants: with a `private_seed` (`psc` = SHA-256(private_seed)), and `_zero_psc` (`psc` is
32 zero bytes, so the `-psc` configurations are unsatisfiable). Per variant:

- `nym_auth_test_vectors<variant>.json`: the holder's openings, the commitments, the
  IssuerSignedItems, the MSO, issuerAuth, the Sig_structure layout, the keys, two sessions
  (redirect, OpenID4VP 1.0 B.2.6.1, and the DC API) and the expected results: the pseudonyms of
  the four configurations (prf `sha-256`) and the age ranges (E and C) on the date of `proof_time`.
- `issuer_signed<variant>.cbor`, `mso<variant>.cbor`, `device_response_redirect<variant>.cbor`,
  `device_response_dcapi<variant>.cbor`; shared: `iaca.der`, `ds.der`.

`gen_nym_auth_mdoc.py` writes them, `verify_nym_auth_mdoc.py` checks them on its own
(`pip install -r requirements.txt`).

What runs the demo's code against them:

- `npm run vectors:check` (`scripts/vectors-check.mjs`): the commitments, the pseudonyms
  (`shared/utils/pseudonym.ts`), the v0.5 profile's `age_check` operator and the range bounds
  (`shared/protocol/operators.ts`), and that the profile's mdoc attributes match the fixture's.
- `tests/rulebook_vectors.rs` in `nym-vega` and `nym-longfellow` (the range bounds, and the
  redirect session's SessionTranscript and device message) and in `nym-bbs` (the range bounds).
