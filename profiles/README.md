# Demo profiles

A profile is one version of the nym_auth rulebook as Community runs it. `/tech` switches between
them with **Demo profile** (switching resets the demo); `NUXT_DEMO_PROFILE` picks the one at start
(default `nym-auth-v0.4`). Every `profile.json` is checked against
[`schema/profile.schema.json`](schema/profile.schema.json) when the server starts; one that does not
fit stops the built server.

| Profile | Rulebook | Proof systems |
| --- | --- | --- |
| `nym-auth-v0.4` | [v0.4](../docs/nym_auth_rulebook.md), 2026-10-20 | Vega, Longfellow, BBS |
| `nym-auth-v0.5` | [v0.5](../docs/nym_auth_rulebook-v0.5.md), 2026-10-27 | Vega and Longfellow (their bsc circuits), BBS |

## What a profile holds

- `rulebook`: version, date and the document in this repository.
- `source`: the GitHub repository and the commit the profile is based on. `null` until the profile
  is committed; then set it to that commit, so `/tech` and `/dev` link to it.
- `credential`: the attestation per encoding (doctype or schema, attributes and their roles) and
  its metadata files (v0.5: `credentials/nym_auth.mdoc.json`, `credentials/nym_auth.schema-meta.yaml`).
- `functions`: per function of `_req`, whether it is a value function (with its `return` handle) or
  an assertion, the **operator** that writes and reads its params (`wire`), and where an age check's
  bounds come from (`bounds_date`: the request, or the date of `proof_time`), with its meaning, the
  translation each side does, and what the proof shows.
- `pseudonym_configs`: each configuration's seed, its PRF per encoding, its properties (the consent
  screen's wording comes from them), and which one Community asks for (`requested`).
- `systems`: per proof system whether this version can use it (`available`, or `pending` with a
  note) and when its presentation carries `proof_time`.

## Where the versions differ in code

The request interpreter (`shared/protocol/request.ts`) knows no version: it reads `_req` with the
profile's function specs and the operators they name (`shared/protocol/operators.ts`:
`age.birth-date-bounds@1` for v0.4, `age.years-range@1` for v0.5). The site writes requests with it
(`shared/utils/dcql.ts`), the demo wallet reads them with it under the profiles its credential fits
(`app/wallet/engine.ts`), and the response route reads the profile for what a verified presentation
shows (`server/api/vp/response/[id].post.ts`).

The native addons take the version as `rulebook` ("0.4" when absent) in the prove and verify input:
`native/bbs/nym-bbs` (`profile::Rulebook`, `dates`), `native/vega/nym-vega` and
`native/longfellow/nym-longfellow` (`request::Rulebook`, `statement_for`, `dates::range_bounds`).

## Adding a version

1. Add `profiles/<id>/profile.json` (copy the newest), the rulebook under `docs/`, and the profile to
   `PROFILES` in `shared/profiles/index.ts`.
2. A new way to write or read params: a new operator in `shared/protocol/operators.ts` (never change
   an existing one), named in the function's `wire`.
3. A new wire or presentation rule in the addons: a new `Rulebook` variant there. New circuits: a
   registry entry of their own (`shared/registry/circuits.ts`), id `urn:circuits:sha256:` and the
   SHA-256 of the archive as shipped, `rulebook` the version they read; the addon lists them in
   `info.circuits` under that id (Longfellow v0.5: `nym-longfellow/src/v05.rs`).
4. Copy the rulebook's test vectors to `profiles/<id>/test-vectors/` and point `scripts/vectors-check.mjs`
   and the addons' `tests/rulebook_vectors.rs` at them (v0.5: `npm run vectors:check`, see
   [`nym-auth-v0.5/test-vectors`](nym-auth-v0.5/test-vectors/README.md)).
5. flows-check group Q covers the switch, and v0.5 over HTTP and in the browser; add the new
   version's flows there.
