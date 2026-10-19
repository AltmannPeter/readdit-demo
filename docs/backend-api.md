# Proof backend contract

There are two backends, each a Node addon (Rust, napi-rs) loaded in the site's server process:
the Vega addon (`native/vega`, `circuit_zk` over the nym_auth mdoc), described first, and the BBS
addon (`native/bbs`, `mms_zk` over the nym_auth BBS credential, `docs/mms_zk.md`), in its own
section below. Only `server/utils/services.ts` calls them. Each loads on its own; the site starts
when at least one loads and offers only the formats of those that did. The Vega prover and
verifier They replaced the earlier HTTP
services (and their stubs) at Frédéric's request (2026-10-13), so a presentation costs no network
hop on the server side.

- **Prover:** the phone's native steps. The mocked SIROS ID wallet holds the credential, the device
  key and `secret_seed` (`app/wallet/demo-wallet.json`, no true holder binding) and sends each step
  what it needs. The prover keeps none of it between calls.
- **Verifier:** verifies a presentation against the site's own request, handover and clock.
- Both build their keys from the circuits (`native/vega/circuits/mdoc/shapes.zst`) once, when the
  server starts (`server/plugins/backends.ts`), and keep them. Setup is deterministic. Nothing
  randomized and no witness is kept between requests.
- Every call runs as an async task off Node's event loop; one heavy step (witness, prove, verify)
  runs at a time, so each step's time and peak memory are its own.

When neither addon loads, the built server stops at start with the reasons (exit code 1,
`server/plugins/backends.ts`); the development server keeps running and answers 503
`unavailable`. When one does not load, the site starts with the other and logs `[vega] not
loaded: …` or `[bbs] not loaded: …`; `/tech` shows which. An addon call that fails at runtime (it
throws, or its result is not JSON) is `500 backend_error` (`services.ts`), logged as
`[vega] <step> failed: <reason>`.

Configuration (Nuxt runtime config, environment variables):

| Variable | Default | Meaning |
| --- | --- | --- |
| `NUXT_VEGA_ADDON` | `native/vega/readdit-vega.node` | The addon (`npm run build:native`), relative to the working directory |
| `NUXT_VEGA_SHAPES` | `native/vega/circuits/mdoc/shapes.zst` | The circuits as data |
| `NUXT_VEGA_TRUST_ANCHORS` | `native/vega/demo/document-signer.pem` | The verifier's trust anchors (PEM) |
| `NUXT_PROOF_TIME_TOLERANCE_S` | `300` | How far `proof_time` may lie from the verifier's clock |
| `NUXT_ACCEPTED_CIRCUITS` | `urn:circuits:vega:nym_auth:v1` | Circuits Readdit accepts, comma-separated, in preference order |
| `NUXT_BBS_ADDON` | `native/bbs/readdit-bbs.node` | The BBS addon (`npm run build:native`) |
| `NUXT_BBS_ISSUER_PARAMS` | `native/bbs/demo/issuer-params.bin` | The BBS issuer parameters the verifier trusts |
| `NUXT_ACCEPTED_SCHEMES` | `urn:mms:bbs-cd:nym_auth:v1` | `mms_zk` schemes Readdit can accept |
| `NUXT_ACCEPTED_PROOF_SYSTEMS` | `vega-v1` | Proof systems accepted at start and after a demo reset; `/tech` switches them (`vega-v1`, `bbs-cd-plugins-v0.1`) |

## The circuit

| Item | Value |
| --- | --- |
| Circuit id | `urn:circuits:vega:nym_auth:v1` |
| Proof system | `vega-v1`: Microsoft vega-prover `c0ee259`, `VegaMcZkSNARK` over `T256HyraxEngine` |
| Circuits | nym-auth-circuits `vega-age` (vendored unchanged, `native/vega/VENDOR-SHA256SUMS`): 32 step instances and one core, layout `FULL_MDOC` |
| Statement | the nym_auth mdoc: issuer signature (ES256), docType, birth date in [E, C], validity at T, device signature on e2, `SHA-256(secret_seed) = ssc`, pseudonym `pseudonym-v1-sha256`, `known-offender-matching-ssc` |
| `shapes.zst` SHA-256 | `b457ba5382eb7604ef035e790f2cb24f0cd5fdcd065f383ff1c2c49fab1bb4df` |
| Proof | 96,079 bytes (bincode of `app::Proof`) |

Public inputs, in the registry order (`shared/registry/circuits.ts`; 18 field elements):

| # | Input | Values | From |
| ---: | --- | ---: | --- |
| 1 | `issuer_key_set` | 2 | presentation: one DER Document Signer certificate, validated against the trust anchors; its P-256 key is Q |
| 2 | `age_check.ge` | 1 | verifier: E = `ge` as sent; `0000-00-00` when absent |
| 3 | `age_check.le` | 1 | verifier: C = `le` as sent; `9999-12-31` when absent |
| 4 | `proof_time` | 1 | presentation: T, `YYYY-MM-DDThh:mm:ssZ`, within the tolerance of the verifier's clock |
| 5 | `session_transcript` | 2 | verifier: e2, below |
| 6 | `doctype` | 3 | verifier: the pattern of `eu.europa.ec.eudi.nym_auth.1` |
| 7 | `birth_date.identifier` | 3 | verifier: the pattern of `birth_date` |
| 8 | `pseudonym.verifier_input` | 3 | verifier: SHA-256(client_id) |
| 9 | `results.nym` | 2 | presentation: the pseudonym |

The site offers the circuit only when the verifier reports the same id, proof system, public-input
names and order, and `shapes.zst` hash as the registry (`server/utils/vp.ts`).

Session binding. Readdit invokes the wallet cross-device with a QR code, so OpenID4VP 1.0
Appendix B.2.6.1 applies:

```
SessionTranscript     = [null, null, ["OpenID4VPHandover", SHA-256(cbor([client_id, nonce, null, response_uri]))]]
DeviceAuthenticationBytes = #6.24(bstr(cbor(["DeviceAuthentication", SessionTranscript, docType, #6.24(bstr(h'A0'))])))
message = cbor(["Signature1", bstr(h'A10126'), bstr(h''), bstr(DeviceAuthenticationBytes)])
e2 = SHA-256(message)
```

`jwk_thumbprint` is null because the response is `direct_post` without encryption. The encoding
matches the specification's example byte for byte (`nym-vega` test `openid4vp_appendix_b261_example`).
The device key signs `message` with ES256; the circuit verifies that signature on e2.

## Encoding conventions

- `presentation` is `base64url(CBOR(CircuitZkPresentation))` without padding (rulebook,
  "Presentation encoding"): `circuit_id`, `proof`, `issuer_key_set` (one DER certificate),
  `proof_time` (tag 0), `results`.
- In decoded `results`, the pseudonym is lowercase hex of the 32-byte `bstr`, and the age predicate is `true`.
- `request` is the decoded Request Object payload, as the site built and signed it (`RequestObject`
  in `shared/types/oid4vp.ts`).
- `handover` is `{ client_id, nonce, response_uri, jwk_thumbprint: null }`; its values must equal the request's.
- Every addon call takes and returns JSON text. A prover refusal is `{ "ok": false, "status": <n>, "error": "<code>", "detail": "…" }`.

## The addon

```ts
loadProver(shapes: string): Promise<Prover>
loadVerifier(shapes: string, trustAnchorsPem: string, toleranceS: number): Promise<Verifier>

Prover.info: string                                       // JSON
Prover.sign(input: string): Promise<string>               // step 1
Prover.witness(input: string): Promise<Witness | string>  // step 2; a string is the refusal
Prover.prove(witness: Witness): Promise<string>           // step 3; consumes the witness
Witness.summary: string                                   // JSON
Verifier.info: string
Verifier.verify(input: string): Promise<string>
```

`services.ts` runs step 2 and step 3 within one call (`prover.prove`), so a witness never outlives
the request that made it. The phone's routes are `POST /api/wallet/sign` (step 1) and
`POST /api/wallet/prove` (steps 2 and 3); they record each step in the session's trace for `/tech`.
A refusal comes back with its HTTP status, a plain status text (`proverMessage` in `services.ts`)
and the code in the error body's `data.error`, which the phone reads (`app/wallet/prover.ts`).

### `info`

```json
{
  "service": "prover",
  "implementation": "Vega: microsoft/vega-prover c0ee259 (VegaMcZkSNARK, T256HyraxEngine), nym-auth-circuits vega-age; Node addon",
  "version": "0.1.0",
  "stub": false,
  "circuits": [{
    "circuit_id": "urn:circuits:vega:nym_auth:v1",
    "proof_system": "vega-v1",
    "shapes_sha256": "b457ba53…",
    "public_inputs": ["issuer_key_set", "age_check.ge", "age_check.le", "proof_time", "session_transcript", "doctype", "birth_date.identifier", "pseudonym.verifier_input", "results.nym"]
  }],
  "load_ms": 276.1,
  "threads": 32
}
```

The verifier's adds `trust_anchors` (subject, not_after) and `proof_time_tolerance_s`. `load_ms` is
the one-time key build at start. The mocked phone sends `circuits` as `wallet_metadata` and selects from it.

### Prover step 1: sign

The device key signs DeviceAuthentication over the SessionTranscript of the handover. The phone's
PIN screen stands for the unlock, and any PIN unlocks; the prover takes no PIN, and an input field
it does not know (such as a `pin`) is ignored.

```json
{
  "device_key": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "d": "…" },
  "doc_type": "eu.europa.ec.eudi.nym_auth.1",
  "handover": { "client_id": "x509_san_dns:readdit.example", "nonce": "…", "response_uri": "…", "jwk_thumbprint": null }
}
```

```json
{ "ok": true, "device_signature": "<hex r‖s>", "challenge_digest": "<hex e2>", "session_transcript": "<hex>", "metrics": { "sign_ms": 0.3 } }
```

### Prover step 2: witness

```json
{
  "circuit_id": "urn:circuits:vega:nym_auth:v1",
  "credential_query_id": "nym_attestation",
  "request": { "…": "decoded Request Object" },
  "handover": { "…": "as above" },
  "credential": { "format": "mso_mdoc", "doctype": "eu.europa.ec.eudi.nym_auth.1", "issuer_signed": "<base64url IssuerSigned>" },
  "secret_seed": "<hex, 16 bytes>",
  "device_signature": "<hex r‖s from step 1>"
}
```

Before building the witness, the prover checks: the request against what the circuit proves
(`pseudonym-v1-sha256` with `known-offender-matching-ssc` and `x509_san_dns`, at most one
`age_check` with `ge`/`le`, rulebook limits); the issuer signature under the `x5chain` certificate's
key; that the MSO lists both items' digests; `SHA-256(secret_seed) = ssc`; the device signature
under the credential's device key; the credential's validity now; and the birth date in [E, C].
Then `MdocWitness::full` and `app::witness` (nym-auth-circuits SPEC.md V5). `Witness.summary`:

```json
{
  "proof_time": "2026-10-13T00:37:07Z",
  "results": { "nym": "<hex>", "age": true },
  "public_inputs": [{ "name": "issuer_key_set", "values": ["<hex 32>", "<hex 32>"] }, "…"],
  "counts": { "shared": 194, "precommitted": 886236, "rest": 7378, "public": 50 },
  "metrics": { "witness_ms": 11.2 }
}
```

### Prover step 3: prove

`app::prepare` and `app::prove` (SPEC.md V6), then the presentation.

```json
{
  "ok": true,
  "circuit_id": "urn:circuits:vega:nym_auth:v1",
  "presentation": "<base64url CBOR>",
  "results": { "nym": "<hex32>", "age": true },
  "metrics": {
    "load_ms": 276.1, "witness_ms": 11.2, "prove_ms": 251.0, "total_ms": 262.2,
    "peak_memory_mb": 1357, "proof_bytes": 96079, "presentation_bytes": 96708, "threads": 32
  }
}
```

`total_ms` is witness + prove, per presentation. `peak_memory_mb` is the server process's peak
resident set during the step (Linux: `VmHWM` after resetting it through `/proc/self/clear_refs`);
it includes Node and both sides' keys, and is absent where it cannot be measured.

Prover refusals:

| Status | Code | Meaning |
| --- | --- | --- |
| 422 | `unsatisfiable` | A predicate does not hold for the holder's data (birth date outside [E, C], credential not valid now). The phone shows "Requirement Not Met" and sends `access_denied`. |
| 400 | `unsupported_circuit`, `unsupported_request`, `unsupported_config`, `unsupported_function` | The request cannot be proven with this circuit. |
| 400 | `bad_credential`, `bad_request` | The credential material or the call is malformed or inconsistent. |
| 500 | `backend_error` | The addon call failed (`services.ts`). The phone shows "Signing Failed". |
| 503 | `unavailable` | The addon is not built or could not load (`services.ts`). The phone shows "Connection Error". |

### Verifier: verify

```json
{
  "request": { "…": "the Request Object Readdit sent" },
  "credential_query_id": "nym_attestation",
  "presentation": "<base64url CBOR>",
  "handover": { "client_id": "…", "nonce": "…", "response_uri": "…", "jwk_thumbprint": null },
  "now": "2026-10-13T00:37:08.000Z"
}
```

```json
{ "ok": true, "circuit_id": "urn:circuits:vega:nym_auth:v1", "results": { "nym": "<hex32>", "age": true },
  "metrics": { "decode_ms": 0.2, "load_ms": 261.2, "verify_ms": 80.1, "total_ms": 80.5, "proof_bytes": 96079, "peak_memory_mb": 1357 } }
```

```json
{ "ok": false, "code": "public_input", "input": "session_transcript", "reason": "the proof does not match the public input session_transcript (value 5)", "metrics": { "…": "…" } }
```

The verifier takes only `issuer_key_set`, `proof_time` and `results` from the presentation (rulebook,
"Verification") and computes every other public input itself. It checks, in order:

| Code | Rule |
| --- | --- |
| `presentation` | base64url CBOR map with exactly the members above, no duplicates, no trailing bytes |
| `circuit` | `circuit_id` is this circuit, and the request offered it (id and proof system) |
| `request` | the request is one this circuit proves, and the handover matches it |
| `issuer_key_set` | exactly one certificate (the circuit names one issuer key), byte-equal to a trust anchor and valid now |
| `proof_time` | a 20-character date-time within the tolerance of `now` |
| `results` | the keys are exactly the `return` handles of `req`; the pseudonym is 32 bytes, the predicate `true` |
| `proof_encoding` | the proof decodes (bincode, at most 1 MiB, no trailing bytes) |
| `proof_invalid` | the SNARK verification fails, or a step instance does not report its position |
| `public_input` | the proof's public values differ from the verifier's; `input` names the first one that differs |

Readdit repeats the circuit and results-key checks after the call, as a second line of defence.

## The BBS addon (`mms_zk`)

`native/bbs/node` (crate `readdit-bbs-node`) around `native/bbs/nym-bbs`, which implements the
profile of `docs/mms_zk.md` on the vendored bbs-cd-plugins crates. `loadProver()` builds the
date-range tables; `loadVerifier(issuerParamsPath)` reads the trusted issuer parameters and
checks that their schema is the profile's. Calls take and return JSON text; one heavy step runs at
a time.

**`info`** (both): `implementation`, `version`, `schemes` (`scheme_id`, `proof_system`,
`schema_id`, `schema_digest`, `plugins` in request order), `load_ms`, `threads`; the verifier also
`issuers` (`issuer_pk`, `schema_id`, `schema_digest`). The site offers a scheme only when the
verifier reports the registry's proof system, schema and plugins (`server/utils/vp.ts`).

**Prover: `prove`.** One call per presentation; there is no separate sign step, because the device
key signs inside `ecdsa-pop` (hashed ECDSA over the plugin's device message).

```json
{ "request": { …Request Object… }, "credential_query_id": "nym_attestation_bbs",
  "handover": { "client_id": "…", "nonce": "…", "response_uri": "…", "jwk_thumbprint": null },
  "credential": { "format": "mms_zk", "schema_id": "…", "issuer_params": "…", "signature": "…", "messages": ["…"] },
  "device_key": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "d": "…" } }
```

It answers `{ ok: true, scheme_id, presentation, results, metrics, statement }`: `presentation` is
base64url of the envelope; `results` as the verifier's; `metrics` `offline_ms` (commitments and
the ecdsa-pop preparation), `bbs_ms`, `ecdsa_pop_ms`, `device_sign_ms`, `pseudonym_ms`,
`date_range_ms`, `online_ms`, `prove_ms`, `total_ms`, `presentation_bytes`, `parts` (bytes per
part), `peak_memory_mb`; `statement` the derived BBS request (audience, nonce, verifier input,
committed attributes, plugins). Refusals as the Vega prover's: `422 unsatisfiable` (the birth date
is outside the range), `400 unsupported_request`, `unsupported_config`, `unsupported_function`,
`unsupported_circuit` (the request does not offer the scheme), `bad_credential` (the credential
does not decode or verify, or the device key is not the credential's), `bad_request`.

**Verifier: `verify`.** `{ request, credential_query_id, presentation, handover }`, all but the
presentation from the site's session store. It answers `{ ok: true, scheme_id, results, metrics }`
or `{ ok: false, code, reason, metrics }` with `code` `presentation`, `request`, `scheme` or
`proof_invalid` (`docs/mms_zk.md` §6). `metrics`: `decode_ms`, `verify_ms`, `parse_ms`, `bbs_ms`,
`ecdsa_pop_ms`, `pseudonym_ms`, `date_range_ms`, `total_ms`, `proof_bytes`.

## Readdit's routes and their refusals

Every refusal carries a plain status text and a code in the error body's `data.error`.

| Route | Status and code | When |
| --- | --- | --- |
| `POST /api/vp/session` | 400 `bad_request` | No JSON object, an unknown purpose or intent, an age check (or a sign-in with `community`) for a community without an age requirement |
| | 401 `login_required` | An age check without a logged-in (and not banned) account |
| | 403 `age_refused` | The ages already proven for the account do not overlap the community's requirement |
| | 409 `age_verified` | The ages already proven already meet it: no new request |
| | 503 `unavailable` | The verifier could not make an offer |
| request_uri | 404 `unknown_session` | |
| | 405 `method_not_allowed` | Not GET or POST |
| | 400 `invalid_wallet_metadata` | `wallet_metadata` is not JSON, or its `circuit_zk` or `mms_zk` values are not lists of strings |
| | 410 `expired`, `cancelled`, `already_used` | The request expired, the site's dialog was closed, or it was already fetched once |
| | 503 `unavailable` | The site has no format to offer now (the offer is made again at this point, from `/tech`'s switches) |
| response_uri | 404 `unknown_session` | |
| | 400 `state_mismatch` | `state` is not the session's; checked first |
| | 410 `expired`, `cancelled` | |
| | 400 `not_requested` | The request was never fetched |
| | 400 `already_answered` | A second response, for example a replay; logged as `[vp] <id>: refused a second response` |
| | 200 | The response was processed. The vp_token must answer exactly one of the request's credential queries, in a format the site still accepts (else refused with code `format`). A presentation that does not verify is refused with its rule in the server log (`[vp] <id>: presentation refused: <code> (<input>): <reason>`) and the session trace (`/tech`), not in the answer |
| | 503 `unavailable` | The verifier failed; the session ends as `unavailable` |
| `GET /api/vp/session/:id`, `…/complete`, `…/cancel` | 404 `unknown_session`, 403 `other_browser` | Only the browser that started the session |
| `POST …/complete` | 409 `not_verified` | Before a verified presentation |
| `POST /api/wallet/sign`, `/prove` | 400 `bad_request` | Missing or mistyped fields; the prover's refusals above otherwise |
| `POST /api/comments` | 401 `login_required`, 400 `bad_request`, 403 `age_required` | Logged out or banned; an unknown post or a comment not of 1 to 2,000 characters; an age-restricted community without a matching age check |
| `POST /api/mod/ban`, `/unban` | 400 `bad_request`, 404 `unknown_account` | |
| `POST /api/tech/accept` | 400 `bad_request`, 409 `last_proof_system` | An unknown proof system; switching off the last accepted one |

`{ purpose: 'signin', intent, community }` is the request of a logged-out visitor at an
age-restricted community: one presentation of the pseudonym and the community's age range, which
logs in (or signs up) and records the age. `GET /api/vp/session/:id` answers `{ status, failure?,
completion?, verification? }`; `verification` holds the verifier's `decode_ms`, `verify_ms` and
`total_ms` and the response route's `round_trip_ms` around the call, once a presentation was
verified or refused.

A completed session answers `POST …/complete` with `{ ok, kind, handle?, age? }`. `kind` is `created`,
`logged_in` or `age` when applied (`age: true` when a sign-in also recorded the age); otherwise `no_account` (a log-in for a pseudonym without an
account; nothing is created), `banned`, `mismatch` (an age proof for another pseudonym than the
logged-in account's), `logged_out` (the browser was logged out meanwhile), or the reason the session
failed: `denied`, `invalid_request`, `invalid`, `unavailable`, `expired`, `cancelled`.

**Test only.** With `READDIT_TEST_FAULTS=1` in the server's environment, `POST /api/test/fault
{ "step": "prover.info" | "prover.sign" | "prover.prove" | "verifier.info" | "verifier.verify" }`
makes the next addon call of that step fail as a failing addon would (`server/utils/test-faults.ts`),
in either addon: `prover.info` and the others name the step, not the backend.
Without the variable the route answers 404 and no call is failed. `scripts/flows-check.mjs` uses it
for the "backend failing" paths.
