# Proof backend contract

There are three backends, each a Node addon (Rust, napi-rs) loaded in the site's server process:
the Vega addon (`native/vega`, a circuit over the nym_auth mdoc, `mso_mdoc`), described first; the
Longfellow addon (`native/longfellow`, a circuit over the same mdoc, with the same interface), in
its own section; and the BBS addon (`native/bbs`, a scheme over the nym_auth BBS credential,
`bbs_cd`, `docs/bbs_cd.md`). All three answer the rulebook's `zkp_req` credential query with
a `ZkpPresentation`, in the version the input names: `"rulebook": "0.4"` (the default when absent)
or `"0.5"` (the demo profile, `profiles/README.md`), in the witness (BBS: prove) and verify input.
v0.5 changes one thing here: `age_check` is an assertion, `{ "fn_id": "age_check", "params": {
"range": "13-17" } }` without `return` and with no output in `results`; the prover and the
verifier compute E and C from the range and the UTC date of `proof_time` (the prover's clock; the
verifier reads it from the presentation after checking it against `now` within its tolerance), and
the verifier answers the bounds it used as `"bounds": { "ge", "le" }` (null for no bound) next to
`results` (v0.4 too, with the request's bounds). BBS presentations carry `proof_time` under v0.5
when the request has an age check (refused otherwise: `proof_time`; under v0.4 a `proof_time` is
refused as `presentation`). Vega and Longfellow read v0.5 requests on the v0.4 circuits; the site
offers them under v0.5 only once their v0.5 circuits are in. Only `server/utils/services.ts` calls them. Each loads on its own; the site
starts when at least one loads and offers only the systems of those that did. The
addons replaced the earlier HTTP services (and their stubs) at Frédéric's request (2026-10-13), so
a presentation costs no network hop on the server side.

`mso_mdoc` calls go to the addon of the circuit: `sign` and the witness and proof steps to the
addon of the `system_id` the wallet chose, `verify` to the addon of the `system_id` the
presentation names (an unknown one goes to the first loaded addon, which refuses it with code
`circuit`). `info` merges both addons' `circuits`, Vega first.

- **Prover:** the phone's native steps. The mocked SIROS ID wallet holds the credential, the device
  key and `secret_seed` (`app/wallet/demo-wallet.json`, no true holder binding) and sends each step
  what it needs. The prover keeps none of it between calls.
- **Verifier:** verifies a presentation against the site's own request, handover and clock.
- Both build their keys from the circuits (`native/vega/circuits/mdoc/shapes.zst`) once, when the
  server starts (`server/plugins/backends.ts`), and keep them. Setup is deterministic. Nothing
  randomized and no witness is kept between requests.
- Every call runs as an async task off Node's event loop; one heavy step (witness, prove, verify)
  runs at a time, so each step's time and memory are its own.
- **Threads.** The witness and verify inputs take `"parallel": true | false` (absent: false), which
  `services.ts` sets from `/tech`'s switch. False runs the step in a one-thread rayon pool, true in a
  pool of one thread per core (`nym-vega/src/threads.rs`); the proof does not depend on it. The
  witness carries the choice to the prove step. `metrics.threads` reports the threads used (the
  witness summary's, the proof's and the verification's); `info.max_threads` the cores.
- **Profiling.** Every step of the three addons (Vega, Longfellow, BBS: sign, witness, prove,
  verify) takes `"profile": true | false` (absent: false), which `services.ts` sets from `/tech`'s
  Profiling switch; the witness carries it to the prove step. On, the step's `metrics` also has
  `profile`: `{ hz, ms, samples, other, lost, stacks }` from the sampling profiler
  (`native/nym-profile`, pprof): `stacks` maps folded stacks (`entry;…;leaf`, the step's own code
  down to the function that was running, Rust names without generics) to samples; `other` counts
  samples of other threads, `lost` samples whose stack could not be walked. Vega's witness, prove and verify add `phases`, vega-prover's own tracing
  spans as a tree (`{ name, n, ms, mb, children }`, siblings of one name merged; `mb` on one thread
  only), each phase ending at the library's own `elapsed_ms` event for it. `services.ts` takes `profile` out of the metrics before they reach any trace, and calls
  one addon step at a time while Profiling is on (the sampler is process-wide).
- **Learned issuers.** The verify input takes `"learned_issuers": [<base64 DER>, …]` (absent:
  none): Document Signer certificates trusted besides the configured trust anchors, any P-256
  certificate, self-signed or not, valid at `now`. `server/utils/issuers.ts` passes the issuers
  `/tech` added, plus, with "Trust new issuers" on, an unknown one the presentation carries; the
  server adds that one only once the presentation is accepted. An `issuer_key_set` refusal for a
  certificate that is not trusted carries it: `"certificate": <base64 DER>` (null otherwise). When
  the site could not read the certificate itself, or read another one, it verifies once more with
  that certificate in `learned_issuers` (log: `[issuers] … verifying again with it trusted`).
- **Proof parts.** The prove metrics carry `proof_parts`, the proof's bytes by part
  (`[{ name, bytes, code?, children }]`, adding up to `proof_bytes`): Vega by the fields of
  vega-prover's proof type, two levels, as bincode writes them (`nym-vega/src/sizes.rs`);
  Longfellow the MAC tags and each circuit's commitment root, sumcheck, Ligero blinding rows,
  column nonces, opened columns and Merkle path; BBS the BBS proof by field, each plugin's proof and
  the envelope's framing. `services.ts` takes them out of the metrics too.

When no addon loads, the built server stops at start with the reasons (exit code 1,
`server/plugins/backends.ts`); the development server keeps running and answers 503
`unavailable`. When one does not load, the site starts with the others and logs, for example,
`[longfellow] not loaded: …`; `/tech` shows which. An addon call that fails at runtime (it throws,
or its result is not JSON) is `500 backend_error` (`services.ts`), logged as `[<addon>] <step>
failed: <reason>` (`[circuits]` for the merged `info`).

Configuration (Nuxt runtime config, environment variables):

| Variable | Default | Meaning |
| --- | --- | --- |
| `NUXT_VEGA_ADDON` | `native/vega/community-vega.node` | The addon (`npm run build:native`), relative to the working directory |
| `NUXT_VEGA_SHAPES` | `native/vega/circuits/mdoc/shapes.zst` | The circuits as data |
| `NUXT_VEGA_TRUST_ANCHORS` | `native/vega/demo/document-signer.pem` | The verifier's trust anchors (PEM) |
| `NUXT_PROOF_TIME_TOLERANCE_S` | `300` | How far `proof_time` may lie from the verifier's clock |
| `NUXT_LONGFELLOW_ADDON` | `native/longfellow/community-longfellow.node` | The Longfellow addon |
| `NUXT_LONGFELLOW_CIRCUITS` | `native/longfellow/circuits/mdoc` | The directory of `circuits.zst`, `params.tsv`, `hash-semantic.tsv` |
| `NUXT_LONGFELLOW_TRUST_ANCHORS` | `native/vega/demo/document-signer.pem` | The Longfellow verifier's trust anchors (PEM), the same demo issuer |
| `NUXT_ACCEPTED_CIRCUITS` | `urn:circuits:vega:nym_auth:v1,urn:circuits:longfellow:nym_auth:v1` | Circuits Community can accept, comma-separated, in preference order |
| `NUXT_BBS_ADDON` | `native/bbs/community-bbs.node` | The BBS addon (`npm run build:native`) |
| `NUXT_BBS_ISSUER_PARAMS` | `native/bbs/demo/issuer-params.bin` | The BBS issuer parameters the verifier trusts |
| `NUXT_ACCEPTED_SCHEMES` | `urn:mms:bbs-cd:nym_auth:v1` | `bbs_cd` schemes Community can accept |
| `NUXT_ACCEPTED_PROOF_SYSTEMS` | empty | Proof systems accepted at start and after a demo reset; `/tech` switches them (`vega-v1`, `longfellow-libzk-v1`, `bbs-cd-plugins-v0.1`). Empty: none, and a wallet request answers 503 `none_accepted` |

## The circuit

| Item | Value |
| --- | --- |
| Circuit id | `urn:circuits:vega:nym_auth:v1` |
| Proof system | `vega-v1`: Microsoft vega-prover `c0ee259`, `VegaMcZkSNARK` over `T256HyraxEngine` |
| Circuits | nym-auth-circuits `vega-age` (vendored unchanged, `native/vega/VENDOR-SHA256SUMS`): 32 step instances and one core, layout `FULL_MDOC` |
| Statement | the nym_auth mdoc: issuer signature (ES256), docType, birth date in [E, C], validity at T, device signature on e2, `SHA-256(secret_seed) = ssc`, the `pseudonym` function with `prf` `sha-256` and `known-offender-matching-ssc` |
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

Session binding. Community invokes the wallet cross-device with a QR code, so OpenID4VP 1.0
Appendix B.2.6.1 applies:

```
SessionTranscript     = [null, null, ["OpenID4VPHandover", SHA-256(cbor([client_id, nonce, jwk_thumbprint, response_uri]))]]
DeviceAuthenticationBytes = #6.24(bstr(cbor(["DeviceAuthentication", SessionTranscript, docType, #6.24(bstr(h'A0'))])))
message = cbor(["Signature1", bstr(h'A10126'), bstr(h''), bstr(DeviceAuthenticationBytes)])
e2 = SHA-256(message)
```

The response is encrypted (`direct_post.jwt`), so `jwk_thumbprint` is the RFC 7638 SHA-256
thumbprint (32 bytes) of the session's encryption key in `client_metadata.jwks`; with `direct_post`
it would be null. The encoding matches the specification's example byte for byte (`nym-vega` test
`openid4vp_appendix_b261_example`).
The device key signs `message` with ES256; the circuit verifies that signature on e2.

## Encoding conventions

- `presentation` is `base64url(CBOR(ZkpPresentation))` without padding (rulebook v0.4,
  "Presentation encoding"): `system_id`, `proof`, `issuer_key_set` (one DER certificate),
  `proof_time` (tag 0), `results`.
- In decoded `results`, the pseudonym is lowercase hex of the `bstr` (32 bytes for `prf` `sha-256`,
  48 for `hashdh-bls12381g1`), and the age predicate is `true`.
- `request` is the decoded Request Object payload, as the site built and signed it (`RequestObject`
  in `shared/types/oid4vp.ts`).
- `handover` is `{ client_id, nonce, response_uri, jwk_thumbprint }`; its values must equal the request's.
  `jwk_thumbprint` is base64url of the 32-byte thumbprint of the request's encryption key
  (`shared/utils/jwe.ts`, `handoverOf`), or null for an unencrypted request. The verifier side takes
  it from the session's own key (`server/utils/vp.ts`, `handoverFor`).
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
    "system_id": "urn:circuits:vega:nym_auth:v1",
    "proof_system": "vega-v1",
    "shapes_sha256": "b457ba53…",
    "public_inputs": ["issuer_key_set", "age_check.ge", "age_check.le", "proof_time", "session_transcript", "doctype", "birth_date.identifier", "pseudonym.verifier_input", "results.nym"]
  }],
  "load_ms": 276.1,
  "keys_mb": 44.4,
  "max_threads": 32
}
```

The verifier's adds `trust_anchors` (subject, not_after) and `proof_time_tolerance_s`. `load_ms` is
the one-time key build at start, `keys_mb` the heap it keeps (null without the counting allocator). The mocked phone sends `circuits` as `wallet_metadata` and selects from it.

### Prover step 1: sign

The device key signs DeviceAuthentication over the SessionTranscript of the handover. The message
is the same for both circuits; `POST /api/wallet/sign` takes the wallet's chosen `system_id` and
calls that circuit's addon. The phone's
PIN screen stands for the unlock, and any PIN unlocks; the prover takes no PIN, and an input field
it does not know (such as a `pin`) is ignored.

```json
{
  "device_key": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "d": "…" },
  "doc_type": "eu.europa.ec.eudi.nym_auth.1",
  "handover": { "client_id": "x509_san_dns:community.example", "nonce": "…", "response_uri": "…", "jwk_thumbprint": "<base64url, 32 bytes>" }
}
```

```json
{ "ok": true, "device_signature": "<hex r‖s>", "challenge_digest": "<hex e2>", "session_transcript": "<hex>", "metrics": { "sign_ms": 0.3 } }
```

### Prover step 2: witness

```json
{
  "system_id": "urn:circuits:vega:nym_auth:v1",
  "credential_query_id": "nym_attestation",
  "request": { "…": "decoded Request Object" },
  "handover": { "…": "as above" },
  "credential": { "format": "mso_mdoc", "doctype": "eu.europa.ec.eudi.nym_auth.1", "issuer_signed": "<base64url IssuerSigned>" },
  "secret_seed": "<hex, 16 bytes>",
  "device_signature": "<hex r‖s from step 1>",
  "rulebook": "0.4"
}
```

Under `"rulebook": "0.5"` (Longfellow only; Vega has no v0.5 circuits yet) the credential is the
holder's v0.5 mdoc and the input adds `"birth_date": "YYYY-MM-DD"`, which opens `bsc` with the seed
(the Longfellow section, "Rulebook v0.5").

Before building the witness, the prover checks: the request against what the circuit proves
(a `zkp_req` query over `mso_mdoc`; one `pseudonym` with `known-offender-matching-ssc`, `ver` 1 and
`prf` `sha-256`, verifier_id = an `x509_san_dns` client_id; at most one `age_check` with `ge`/`le`,
rulebook limits); the issuer signature under the `x5chain` certificate's
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
  "system_id": "urn:circuits:vega:nym_auth:v1",
  "presentation": "<base64url CBOR>",
  "results": { "nym": "<hex32>", "age": true },
  "metrics": {
    "load_ms": 276.1, "keys_mb": 44.4, "witness_ms": 11.2, "prove_ms": 251.0, "total_ms": 262.2,
    "heap_mb": 412.3, "witness_mb": 34.3, "peak_memory_mb": 1357, "proof_bytes": 96079, "presentation_bytes": 96708, "threads": 32
  }
}
```

`total_ms` is witness + prove, per presentation. `heap_mb` is the proof's working memory: the most
heap the addon's own code held at once during the witness and prove steps, above what it held
before the witness step (the witness stays held between the two). A counting allocator in the
addon (`node/src/alloc.rs`, the only `unsafe` code; the library crates forbid it) wraps the system
allocator and reports to `measure::Heap`, so the figure excludes Node, V8, the other addons and the
keys or circuits loaded at start, on every platform. The witness summary has the witness step's own
`heap_mb`; the verifier and the BBS prover report theirs. Without the allocator (the crates' own
tests) it is null. `witness_mb` is the part of `heap_mb` that is the witness, held from the witness
step into the prove step. `keys_mb` is the heap the keys or circuits loaded at start still hold
(loads take one at a time, so the figure is the load's own); the whole memory a proof needs is
`keys_mb + heap_mb`. The BBS date-range tables are shared: whichever side loads first holds them
(the prover), so the BBS verifier reports 0. The example's figures are illustrative. `peak_memory_mb` is the server process's
peak resident set during the step (Linux: `VmHWM` after resetting it through `/proc/self/clear_refs`);
it includes Node, all three addons and both sides' keys, and is absent where it cannot be measured
(macOS).

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
  "request": { "…": "the Request Object Community sent" },
  "credential_query_id": "nym_attestation",
  "presentation": "<base64url CBOR>",
  "handover": { "client_id": "…", "nonce": "…", "response_uri": "…", "jwk_thumbprint": "<base64url, 32 bytes>" },
  "now": "2026-10-13T00:37:08.000Z",
  "rulebook": "0.4"
}
```

```json
{ "ok": true, "system_id": "urn:circuits:vega:nym_auth:v1", "results": { "nym": "<hex32>", "age": true }, "bounds": { "ge": "2008-10-14", "le": "2013-10-13" },
  "metrics": { "decode_ms": 0.2, "load_ms": 261.2, "keys_mb": 40.5, "verify_ms": 80.1, "total_ms": 80.5, "proof_bytes": 96079, "heap_mb": 3.1, "peak_memory_mb": 1357 } }
```

```json
{ "ok": false, "code": "public_input", "input": "session_transcript", "reason": "the proof does not match the public input session_transcript (value 5)", "metrics": { "…": "…" } }
```

The verifier takes only `issuer_key_set`, `proof_time` and `results` from the presentation (rulebook,
"Verification") and computes every other public input itself. It checks, in order:

| Code | Rule |
| --- | --- |
| `presentation` | base64url CBOR map with exactly the members above, no duplicates, no trailing bytes |
| `circuit` | `system_id` is this circuit, and the request offered it (id and proof system) |
| `request` | the request is one this circuit proves, and the handover matches it |
| `issuer_key_set` | exactly one certificate (the circuit names one issuer key), byte-equal to a trust anchor and valid now |
| `proof_time` | a 20-character date-time within the tolerance of `now` |
| `results` | the keys are exactly the `return` handles of `_req`; the pseudonym is 32 bytes, the predicate `true` |
| `proof_encoding` | the proof decodes (bincode, at most 1 MiB, no trailing bytes) |
| `proof_invalid` | the SNARK verification fails, or a step instance does not report its position |
| `public_input` | the proof's public values differ from the verifier's; `input` names the first one that differs |

Community repeats the circuit and results-key checks after the call, as a second line of defence.

## The Longfellow addon (`mso_mdoc`)

`native/longfellow/node` (crate `community-longfellow-node`) around `native/longfellow/nym-longfellow`,
on Google's longfellow-zk Rust runtime. It has the Vega addon's interface, objects and JSON, with
these differences.

| Item | Value |
| --- | --- |
| Circuit id | `urn:circuits:longfellow:nym_auth:v1` |
| Proof system | `longfellow-libzk-v1`: google/longfellow-zk `61a8a73`, Rust runtime; Ligero (rate 1/7, 132 columns) over sumcheck. The 11 runtime crates are vendored unchanged in `native/longfellow/vendor/longfellow-zk` (`native/longfellow/VENDOR-SHA256SUMS`) |
| Circuits | rulebook v0.4: the nym-auth-circuits archive's `longfellow/mdoc`, unchanged (v0.5: below): an LFC2 pair, the hash circuit over GF(2^128) (97,032 inputs, 586 public) and the signature circuit over P-256 (4,765 inputs, 1,155 public), SPEC.md L1 |
| Statement | the same as Vega's, over the same mdoc, with the same pseudonym function: one account under either |
| `circuits.zst` SHA-256 | `6c4b96ed431ee547a3a2e5b62621943a9a0a44646267653bf2db0fcc269b5c3b` |
| Proof | about 344 kB: 6 MAC tags (16 bytes each), the hash circuit's proof, the signature circuit's proof (SPEC.md L6.2) |
| Threads | 1: Google's runtime at `61a8a73` has no parallel code. `parallel` is ignored; `info.threads` and `metrics.threads` are 1 |

`loadProver(circuits)` and `loadVerifier(circuits, trustAnchorsPem, toleranceS)` take the directory
of `circuits.zst`, `params.tsv` and `hash-semantic.tsv`, read both circuits once and check them
against `params.tsv` (sizes and circuit ids). There are no keys. `info` reports `artifact_sha256`
(of `circuits.zst`) where Vega reports `shapes_sha256`.

Public inputs, in the registry order: the two circuits' public slots, grouped by input (SPEC.md
L3). Values are elements in the hash circuit plus the signature circuit.

| # | Input | Values | From |
| ---: | --- | ---: | --- |
| 1 | `proof_time` | 160 | presentation: the bits of T, `YYYY-MM-DDThh:mm:ssZ` (hash) |
| 2 | `age_check.ge` | 80 | verifier: the bits of E; `0000-00-00` when absent (hash) |
| 3 | `age_check.le` | 80 | verifier: the bits of C; `9999-12-31` when absent (hash) |
| 4 | `pseudonym.verifier_input` | 256 | verifier: the bits of SHA-256(client_id) (hash) |
| 5 | `mac.tags` | 6 + 768 | presentation: the proof's 6 tags, (a_p,k ⊕ a_v)·m_k in GF(2^128), as elements (hash) and bits (signature) |
| 6 | `mac.a_v` | 1 + 128 | verifier: a_v, 16 bytes of the Fiat–Shamir transcript after both commitments |
| 7 | `results.nym` | 2 | presentation: the pseudonym, two GF(2^128) halves (hash) |
| 8 | `issuer_key_set` | 2 | presentation: one DER Document Signer certificate, validated against the trust anchors; its key is Q (signature) |
| 9 | `session_transcript` | 256 | verifier: the bits of e2 (signature); the SessionTranscript bytes seed the Fiat–Shamir transcript |

The MAC ties the circuits together: the hash circuit reads the signed message's digest e and the
device key (x, y) from the credential, the signature circuit verifies the issuer's signature on e
and the device's on e2 under (x, y), and the tags on m = (e, x, y) halves show both used the same
values.

Session binding is the B.2.6.1 SessionTranscript above, as for Vega. The archive's fixtures use
the Digital Credentials API handover instead (`OpenID4VPDCAPIHandover`); the circuits see only e2
and the transcript only seeds Fiat–Shamir, so the same circuits serve both (`nym-longfellow`
tests: the archive's witness slot for slot and its proof, then Community's handover end to end).

**Witness summary.** `public_inputs` gives T, E and C as text and the other inputs as hex, with
`mac.tags` and `mac.a_v` empty (they exist only once the proof is made); `counts` is `{ hash: {
inputs, public }, signature: { inputs, public } }`.

**Verifier refusals.** As the Vega verifier's, except: `proof_encoding` (the 6 tags and two proofs
of these circuits' geometry do not read, or bytes remain; at most 1 MiB); `proof_invalid` with
`input` `hash` or `signature`, the circuit whose proof fails. Longfellow does not say which public
input differs: a wrong T, E, C, verifier_input or pseudonym fails the hash circuit; a wrong issuer
key or e2 the signature circuit; a presentation for another request fails on the transcript.
There is no `public_input` code.

### Rulebook v0.5: the bsc circuits

Under `"rulebook": "0.5"` the same circuit id runs other circuits: `nym-auth-zk` (Peter's package
`nym-auth-longfellow-v1`, revision 2 of the bsc baseline), delivered as is in
`native/longfellow/nym-auth-zk` and pinned in `VENDOR-SHA256SUMS`, on the same vendored runtime.
Both addon objects load them next to the v0.4 circuits (the archive is compiled into the crate,
from `nym-auth-zk/circuits/nym_auth_mdoc_bsc.lfa2.zst`), and `info.circuits` lists the circuit once
per version: `{ system_id, proof_system, rulebook: "0.4" | "0.5", artifact, artifact_sha256,
public_inputs }`. The site takes the entry of the demo profile's version (`shared/registry/circuits.ts`,
`byRulebook`; `server/utils/vp.ts`).

| Item | Value |
| --- | --- |
| Credential | rulebook v0.5, compact profile: `bsc` = SHA-256(secret_seed ‖ birth_date) at digestID 0, `psc` at 1 (signed, not read). Sig_structure 376 to 439 bytes, bsc item 56 to 119 (package INTEGRATION.md §5); `nym_auth_zk::mdoc::parse` refuses anything else |
| Statement | the issuer's signature under Q, the docType, validFrom ≤ proof_time ≤ validUntil (both inclusive), the device signature on e2, (secret_seed, birth_date) opens bsc, E ≤ birth_date ≤ C from the range and the UTC date of proof_time, the `known-offender-matching-ssc` pseudonym (the same formula as v0.4, so the same pseudonym) |
| Artifact SHA-256 | `nym_auth_mdoc_bsc.lfa2.zst` `f4d75ee2a112c63adfb00f1da45347c4691085c8cca6ab13cee7b03f00cdbd52`; hash circuit id `a5856d5c…36ca` (278 public slots), signature circuit id `6a62a572…315f` (1,155) |
| MAC | the affine `t = a + c·m`; the challenge is `mac.challenge` (no `mac.a_v`); the transcript starts from `"nym_auth/v1/mdoc-bsc/longfellow" ‖ e2` |
| Proof | about 323 kB: 6 tags, the hash proof, the signature proof (`proof_parts`: the tags and the rest) |

Public inputs in circuit order: `doctype` 8, `proof_time` 2, `pseudonym.verifier_input` 256,
`results.nym` 2, `age_check.ge` 1, `age_check.le` 1, `mac.challenge` 1 + 128, `mac.tags` 6 + 768,
`issuer_key_set` 2, `session_transcript` 256 (hash + signature). The crate computes all of them
from `nym_auth_zk::Request`, which `nym-longfellow/src/bsc.rs` (the package's adapter) builds from
the request, the handover and the certificate's key; nothing else is passed to it.

**Prover.** `witness` takes `birth_date` (`YYYY-MM-DD`) besides `secret_seed`, and makes the
holder-side checks in the package's order (INTEGRATION.md §6): the credential parses as the compact
profile (`bad_credential`, also for a v0.4 credential), the issuer signature verifies, the seed and
birth date open `bsc` (`bad_credential`), the device signature verifies, validity is inclusive at
now (`unsatisfiable`), the birth date lies in [E, C] (`unsatisfiable`). `prove` lets the crate build
the witness and both proofs. The witness summary has `rulebook: "0.5"` and the v0.5 input names.

**Verifier.** Steps 1 to 4 as above (the `results` keys are the pseudonym's handle only: v0.5's
`age_check` has no output); step 5 is the crate's verifier. `proof_invalid.input` names the first
circuit that fails: another session already fails `hash`, since e2 seeds the transcript; another
issuer key fails only `signature`. `bounds` are E and C from the range and the date of
`proof_time` (`dates::range_bounds`, which agrees with the crate).

**Build.** `native/longfellow/.cargo/config.toml` turns on carry-less multiplication for the
GF(2^128) arithmetic: `+pclmulqdq` on x86-64 (without it, Google's portable code), `+aes` on
arm64, without which the runtime does not compile (Apple Silicon has it by default, Linux arm64 does
not). A `RUSTFLAGS` environment variable replaces these flags.

## The BBS addon (`bbs_cd`)

`native/bbs/node` (crate `community-bbs-node`) around `native/bbs/nym-bbs`, which implements the
rulebook's `bbs_cd` encoding (`docs/bbs_cd.md`) on the vendored bbs-cd-plugins crates. `loadProver()` builds the
date-range tables; `loadVerifier(issuerParamsPath)` reads the trusted issuer parameters and
checks that their schema is the profile's. Calls take and return JSON text; one heavy step runs at
a time.

**`info`** (both): `implementation`, `version`, `schemes` (`system_id`, `proof_system`,
`schema_id`, `schema_digest`, `plugins` in request order), `load_ms`, `max_threads`; the verifier also
`issuers` (`issuer_pk`, `schema_id`, `schema_digest`). The site offers a scheme only when the
verifier reports the registry's proof system, schema and plugins (`server/utils/vp.ts`).

**Threads.** The crates are built with bbs-cd-plugins' `parallel` feature. `prove` and `verify`
take `"parallel": true | false` (absent: false): ecdsa-pop runs with `Parallelism::Max` (one thread
per core) or `Off`. The library makes the output the same for both. `metrics.threads` reports it,
`info.max_threads` the cores.

**Prover: `prove`.** One call per presentation; there is no separate sign step, because the device
key signs inside `ecdsa-pop` (hashed ECDSA over the plugin's device message).

```json
{ "request": { …Request Object… }, "credential_query_id": "nym_attestation_bbs",
  "handover": { "client_id": "…", "nonce": "…", "response_uri": "…", "jwk_thumbprint": "<base64url, 32 bytes>" },
  "credential": { "format": "bbs_cd", "schema_id": "…", "issuer_params": "…", "signature": "…", "messages": ["…"] },
  "device_key": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…", "d": "…" },
  "rulebook": "0.5" }
```

It answers `{ ok: true, system_id, presentation, results, metrics, proof_time, statement }`: `presentation` is
base64url(CBOR(ZkpPresentation)), its `proof` the bbs-cd-plugins envelope, `issuer_key_set` the
96-byte issuer key, `results.nym` the 48-byte G1 point, `proof_time` only under v0.5 with an age
check (also answered as `proof_time`, null otherwise); `results` as the
verifier's; `metrics` `offline_ms` (commitments and
the ecdsa-pop preparation), `bbs_ms`, `ecdsa_pop_ms`, `device_sign_ms`, `pseudonym_ms`,
`date_range_ms`, `online_ms`, `prove_ms`, `total_ms`, `proof_bytes` (the envelope),
`presentation_bytes` (the ZkpPresentation), `parts` (bytes per part), `heap_mb`, `peak_memory_mb`; `statement` the derived BBS request (audience, nonce, verifier input,
committed attributes, plugins, `rulebook`, `age_bounds`). Refusals as the Vega prover's: `422 unsatisfiable` (the birth date
is outside the range), `400 unsupported_request`, `unsupported_config`, `unsupported_function`,
`unsupported_circuit` (the request does not offer the scheme), `bad_credential` (the credential
does not decode or verify, or the device key is not the credential's), `bad_request`.

**Verifier: `verify`.** `{ request, credential_query_id, presentation, handover, learned_issuers?, rulebook?, now?, proof_time_tolerance_s? }`,
all but the presentation from the site's session store; `now` (RFC 3339) and
`proof_time_tolerance_s` are needed for a v0.5 age check. `learned_issuers`: BBS issuer public keys
(base64 of the 96-byte point) trusted besides the configured issuer, each with the profile's
schema ("Trust new issuers", `server/utils/issuers.ts`). It answers `{ ok: true, system_id, results, bounds, metrics }`
or `{ ok: false, code, reason, issuer_key, metrics }` with `code` `presentation`, `scheme`, `issuer_key_set`,
`proof_time` (v0.5), `request`, `results` or `proof_invalid` (`docs/bbs_cd.md` §5); `issuer_key` (base64) names the
one key of an `issuer_key_set` refusal that is not trusted, null otherwise. `metrics`: `decode_ms`, `verify_ms`, `parse_ms`, `bbs_ms`,
`ecdsa_pop_ms`, `pseudonym_ms`, `date_range_ms`, `total_ms`, `proof_bytes`.

## Community's routes and their refusals

Every refusal carries a plain status text and a code in the error body's `data.error`.

| Route | Status and code | When |
| --- | --- | --- |
| `POST /api/vp/session` | 400 `bad_request` | No JSON object, an unknown purpose or intent, an age check (or a sign-in with `community`) for a community without an age requirement |
| | 401 `login_required` | An age check without a logged-in (and not banned) account |
| | 403 `age_refused` | The ages already proven for the account do not overlap the community's requirement |
| | 409 `age_verified` | The ages already proven already meet it: no new request |
| | 503 `none_accepted` | Community accepts no proof system (the start state, and after a demo reset) |
| | 503 `unavailable` | The verifier could not make an offer |
| request_uri | 404 `unknown_session` | |
| | 405 `method_not_allowed` | Not GET or POST |
| | 400 `invalid_wallet_metadata` | `wallet_metadata` is not JSON, or its `zkp_req` values are not lists of strings |
| | 410 `expired`, `cancelled`, `already_used` | The request expired, the site's dialog was closed, or it was already fetched once |
| | 503 `none_accepted`, `unavailable` | The site accepts nothing now, or has no system to offer (the offer is made again at this point, from `/tech`'s switches) |
| response_uri | 404 `unknown_session` | |
| | 400 `invalid_response` | `response` is not a JWE (ECDH-ES, A128GCM) to the session's key, or its payload is not a JSON object; logged as `[vp] <id>: refused a response that does not decrypt` |
| | 400 `state_mismatch` | `state` (inside the JWE) is not the session's; checked first after decryption |
| | 400 `unencrypted` | A vp_token sent as form fields (`direct_post`); logged as `[vp] <id>: refused an unencrypted response`. An unencrypted error response (`error`, `state`) is accepted |
| | 410 `expired`, `cancelled` | |
| | 400 `not_requested` | The request was never fetched |
| | 400 `already_answered` | A second response, for example a replay; logged as `[vp] <id>: refused a second response` |
| | 200 | The response was processed. The vp_token must answer exactly one of the request's credential queries, with a system of the query's source format whose proof system the site still accepts (else refused with code `format`). A presentation that does not verify is refused with its rule in the server log (`[vp] <id>: presentation refused: <code> (<input>): <reason>`) and the session trace (`/tech`), not in the answer |
| | 503 `unavailable` | The verifier failed; the session ends as `unavailable` |
| `GET /api/vp/session/:id`, `…/complete`, `…/cancel` | 404 `unknown_session`, 403 `other_browser` | Only the browser that started the session |
| `POST …/complete` | 409 `not_verified` | Before a verified presentation |
| `POST /api/wallet/sign`, `/prove` | 400 `bad_request` | Missing or mistyped fields; the prover's refusals above otherwise |
| `POST /api/wallet/trace` | 400 `bad_request` | An unknown step (`authenticate`, `match`, `consent`, `decline`, `encrypt`), a label over 80 characters, or over 8 kB of data. 204 otherwise, also for an unknown `state` (nothing recorded) |
| `GET /api/dev/latest` | | This browser's newest session for the developer view, created after `?after=<ms>`, and what `/tech` accepts |
| `POST /api/comments` | 401 `login_required`, 400 `bad_request`, 403 `age_required` | Logged out or banned; an unknown post or a comment not of 1 to 2,000 characters; an age-restricted community without a matching age check |
| `POST /api/mod/ban`, `/unban` | 400 `bad_request`, 404 `unknown_account` | |
| `POST /api/tech/accept` | 400 `bad_request`, 409 `pending_system` | An unknown proof system; one the demo profile cannot use yet (v0.5: Vega and Longfellow, waiting for their circuits). Switching off the last accepted one is allowed |
| `POST /api/tech/demo-profile` | 400 `bad_request` | `{ profile }`: `nym-auth-v0.4` or `nym-auth-v0.5`. Switches the profile and resets the demo; a later demo reset keeps it |
| `POST /api/tech/threads` | 400 `bad_request` | `parallel` is not a boolean |
| `POST /api/tech/issuers` | 400 `bad_request`, 404 `unknown_issuer` | `{ trust_new: boolean }` switches "Trust new issuers"; `{ forget: <fingerprint> }` removes an added issuer (404 when there is none). Neither: 400 |
| `POST /api/tech/profiling` | 400 `bad_request` | `on` is not a boolean. Off at start and after a demo reset |
| `GET /api/tech/profile?row=` | 400 `bad_request` | Without `row` (a Benchmark row's `key`). Answers the row's profiled runs: `{ runs, prove, verify }`, each `{ runs, samples, other, lost, hz, stacks, phases }` (the prover's stacks rooted at Device signature, Witness, Proof for the circuits) |
| `POST /api/tech/measurements/clear` | | Empties the measurements file and the profiles file |

`{ purpose: 'dev', age: 'none' | 'over18' | 'range13to17' }` is the developer view's request: the
pseudonym, and the age range 18+ or 13–17 if chosen; its completion creates the account or logs in
and records the age range (`banned` for a banned account).

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

**Test only.** With `COMMUNITY_TEST_FAULTS=1` in the server's environment, `POST /api/test/fault
{ "step": "prover.info" | "prover.sign" | "prover.prove" | "verifier.info" | "verifier.verify" }`
makes the next addon call of that step fail as a failing addon would (`server/utils/test-faults.ts`),
in either addon: `prover.info` and the others name the step, not the backend.
Without the variable the route answers 404 and no call is failed. `scripts/flows-check.mjs` uses it
for the "backend failing" paths.
