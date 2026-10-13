# Proof backend contract

The prover and the verifier are the Vega Node addon (`native/vega`, Rust, napi-rs), loaded in the
site's server process. Only `server/utils/services.ts` calls them. They replaced the earlier HTTP
services (and their stubs) at Frédéric's request (2026-10-13), so a presentation costs no network
hop on the server side.

- **Prover:** the phone's native steps. The mocked SIROS ID wallet holds the credential, the device
  key and `secret_seed` (`app/wallet/demo-wallet.json`, no true holder binding) and sends each step
  what it needs. The prover keeps none of it between calls.
- **Verifier:** verifies a presentation against the site's own request, handover and clock.
- Both build their keys from the circuits (`native/vega/circuits/mdoc/shapes.zst`) once, when the
  server starts (`server/plugins/vega.ts`), and keep them. Setup is deterministic. Nothing
  randomized and no witness is kept between requests.
- Every call runs as an async task off Node's event loop; one heavy step (witness, prove, verify)
  runs at a time, so each step's time and peak memory are its own.

In offline mode (`NUXT_BACKEND_MODE=offline` or the switch in `/mod`) the site uses a built-in
simulation instead (`server/utils/offline-backend.ts`). It follows the same contract, sends a random
proof of Vega's size (96,079 bytes) and marks its metrics `"simulated": true`.

Configuration (Nuxt runtime config, environment variables):

| Variable | Default | Meaning |
| --- | --- | --- |
| `NUXT_VEGA_ADDON` | `native/vega/readdit-vega.node` | The addon (`npm run build:native`), relative to the working directory |
| `NUXT_VEGA_SHAPES` | `native/vega/circuits/mdoc/shapes.zst` | The circuits as data |
| `NUXT_VEGA_TRUST_ANCHORS` | `native/vega/demo/document-signer.pem` | The verifier's trust anchors (PEM) |
| `NUXT_PROOF_TIME_TOLERANCE_S` | `300` | How far `proof_time` may lie from the verifier's clock |
| `NUXT_WALLET_PIN` | `123456` | The PIN that unlocks the device key (prover and offline simulation) |
| `NUXT_ACCEPTED_CIRCUITS` | `urn:circuits:vega:nym_auth:v1` | Circuits Readdit accepts, comma-separated, in preference order |

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
loadProver(shapes: string, pin: string): Promise<Prover>
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

### Prover step 1: unlock and sign

The PIN unlocks the device key, which signs DeviceAuthentication over the SessionTranscript of the handover.

```json
{
  "pin": "123456",
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
| 401 | `invalid_pin` | Wrong PIN. The phone asks again. |
| 422 | `unsatisfiable` | A predicate does not hold for the holder's data (birth date outside [E, C], credential not valid now). The phone shows "Requirement not met" and sends `access_denied`. |
| 400 | `unsupported_circuit`, `unsupported_request`, `unsupported_config`, `unsupported_function` | The request cannot be proven with this circuit. |
| 400 | `bad_credential`, `bad_request` | The credential material or the call is malformed or inconsistent. |
| 503 | `unavailable` | The addon is not built or could not load (`services.ts`). |

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
