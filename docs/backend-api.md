# Backend service contract

The site talks to two local services over JSON/HTTP. Only `server/utils/services.ts` calls them.
`backend-stubs/` implements this contract without zero-knowledge proofs, so the demo runs end to end.
Replace the stubs with the Longfellow services and keep this contract (or update it here and in
`services.ts` together).

In offline mode (`NUXT_BACKEND_MODE=offline` or the switch in `/mod`) the site uses a built-in
simulation of both services instead (`server/utils/offline-backend.ts`). It follows the same
contract and marks its metrics `"simulated": true`.

Configuration (Nuxt runtime config, environment variables):

| Variable | Default | Meaning |
| --- | --- | --- |
| `NUXT_PROVER_URL` | `http://localhost:8081` | Prover service base URL |
| `NUXT_VERIFIER_URL` | `http://localhost:8082` | Verifier service base URL |
| `NUXT_ACCEPTED_CIRCUITS` | `urn:circuits:longfellow:nym_auth:v1` | Circuits Readdit accepts, comma-separated, in preference order |
| `NUXT_DEMO_HOLDER` | `demo-persona` | Holder id the mocked phone uses at the prover |

Encoding conventions:

- `presentation` is `base64url(CBOR(CircuitZkPresentation))` without padding (rulebook, "Presentation encoding").
- In decoded `results`, pseudonyms are lowercase hex of the 32-byte `bstr`, and predicates are `true`.
- `request` is the decoded Request Object payload, as the site built and signed it. See `RequestObject` in `shared/types/oid4vp.ts`.
- `handover` holds the inputs for `SessionTranscript = [null, null, OpenID4VPHandover]`. The flow uses
  `direct_post` without encryption, so `jwk_thumbprint` is `null`.

## Prover service

The prover stands in for the phone's secure parts. It holds the holder's `nym_auth` mdoc, the device
key and `secret_seed`. It checks the PIN before the device key signs `DeviceAuthentication`, then
runs the circuit.

### `GET /info`

```json
{
  "service": "prover",
  "implementation": "longfellow-zk (Google Rust)",
  "version": "…",
  "stub": false,
  "circuits": [{ "circuit_id": "urn:circuits:longfellow:nym_auth:v1", "proof_system": "longfellow-libzk-v1" }]
}
```

`circuits` is what the wallet can run. The mocked phone sends it as `wallet_metadata` and selects from it.

### `GET /holders/{holder}/credentials/nym_auth`

A human-readable view of the credential for the wallet's detail window. It contains no secrets.

```json
{
  "docType": "eu.europa.ec.eudi.nym_auth.1",
  "namespace": "eu.europa.ec.eudi.nym_auth.1",
  "title": "Age and pseudonym",
  "encoding": "ISO/IEC 18013-5 mdoc",
  "compactProfile": true,
  "issuer": { "name": "Demo Issuer", "country": "SE", "documentSigner": "CN=…" },
  "validity": { "signed": "…Z", "validFrom": "…Z", "validUntil": "…Z" },
  "attributes": { "birth_date": "2011-03-14", "ssc": "<hex32>", "psc": null },
  "mso": { "digestAlgorithm": "SHA-256", "signatureAlgorithm": "ES256" },
  "deviceKey": { "kty": "EC", "crv": "P-256", "jwkThumbprint": "…", "protection": "…" }
}
```

### `POST /prove`

```json
{
  "holder": "demo-persona",
  "pin": "123456",
  "circuit_id": "urn:circuits:longfellow:nym_auth:v1",
  "credential_query_id": "nym_attestation",
  "request": { "…": "decoded Request Object" },
  "handover": { "client_id": "x509_san_dns:readdit.example", "nonce": "…", "response_uri": "…", "jwk_thumbprint": null }
}
```

Success, `200`:

```json
{
  "circuit_id": "urn:circuits:longfellow:nym_auth:v1",
  "presentation": "<base64url CBOR>",
  "results": { "nym": "<hex32>", "age": true },
  "metrics": {
    "load_ms": 0, "witness_ms": 0, "prove_ms": 0, "total_ms": 0,
    "peak_memory_mb": 0, "proof_bytes": 0, "presentation_bytes": 0
  }
}
```

All `metrics` fields are optional. The technical view shows whichever fields are present.

Errors (`{ "error": "<code>" }`):

| Status | Code | Meaning |
| --- | --- | --- |
| 401 | `invalid_pin` | Wrong PIN. The phone asks again. |
| 422 | `unsatisfiable` | A predicate does not hold. The phone shows "Requirement not met" and sends `access_denied`. |
| 400 | `unsupported_circuit`, `unsupported_request`, `unsupported_config`, `unsupported_function` | The request cannot be proven by this service. |

## Verifier service

The verifier verifies the proof against the circuit. It builds every public input itself except
`issuer_key_set`, `proof_time` and `results`, which come from the presentation (rulebook,
"Verification"). The site passes `request` and `handover` from its own session store, never from the
wallet's response.

### `GET /info`

The same shape as the prover's `/info`. `circuits` lists what the verifier can verify. Readdit offers
the intersection of this list with `NUXT_ACCEPTED_CIRCUITS` and the circuit registry.

### `POST /verify`

```json
{
  "request": { "…": "the Request Object Readdit sent" },
  "credential_query_id": "nym_attestation",
  "presentation": "<base64url CBOR>",
  "handover": { "client_id": "…", "nonce": "…", "response_uri": "…", "jwk_thumbprint": null },
  "now": "2026-10-12T12:00:00.000Z"
}
```

`200` on both outcomes:

```json
{
  "ok": true,
  "circuit_id": "urn:circuits:longfellow:nym_auth:v1",
  "results": { "nym": "<hex32>", "age": true },
  "metrics": { "decode_ms": 0, "load_ms": 0, "verify_ms": 0, "total_ms": 0, "proof_bytes": 0 }
}
```

```json
{ "ok": false, "reason": "proof does not verify" }
```

The verifier must check:

- `circuit_id` is in the registry and among the ids the request offered.
- `issuer_key_set` validates against the trust anchors.
- `proof_time` is within tolerance of `now`.
- The `results` keys equal the `return` handles in `req`.
- The proof verifies with public inputs in the registry order: `issuer_key_set`, `proof_time`,
  `session_transcript`, `pseudonym.config`, `pseudonym.verifier_input = SHA-256(client_id)`,
  `age_check.ge`, `age_check.le`, `results` (see `shared/registry/circuits.ts`).

Readdit repeats the circuit and results-key checks after the call, as a second line of defence.
