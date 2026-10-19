# `mms_zk`: nym_auth over BBS committed disclosures (demo profile)

Status: Readdit demo profile, version 1, 2026-10-19. Defined for this demo at Peter's request; not
part of the nym_auth rulebook, which leaves BBS and other non-circuit proofs out of scope. For
review.

`mms_zk` (multi-message signature, zero knowledge) is a DCQL credential format next to the
rulebook's `circuit_zk`. It carries the same nym_auth statements, a pseudonym and an age range,
over a BBS credential with committed disclosures. The cryptography is
[sirosfoundation/bbs-cd-plugins](https://github.com/sirosfoundation/bbs-cd-plugins) 0.1, vendored
unchanged in `native/bbs/vendor/bbs-cd-plugins`: ETSI BBS committed disclosures (draft v0.7,
BLS12-381-SHA-256) with the plugins `ecdsa-pop/0.1`, `pseudonym/0.1` and `date-range/0.1`
(`docs/ENVELOPE.md` and `docs/plugins/*.md` there). That code is research code: not
constant-time, not audited.

## 1. Credential

Schema `eu.europa.ec.eudi.nym_auth.bbs.1` (framework schema, `ENVELOPE.md` §2), digest
`2b39f8559b7bf2888502ccac0a681538f218bbf792d826cbad482ee487fb6793`:

| Attribute | Type | Messages | Content |
| --- | --- | --- | --- |
| `device_key` | `p256-point-xy.ecdsa-sha256`, 96-bit limbs | 6 SCALAR | The wallet's P-256 device key, attested for hashed ECDSA at issuance |
| `birth_date` | `date-packed`, 17 bits | 1 SCALAR | (Y − 1900)·372 + (M − 1)·31 + (D − 1) |
| `nym_seed` | `nym-seed.issuer-known`, 255 bits | 1 SCALAR | The pseudonym seed, chosen and kept by the issuer |

The issuer signs with BBS over the 8 messages; the header fixes the schema. No attribute is
disclosable: every presentation commits to the attributes it uses and hides the rest.

The demo credential (`app/wallet/demo-wallet-bbs.json`, from `native/bbs/issuer`) is the teen's,
born 2011-03-14, with the same device key as the teen's mdoc. Its issuer parameters
(`native/bbs/demo/issuer-params.bin`) are the verifier's trust anchor. The issuer key is new at
each issuance run.

## 2. Request

### Credential query

```json
{
  "id": "nym_attestation_bbs",
  "format": "mms_zk",
  "meta": { "schema_id_value": "eu.europa.ec.eudi.nym_auth.bbs.1" },
  "req": [
    { "id": "pseudonym-bbs-v1", "return": "nym",
      "params": { "config": "known-offender-matching-ssc", "verifier_id_type": "x509_san_dns" } },
    { "id": "age_check", "return": "age", "params": { "ge": "2008-10-20", "le": "2013-10-19" } }
  ]
}
```

- `pseudonym-bbs-v1` is required and appears once. Its configuration names the properties, as in
  the rulebook: `known-offender-matching-ssc`, the only one the pseudonym plugin defines (the seed
  is issuer-known; `private_seed` needs blind issuance, which the framework reserves). The
  verifier identity is `client_id`, which must be `x509_san_dns:<host>`.
- `age_check` is optional and appears once, with `ge` and/or `le` as YYYY-MM-DD (calendar dates),
  as in the rulebook. The wallet refuses bounds that span less than 365 days; the date-range
  prover also refuses ranges narrower than 372 packed slots (one year).
- `require_cryptographic_holder_binding` false is refused: the scheme always binds the device key.

### Metadata

`client_metadata.vp_formats_supported.mms_zk` and the wallet's `wallet_metadata` carry:

```json
{ "proof_system_values": ["bbs-cd-plugins-v0.1"], "scheme_id_values": ["urn:mms:bbs-cd:nym_auth:v1"] }
```

A scheme is a schema with its plugins, the counterpart of a circuit (registry:
`shared/registry/circuits.ts`, `SCHEME_REGISTRY`). The verifier tailors the offer to the wallet's
values as for `circuit_zk` (`shared/utils/negotiation.ts`); a format the wallet does not list keeps
the full offer.

### Both formats

The site accepts the proof systems switched on in `/tech` (none at start). With BBS and a
`circuit_zk` system (Vega, Longfellow), the DCQL query holds both credential queries, `circuit_zk`
first (the preference), and one credential set whose options are the alternatives:

```json
"credential_sets": [{ "options": [["nym_attestation"], ["nym_attestation_bbs"]] }]
```

The wallet answers one of them: the credential the person has selected, if it fits, else the first
that fits in the request's order. "Switch credential" offers the other.

The offer and the query are made when the wallet fetches the request (request_uri), from what the
site accepts at that moment, and the response is refused (code `format`) when its format is no
longer accepted.

## 3. The BBS request both sides derive

Both the holder and the verifier compute the framework request (`ENVELOPE.md` §4) from the Request
Object, the `mms_zk` query and the handover; the presentation does not carry it.

| Field | Value |
| --- | --- |
| `audience` | SHA-256(OpenID4VPHandoverInfoBytes), OpenID4VPHandoverInfo = [client_id, nonce, jwk_thumbprint / null, response_uri] (OpenID4VP 1.0 B.2.6.1), the hash the mdoc SessionTranscript carries |
| `nonce` | the Request Object's `nonce`, UTF-8 (16 to 64 bytes) |
| `credentials` | one: the issuer public key and the schema digest; `disclose` empty |
| `plugins` | 0: `ecdsa-pop/0.1` on `device_key`, hashed mode, 96-bit limbs, profile `draft00-shared-bit`<br>1: `pseudonym/0.1` on `nym_seed`, config as requested, `verifier_input` = UTF-8(client_id)<br>2: `date-range/0.1` on `birth_date`, ge and le as YYYYMMDD, only when `age_check` is asked |

ctx binds the audience and every entry; the presentation header binds the nonce and ctx; each
plugin proof is bound to env, which contains every commitment. So the response is bound to the
client_id, the nonce and the response_uri, as an mdoc presentation is through DeviceAuthentication.

The holder's pseudonym prover takes the verifier identity from the request's `client_id`, which
the wallet checked against the request-signing certificate's SAN (`app/wallet/transport.ts`).

## 4. Response

`vp_token = { "nym_attestation_bbs": ["<base64url of the BCDP envelope>"] }` (`ENVELOPE.md` §6).
With both formats offered, the vp_token answers exactly one query; Readdit refuses a vp_token with
none or both.

## 5. Results

The verifier returns the same results as `circuit_zk`:

- `nym`: SHA-256(nym), nym = seed·OP the 48-byte compressed G1 point the pseudonym plugin outputs,
  OP = hash_to_curve_G1(u8(len(config)) ‖ config ‖ verifier_input). 32 bytes, hex.
- `age`: `true` when the date-range proof verifies.

The pseudonym differs from the `circuit_zk` one for the same person (another function and seed),
so the same person has one Readdit account per format. Known-offender matching holds within a
format. A site that accepts both formats lets a person banned under one come back under the other;
the site decides by what it accepts.

## 6. Verification (Readdit)

1. The answered query is one of the request's, and its format is `mms_zk`.
2. The request offers the scheme; the query is one this profile defines (§2).
3. The envelope parses against the derived BBS request (counts, lengths, no trailing bytes).
4. The ETSI BBS proof verifies against the trusted issuer key, with the presentation header.
5. Each plugin verifies: `ecdsa-pop` (the committed device key signed the device message),
   `pseudonym`, `date-range`.
6. The results' keys are the `return` handles; `nym` is 32 bytes; `age` is true.

Refusal codes (`[vp] … presentation refused: <code>`): `presentation` (not base64url, too large,
does not parse), `request` (the query is not one the profile defines), `scheme` (not offered),
`proof_invalid` (the BBS proof or a plugin proof fails).

## 7. Sizes and times

On the 2-core Intel Xeon VM it was built on (bbs-cd-plugins full-flow-bench, 1 thread, 13–17):
presentation 126.7 kB, of which ecdsa-pop 123.2 kB, BBS proof 1.2 kB, date-range 2.1 kB, pseudonym
148 bytes. Holder about 8 ms before the request and 158 ms after it (ecdsa-pop 136 ms); verifier
82 ms (ecdsa-pop 58 ms).

## 8. Open points for review

- The function id `pseudonym-bbs-v1` and the format name `mms_zk` are this demo's.
- The issuer-known seed: the issuer can compute every pseudonym (as with `ssc` in the rulebook).
- One schema and issuer key per anonymity set (`DESIGN.md` §13 of bbs-cd-plugins): the request
  names neither, but the presentation reveals both to the verifier.
- No validity period in the credential, so nothing to check at presentation time.
