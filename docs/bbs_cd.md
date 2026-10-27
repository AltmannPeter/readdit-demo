# `bbs_cd` in Community: nym_auth over BBS committed disclosures

Status: how the demo implements the `bbs_cd` encoding of rulebook v0.4 (`docs/nym_auth_rulebook.md`,
"BBS committed-disclosure encoding", `zkp_req`, PRF `hashdh-bls12381g1`) and v0.5
(`docs/nym_auth_rulebook-v0.5.md`; the demo profile decides, `profiles/README.md`). The schema, the
credential and the plugins are the same in both; v0.5 changes `age_check` (§4, "v0.5"). The rulebook is
normative; this note records the demo's choices and what the code checks. It replaces the demo's
earlier `mms_zk` profile (format `mms_zk`, function `pseudonym-bbs-v1`, the pseudonym as SHA-256 of
the point).

The cryptography is [sirosfoundation/bbs-cd-plugins](https://github.com/sirosfoundation/bbs-cd-plugins)
0.1, vendored unchanged in `native/bbs/vendor/bbs-cd-plugins`: ETSI BBS committed disclosures
(draft v0.7, BLS12-381-SHA-256) with the plugins `ecdsa-pop/0.1`, `pseudonym/0.1` and
`date-range/0.1` (`docs/ENVELOPE.md` and `docs/plugins/*.md` there). That code is research code:
not constant-time, not audited. The demo's own code is `native/bbs/nym-bbs` (profile, prover,
verifier, `ZkpPresentation`) and `native/bbs/issuer`.

## 1. Credential

Schema `eu.europa.ec.eudi.nym_auth.bbs.1`, digest
`ab4183a9ed0b57d6bfb8994c92b432bb9731a3e2fd974ac2f67422e2f7dfb7e1`:

| Attribute | Type | Messages | Content |
| --- | --- | --- | --- |
| `device_key` | `p256-point-xy.ecdsa-sha256`, 96-bit limbs | 6 SCALAR | The wallet's P-256 device key, attested for hashed ECDSA at issuance |
| `birth_date` | `date-packed`, 17 bits | 1 SCALAR | (Y − 1900)·372 + (M − 1)·31 + (D − 1) |
| `secret_seed` | `nym-seed.issuer-known`, 255 bits | 1 SCALAR | hash_to_scalar(secret_seed, "nym_auth/v1/bbs-seed") |

The schema digest covers the attribute names, so renaming `nym_seed` to `secret_seed` changed it
(it was `2b39f855…6793`).

The demo credential (`app/wallet/demo-wallet-bbs.json`, from `native/bbs/issuer`) is the teen's,
born 2011-03-14, on its own phone ("Teen's BBS phone"). It has the teen's mdoc device key, and its
`secret_seed` attribute is derived from the teen's 16-byte `secret_seed`, the one the teen's mdoc
commits to as `ssc`: hash_to_scalar of the BLS12-381-SHA-256 ciphersuite with DST
`nym_auth/v1/bbs-seed`. The issuer refuses a zero scalar. One seed on record serves both
encodings. `nym-bbs`'s test recomputes the seed and the pseudonym from the rulebook's formulas.

Its issuer parameters (`native/bbs/demo/issuer-params.bin`, IssuerParams = var8(pk) ‖
var16(schema)) are the verifier's trust anchor. The issuer key is new at each issuance run.

## 2. Request

The credential query, as the site builds it (`shared/utils/dcql.ts`):

```json
{
  "id": "nym_attestation_bbs",
  "format": "zkp_req",
  "meta": { "source_format": "bbs_cd", "schema_id_value": "eu.europa.ec.eudi.nym_auth.bbs.1" },
  "_req": [
    { "fn_id": "pseudonym", "return": "nym",
      "params": { "config": "known-offender-matching-ssc", "ver": 1, "prf": "hashdh-bls12381g1" } },
    { "fn_id": "age_check", "return": "age", "params": { "ge": "2008-10-20", "le": "2013-10-19" } }
  ]
}
```

- The pseudonym is required (the scheme always reveals one) and appears once. `ver` must be 1,
  `prf` `hashdh-bls12381g1`, `config` `known-offender-matching-ssc`; any other parameter is
  refused.
- verifier_id: the demo's trust framework fixes the `x509_san_dns` form, so verifier_id is the
  `client_id`, which must be `x509_san_dns:<host>`, 1 to 255 bytes.
- `age_check` is optional and appears once, with `ge` and/or `le`. The wallet refuses bounds that
  span less than 365 days; the date-range prover also refuses ranges narrower than 372 packed
  slots (one year).
- `require_cryptographic_holder_binding` false is refused.

Metadata: one `zkp_req` entry in `vp_formats_supported` for every system the site accepts,
circuits and schemes together, Vega first:

```json
{ "zkp_req": { "proof_system_values": ["vega-v1", "bbs-cd-plugins-v0.1"],
               "system_id_values": ["urn:circuits:vega:nym_auth:v1", "urn:mms:bbs-cd:nym_auth:v1"] } }
```

The phone's `wallet_metadata` lists the systems for the credentials on that phone, and the site
tailors the offer to them (`shared/utils/negotiation.ts`). With an mso_mdoc system and BBS
accepted, the DCQL query holds both credential queries, mso_mdoc first, as alternatives in one
credential set. Each phone holds one credential, so the phone decides which query is answered.

## 3. The BBS request both sides derive

The holder and the verifier compute the framework request (`ENVELOPE.md` §4) from the Request
Object, the query and the handover; the presentation does not carry it.

| Field | Value |
| --- | --- |
| `audience` | SHA-256(OpenID4VPHandoverInfoBytes), OpenID4VPHandoverInfo = [client_id, nonce, jwk_thumbprint, response_uri] (OpenID4VP 1.0 B.2.6.1); jwk_thumbprint is the RFC 7638 thumbprint of the session's response encryption key |
| `nonce` | the Request Object's `nonce`, UTF-8 (16 to 64 bytes) |
| `credentials` | one: the issuer public key and the schema digest; `disclose` empty |
| `plugins` | 0: `ecdsa-pop/0.1` on `device_key`, hashed mode, 96-bit limbs<br>1: `pseudonym/0.1` on `secret_seed`, config as requested, `verifier_input` = UTF-8(client_id)<br>2: `date-range/0.1` on `birth_date`, ge and le, only when `age_check` is asked |

ctx binds the audience and every entry; the presentation header binds the nonce and ctx; each
plugin proof is bound to env, which contains every commitment.

## 4. Response

`vp_token = { "nym_attestation_bbs": ["<base64url(CBOR(ZkpPresentation))>"] }`, sent with `state` as
the payload of a JWE (`direct_post.jwt`, ECDH-ES, A128GCM) to the key in `client_metadata.jwks`:

```cbor-diag
{
  "system_id": "urn:mms:bbs-cd:nym_auth:v1",
  "proof": h'42434450...',          / the BCDP envelope, unchanged /
  "issuer_key_set": [h'...'],        / the 96-byte BBS issuer key /
  "results": { "nym": h'...', "age": true }   / nym: the 48-byte G1 point /
}
```

v0.4: no `proof_time`; the encoding has no validity period, and the verifier refuses one.

**v0.5.** `age_check` is an assertion: `{ "fn_id": "age_check", "params": { "range": "13-17" } }`,
no `return`, no entry in `results` (`{ "nym": h'...' }` only). The presentation carries
`"proof_time": 0("YYYY-MM-DDThh:mm:ssZ")` (UTC, to the second) when the request has an age check:
the prover sets it from its clock, and both sides compute the date-range plugin's bounds from the
range and its UTC date D (C on or before D minus A years, E after D minus (B + 1) years; 29 February
clamps; `nym_bbs::dates`). The verifier checks `proof_time` against its clock within the tolerance
(`proof_time` refusal), derives the bounds from it for the BBS request it builds itself, and
answers them as `bounds`; a wallet that moves `proof_time` to another date gets other bounds, and
the date-range proof does not verify.

## 5. Verification (`nym-bbs` verifier)

1. `system_id` is `urn:mms:bbs-cd:nym_auth:v1`, and the request offered it and its proof system.
2. `issuer_key_set` holds exactly one key: the trusted issuer's, or a key the site added at runtime
   (`learned_issuers`, `/tech`'s Trust new issuers), trusted with the profile's schema. The BBS
   request binds the issuer's key, so the verifier derives it for the key presented.
3. The query is one the rulebook allows (§2); the keys of `results` are its `return` handles.
4. The envelope parses against the derived BBS request; the BBS proof verifies under the issuer
   key with the presentation header; each plugin verifies.
5. `results.nym` equals the pseudonym plugin's G1 point; v0.4: `age` is true (v0.5: no age entry,
   the date-range plugin's proof is the assertion).

Refusal codes (`[vp] … presentation refused: <code>`): `presentation` (not base64url, too large, not
a ZkpPresentation, or the envelope does not parse), `scheme` (another system, or not offered),
`issuer_key_set`, `proof_time` (v0.5: missing with an age check, or beyond the tolerance), `request`,
`results`, `proof_invalid` (the BBS proof or a plugin proof fails).

Community stores the pseudonym as 96 hex digits. It differs from the mso_mdoc pseudonym of the same
person (another PRF, even over the same seed), so the teen has one Community account per encoding.
Known-offender matching holds within an encoding. A site that accepts both lets a person banned
under one come back under the other; the site decides by what it accepts.

## 6. Sizes and times

On the 2-core Intel Xeon VM (1 thread, 13–17): envelope about 125 kB (ecdsa-pop about 123 kB, BBS
proof 1.2 kB, date-range 2.1 kB, pseudonym 148 bytes), plus about 200 bytes of ZkpPresentation.
Holder 159–173 ms, verifier 78–90 ms. `/tech` shows the runs measured on the server it runs on.

## 7. Open points

- The issuer-known seed: the issuer can compute every pseudonym (as with `ssc`).
- One schema and issuer key per anonymity set: the presentation reveals both to the verifier.
- No validity period in the credential, so nothing to check at presentation time.
