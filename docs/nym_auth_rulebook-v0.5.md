---
title: "Nym-authentication Attestation Specification and Rulebook"
author: "Peter Altmann & Frédéric Nieto"
version: "0.4"
status: "public draft"
date: "2026-10-20"
---

# Introduction and scope

## Scope

This document specifies the natural-person anonymous/pseudonymous authentication attestation (`eu.europa.ec.eudi.nym_auth.1` in its ISO/IEC 18013-5 form, and `eu.europa.ec.eudi.nym_auth.bbs.1` in its BBS form). This attestation enables a Holder to:

1. Generate a pseudonym with various properties for authentication, account binding, and known-offender matching.
2. Generate a zero-knowledge proof of correct pseudonym generation.
3. Prove zero-knowledge date-based predicates (e.g., age checks).

This version targets Zero-Knowledge Proof (ZKP) presentations using the `zkp_req` presentation format, over two encodings of the attestation: ISO/IEC 18013-5 (`mso_mdoc`), proved with circuits, and BBS committed disclosures (`bbs_cd`), proved with a BBS scheme and its plugins. The following are out of scope:

* Non-ZKP fallbacks.
* SD-JWT VC encodings.
* Details on revocation. Validity checks apply where the encoding carries a validity period; the `bbs_cd` encoding carries none in this version.
* For circuits: The relationship between the system provider and any trust mechanism (e.g., circuit registry).
* The selection of a trusted issuer.

ZKP proof systems, circuit definitions and scheme definitions referenced herein are defined externally in:

* Source for proof systems.
* Source for circuit definitions.
* Source for scheme definitions: bbs-cd-plugins 0.1 (ETSI BBS committed disclosures, BLS12-381-SHA-256) and its plugins `ecdsa-pop/0.1`, `pseudonym/0.1` and `date-range/0.1`.

Pseudonym derivation is normatively defined in this document.

Approved systems (circuits and schemes), with their verification hashes and parameter mappings, are maintained in a registry of approved systems.

## System roles

* **Issuer:** Issues a signed attestation with attributes and statements about an identity subject.
* **System provider:** Issues a signed circuit (`mso_mdoc`) or publishes a scheme (`bbs_cd`) suitable for a specified presentation request.
* **Prover (Holder, Wallet Unit):** Stores the issuer-signed attestation, generates pseudonyms, and produces ZKP.
* **Verifier (Relying Party):** Requests at least one function execution and/or a claim via DCQL and validates the ZKP.

## Key words

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** in this document are to be interpreted as described in RFC 2119.

In tables, REQ is short for REQUIRED, OPT is short for OPTIONAL, CON is short for CONDITIONAL.

---

# Attestation data model and attributes

## Attribute overview

| Data Identifier | Attribute Identifier | CBOR / CDDL Representation | Presence | Description |
| :--- | :--- | :--- | :--- | :--- |
| **birthdate_and_secret_seed_commitment** | `bsc` | `bstr` (32 bytes) | REQ | **Birthdate and Seed Commitment**: $`C = \text{SHA-256}(\text{secret\_seed} \Vert \text{birth\_date})`$ where $`\text{secret\_seed}`$ is a 16-byte random shared secret between the issuer and prover (the issuer known seed), and $`\text{birth\_date}`$ is the holder's date of birth as an RFC 3339 `full-date`. |
| **private_seed_commitment** | `psc` | `bstr` (32 bytes) | REQ | **Issuer Unknown Seed Commitment**: $`C = \text{SHA-256}(\text{private\_seed})`$ where $`\text{private\_seed}`$ is a 16-byte random value known only to the prover, or 32 zero bytes if the prover has not provided one. |

In the `mso_mdoc` encoding the commitment input `birth_date` is the `full-date` (`YYYY-MM-DD`) as a 10-byte UTF-8 string, without CBOR tag or length prefix; with the 16-byte `secret_seed`, the hash input is 26 bytes. `birth_date` is not itself a data element of the `mso_mdoc` encoding.

In the `bbs_cd` encoding the issuer signs the seed itself (`secret_seed`) and the date of birth itself (`birth_date`) as hidden attributes, instead of their commitment `bsc`, and adds the device key as an attribute (`device_key`); `psc` is not defined for `bbs_cd` in this version (see the BBS encoding section).

## Non-disclosure of seed commitments

`bsc` and `psc` are stable values that can act as a correlation handle for the Holder.

A Wallet Unit MUST NOT disclose `bsc` or `psc` in a presentation; a Credential Query that requests any of these values MUST be treated as unsatisfiable.

A Wallet Unit MUST NOT present a `nym_auth` attestation other than in a `zkp_req` presentation. A Credential Query in another format that would match a `nym_auth` attestation, with or without `claims`, MUST be treated as unsatisfiable for that attestation.

## Mobile Security Object requirements

For ISO/IEC 18013-5 encoded attestations:

* The MSO `validityInfo` MUST contain `signed`, `validFrom` and `validUntil` as defined in ISO/IEC 18013-5. A proof over the attestation MUST establish `validFrom` ≤ `proof_time` ≤ `validUntil`, both bounds included. `signed` is not checked.
* The MSO `digestAlgorithm` MUST be `"SHA-256"`.
* `deviceKeyInfo.deviceKey` MUST contain the public key of a device key pair whose private key is protected by [hardware / WSCD reference].
* `issuerAuth` MUST carry the `x5chain` header parameter (label 33) in its unprotected header, containing the Document Signer certificate. The
  `issuerAuth` signature MUST verify under the public key in that certificate.

> **NOTE:** Attestation authenticity is established by the `issuerAuth` signature and its certificate chain. In a `zkp_req` presentation over `mso_mdoc` the signature is verified inside the circuit against the issuer key set. Certificate chain validation happens when the issuer key set is built.

---

# ISO/IEC 18013-5 compliant encoding

## Document type and Namespace

For attestations complying with ISO/IEC 18013-5, the Document Type (`docType`) and Namespace MUST both be set to: `eu.europa.ec.eudi.nym_auth.1`

## Attribute encodings and CDDL specification

The complete attribute map for the `eu.europa.ec.eudi.nym_auth.1` namespace MUST conform to the following CDDL specification (RFC 8610):

```cddl
nym_auth_namespace = {
  "bsc"       => bsc_type,
  "psc"       => psc_type
}

bsc_type = bstr .size 32
psc_type = bstr .size 32
```

Each data element is issued as a separate `IssuerSignedItem` as defined in ISO/IEC 18013-5. `birth_date` is carried only inside `bsc`, as defined in the attribute overview.

The Wallet Unit MUST hold `secret_seed` and `birth_date` (and `private_seed` when `psc` is not 32 zero bytes) alongside the attestation; their delivery is not defined in this version.

The issuer MUST compute `bsc` with the same `secret_seed` it uses to remap pseudonyms to an identity.

Approved circuits for `mso_mdoc` MUST accept any encoding of these data elements and of the MSO that conforms to ISO/IEC 18013-5.

## Compact profile

An attestation conforms to the compact profile if, in addition to ISO/IEC 18013-5:

* it contains only the data elements defined in this document;
* each `random` value is 16 bytes;
* `bsc` has `digestID` 0 and `psc` `digestID` 1;
* the MSO contains no optional members;
* `validityInfo` values have the form `YYYY-MM-DDTHH:MM:SSZ`;
* the device key and the Document Signer key are P-256 keys;
* the `issuerAuth` protected header is exactly `{1: -7}`;
* these maps contain exactly these keys, in this order:
  * MSO: `version`, `digestAlgorithm`, `docType`, `valueDigests`, `deviceKeyInfo`, `validityInfo`;
  * `deviceKeyInfo`: `deviceKey`;
  * `validityInfo`: `signed`, `validFrom`, `validUntil`;
  * `IssuerSignedItem`: `digestID`, `random`, `elementIdentifier`, `elementValue`;
  * `deviceKey`: 1 (kty = 2), −1 (crv = 1), −2 (x), −3 (y), with x and y each a 32-byte `bstr`.

Issuers SHOULD issue attestations conforming to the compact profile.

A registry entry MAY target the compact profile. The registry MUST contain at least one approved circuit that supports every function and configuration defined in this document for `mso_mdoc` and accepts any ISO/IEC 18013-5 conformant encoding. A Wallet Unit SHOULD use a compact-profile circuit when its attestation conforms and the Verifier accepts one.

# BBS committed-disclosure encoding (`bbs_cd`)

## Schema

For attestations in the BBS committed-disclosure encoding, the schema identifier MUST be `eu.europa.ec.eudi.nym_auth.bbs.1`. The schema is a bbs-cd-plugins 0.1 framework schema with these attributes, in this order:

| Attribute | Type | BBS messages | Content |
| :--- | :--- | :--- | :--- |
| `device_key` | `p256-point-xy.ecdsa-sha256`, 96-bit limbs | 6 | The public key of a device key pair whose private key is protected by [hardware / WSCD reference], attested for hashed ECDSA at issuance |
| `birth_date` | `date-packed` | 1 | (Y − 1900)·372 + (M − 1)·31 + (D − 1), which preserves date order |
| `secret_seed` | `nym-seed.issuer-known` | 1 | The pseudonym seed: an issuer-managed scalar drawn uniformly at random from the non-zero elements of the BLS12-381 scalar field |

> **NOTE:** An issuer that also issues the `mso_mdoc` encoding may derive the scalar from the holder's 16-byte `secret_seed` as `hash_to_scalar(secret_seed, "nym_auth/v1/bbs-seed")` with the BLS12-381-SHA-256 ciphersuite's `hash_to_scalar`.

The schema digest is `ab4183a9ed0b57d6bfb8994c92b432bb9731a3e2fd974ac2f67422e2f7dfb7e1`.

The issuer signs the messages with BBS; the credential header fixes the schema. No attribute is disclosable: a presentation commits to the attributes it uses and hides the rest.

> **NOTE:** The `bbs_cd` encoding has no validity period and no `psc` in this version. `private_seed` would require blind issuance. It has no `bsc` either: no attribute is disclosable, so `secret_seed` and `birth_date` are signed directly.

# DCQL profile and presentation syntax (`zkp_req`)

## Overview and fail-closed design

This profile extends OpenID4VP Digital Credentials Query Language (DCQL) for zero-knowledge presentations.

A Wallet Unit that does not support the `zkp_req` format cannot match a Credential Query that uses it, and therefore returns no presentation for it. For `"format": "zkp_req"`, attestation attributes are never disclosed directly. All calculations and assertions MUST be requested inside `_req`.

### Unsatisfiable Credential Queries

An unsatisfiable request makes the affected Credential Query unsatisfiable; whether the Authorization Request can still be fulfilled follows the DCQL rules of OpenID4VP 1.0, including `credential_sets`. If it cannot, the Wallet Unit returns an Error Response (OpenID4VP 1.0, Section 8.5):

* `invalid_request` MAY be used if the cause is independent of the Holder's attestation data.
* Otherwise `access_denied` MUST be used, without `error_description`.

> **NOTE:** `access_denied` is also returned when the user declines, so data-dependent failures are indistinguishable from refusal. 

## Query structure

A Credential Query targeting the `nym_auth` attestation (`eu.europa.ec.eudi.nym_auth.1`, or `eu.europa.ec.eudi.nym_auth.bbs.1` for `bbs_cd`) MUST observe the following rules:

* `format` (REQUIRED): MUST be set to `"zkp_req"`.
* `meta` (REQUIRED): MUST contain `source_format` and the matching type value, as defined in the `zkp_req` format section.
* `_req` (REQUIRED): A non-empty array of objects specifying proven zero-knowledge calculations and predicates. The leading underscore marks a member whose values are proven and never disclosed.

> **NOTE**: Proof system capability negotiation (e.g., supported ZK proof systems) occurs at the protocol level as defined in the capability negotiations subsection.

### `_req` item member specification

Each object inside the `_req` array has the following members:

| Member | Type | Presence | Description |
| :--- | :--- | :--- | :--- |
| `fn_id` | String | REQ | Function identifier registered in the function catalogue (`"pseudonym"`, `"age_check"`). |
| `return` | String | CON | An output handle unique within the Credential Query for mapping the function's output into `results`. REQUIRED for value functions. MUST NOT be present for assertion functions. |
| `params` | Object | OPT | Key-value mapping of declared parameters for the specified function. Omission applies the function's defined defaults. |

Each function in the function catalogue is either a value function, whose output is placed in `results`, or an assertion function, which has no output: a presentation exists only if the assertion holds. A Wallet Unit MUST treat the request as unsatisfiable if an item lacks `return` for a value function or contains `return` for an assertion function.

> **NOTE:** An assertion has no output so that a Verifier can never observe a negative result. A predicate that returned `true` or `false` would let a Verifier recover `birth_date` bit by bit through repeated queries.

## Response processing and results mapping

The Wallet Unit generates a proof, using one approved system, that covers all requested statements in `_req` and is bound to the presentation session as defined in the Binding section.

> **NOTE:** It is possible to use two distinct attestations, one for age and one for pseudonym, but if both require 2FA the user experience is degraded. In this version, both age verification and pseudonym are satisfied using a single attestation `nym_auth`.

### Presentation encoding

In the `vp_token`, the value for each `zkp_req` Credential Query `id` is an array of presentations as defined in OpenID4VP 1.0. Each presentation is the base64url-encoded (without padding) CBOR encoding of a `ZkpPresentation`:

```cddl
ZkpPresentation = {
  "system_id"      => tstr,            ; approved system used: a circuit or scheme identifier
  "proof"          => bstr,            ; proof as defined by the proof system
  "issuer_key_set" => IssuerKeySet,
  ? "proof_time"   => tdate,           ; present when the system checks validity or `_req` has `age_check`
  "results"        => Results
}

IssuerKeySet = [+ bstr]                ; representation defined by the registry entry

Results = { * tstr => ResultValue }    ; keys are the `return` handles in `_req`; empty if `_req` holds only assertions
ResultValue = PseudonymValue
PseudonymValue = bstr                  ; length set by the pseudonym's `prf`
```

For `bbs_cd`, `proof` is the bbs-cd-plugins presentation envelope (MAGIC, the BBS proof with its commitments, and one proof per plugin, in request order).

The keys of `results` MUST be exactly the `return` handles of the items in `_req`. The Verifier MUST reject a presentation with missing or additional keys.

`issuer_key_set` is the set of issuer keys among which the proof shows the attestation's issuer to be, without revealing which. It supports set membership over a set of approved issuers. The registry entry of `system_id` defines its representation and how many keys it may hold. The Verifier MUST validate every element against its trust anchors or its list of trusted issuers.

* `mso_mdoc`: each element is a DER-encoded Document Signer certificate.
* `bbs_cd`: each element is a BBS issuer public key (96 bytes, the ETSI encoding). A BBS proof verifies under one issuer key, so the set holds exactly one element and reveals the issuer to the Verifier.

`proof_time` is the time used by the system for validity checks and, through its UTC date D, for the `age_check` bounds. It MUST be present when the system checks validity or `_req` contains an `age_check` item. The Verifier MUST reject the presentation if `proof_time` deviates from its own clock by more than its tolerance.

### Verification

To verify a presentation, the Verifier:

1. looks up `system_id` in the approved systems registry and confirms it is one it accepts and offered;
2. validates `issuer_key_set` as the registry entry defines;
3. assembles its statement as the registry entry defines, taking `issuer_key_set`, `proof_time` and the values in `results` from the presentation and computing everything else itself (session binding values, `verifier_input`, the `_req` parameters it sent, and the `age_check` bounds E and C from `range` and `proof_time`): for a circuit, the public inputs in the registry's order; for a scheme, the scheme's request;
4. verifies `proof` against the system and that statement, and confirms that the proof establishes each value in `results` and each assertion in `_req`.

The Verifier MUST NOT take any part of its statement from the presentation other than `issuer_key_set`, `proof_time` and `results`.

> **NOTE:** In a circuit, the values in `results` are public inputs. In a `bbs_cd` presentation, the pseudonym is also carried in the pseudonym plugin's proof; the Verifier confirms the two are equal.

Example `vp_token` (presentations shown in CBOR diagnostic notation before encoding):

```json
{
  "nym_attestation": ["<base64url(CBOR(ZkpPresentation))>"]
}
```

`mso_mdoc`:

```cbor-diag
{
  "system_id": "urn:circuits:longfellow:nym_auth:v1",
  "proof": h'...',
  "issuer_key_set": [h'3082...'],
  "proof_time": 0("2026-10-20T12:00:00Z"),
  "results": {
    "nym": h'5f2a...e1'
  }
}
```

`bbs_cd`:

```cbor-diag
{
  "system_id": "urn:mms:bbs-cd:nym_auth:v1",
  "proof": h'42434450...',
  "issuer_key_set": [h'...'],
  "proof_time": 0("2026-10-20T12:00:00Z"),
  "results": {
    "nym": h'a3...'
  }
}
```

With `proof_time` on 2026-10-20, the range `13-17` gives E = 2008-10-21 and C = 2013-10-20.

## Example DCQL request

The example shows the decoded payload of a signed Request Object (`openid4vp-v1-signed`), passed to the Digital Credentials API. The JWS is signed with the key of the Verifier's access certificate, carried in the `x5c` header; the leaf certificate MUST contain `rp.example.com` as a dNSName SAN.

> **NOTE:** The example will be updated to align with the OpenID drafts.

EXAMPLE BELOW IS WORK IN PROGRESS AND BEING REVISED.

Over the cross-device redirect flow, the same DCQL and metadata are sent in a Request Object fetched from a `request_uri`, with Response Mode `direct_post.jwt` instead of `dc_api.jwt`; the response is encrypted in both cases.

```json
{
  "response_type": "vp_token",
  "response_mode": "dc_api.jwt",
  "nonce": "n-0S6_WzA2Mj",
  "client_id": "x509_san_dns:rp.example.com",
  "expected_origins": [
    "https://rp.example.com"
  ],
  "client_metadata": {
    "jwks": {
      "keys": [
        {
          "kty": "EC",
          "crv": "P-256",
          "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
          "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ",
          "use": "enc",
          "alg": "ECDH-ES",
          "kid": "1"
        }
      ]
    },
    "vp_formats_supported": {
      "zkp_req": {
        "proof_system_values": [
          "longfellow-libzk-v1",
          "vega-v1",
          "bbs-cd-plugins-v0.1"
        ],
        "system_id_values": [
          "urn:circuits:longfellow:nym_auth:v1",
          "urn:circuits:vega:nym_auth:v1",
          "urn:mms:bbs-cd:nym_auth:v1"
        ]
      }
    }
  },
  "dcql_query": {
    "credentials": [
      {
        "id": "nym_attestation",
        "format": "zkp_req",
        "meta": {
          "source_format": "mso_mdoc",
          "doctype_value": "eu.europa.ec.eudi.nym_auth.1"
        },
        "_req": [
          {
            "fn_id": "pseudonym",
            "return": "nym",
            "params": {
              "config": "known-offender-matching-ssc",
              "ver": 1,
              "prf": "sha-256"
            }
          },
          {
            "fn_id": "age_check",
            "params": {
              "range": "13-17"
            }
          }
        ]
      },
      {
        "id": "nym_attestation_bbs",
        "format": "zkp_req",
        "meta": {
          "source_format": "bbs_cd",
          "schema_id_value": "eu.europa.ec.eudi.nym_auth.bbs.1"
        },
        "_req": [
          {
            "fn_id": "pseudonym",
            "return": "nym",
            "params": {
              "config": "known-offender-matching-ssc",
              "ver": 1,
              "prf": "hashdh-bls12381g1"
            }
          },
          {
            "fn_id": "age_check",
            "params": {
              "range": "13-17"
            }
          }
        ]
      }
    ],
    "credential_sets": [
      {
        "options": [
          [
            "nym_attestation"
          ],
          [
            "nym_attestation_bbs"
          ]
        ]
      }
    ]
  }
}
```

> NOTE: `format` is the expected format of the attestation that wraps the response, and NOT the source format of the attestation, or the vp_formats_supported etc.

> **NOTE:** Show variations of the sibling vs nesting between `claims` and `_req`

# Function catalogue

Functions invoked inside `_req` MUST be registered in this specification or an official extension profile. Each registered function defines:

1. The mathematical operation, possible intermediate values, and parameter constraints.
2. The implicit credential source attribute(s) bound to the computation.
3. Whether it is a value function or an assertion function and, for a value function, the output representation in the presentation response `results` map.

If a Wallet Unit receives a request for a function `fn_id` not defined below, or not supported by an approved system for the Credential Query's `source_format` and type value, the request is unsatisfiable.

## Pseudonym generation function (`pseudonym`)

Derives a deterministic pseudonym with the pseudorandom function named by `prf`.

* Function identifier (`fn_id`): `"pseudonym"`.
* Source attribute: for `mso_mdoc`, `bsc` for issuer-known-seed configurations and `psc` for private-seed configurations; the generation does not use `bsc` or `psc` directly, but the seed from their openings (`secret_seed` from `bsc`, `private_seed` from `psc`). For `bbs_cd`, `secret_seed`.
* Function type: value function; `return` is REQUIRED.
* Output: a `PseudonymValue` placed in `results[<handle>]`: 32 bytes for `prf` `sha-256`; for `prf` `hashdh-bls12381g1`, a compressed BLS12-381 G1 point of 48 bytes, which the Verifier processes as it chooses.

A `_req` MUST NOT contain more than one `pseudonym` item. A Wallet Unit MUST treat a request containing more than one as unsatisfiable.

### Verifier identity

Configurations that use `verifier_input` derive it from `verifier_id`, a UTF-8 string identifying the Verifier. The request does not select its form. The trust framework under which the Verifier operates MUST fix exactly one form of `verifier_id`, and the Wallet Unit and the Verifier MUST both use that form. The forms a trust framework can fix are:

* `semantic`: `"semantic_id:"` followed by the end Relying Party's semantic identifier as defined in ETSI TS 119 475, Section 5.1.3 (legal persons) or Section 5.1.5 (natural persons). The Wallet Unit MUST take it from the registration certificate when one is present, and otherwise from the access certificate.
* `x509_san_dns`: the Client Identifier, i.e. `"x509_san_dns:"` followed by the DNS name bound to the access certificate used to sign the request. An internationalised domain name is represented in the A-label form (`xn--...`) in which it appears in the certificate (RFC 5280, Section 7.2). How a name given in another form, such as a U-label, is converted to the A-label form is defined by the trust framework; a Wallet Unit MUST NOT apply its own conversion.

The Wallet Unit MUST treat the request as unsatisfiable if:

* the identifier of the form fixed by the trust framework cannot be obtained from authenticated sources;
* the form is `x509_san_dns` and the Client Identifier uses any other prefix (including `x509_hash`);
* the form is `x509_san_dns` and the registration certificate identifies an intermediary.

> **NOTE 1:** The two forms yield unrelated pseudonyms for the same Relying Party. A change of the form fixed by the trust framework, or of the Verifier's identifier, loses continuity with existing pseudonyms.

> **NOTE 2:** Outside the EUDIW ecosystem intermediaries cannot be detected; with `x509_san_dns` the pseudonym is then distinct per access-certificate holder, not per end Relying Party.

> **NOTE 3:** Within the EUDIW, an intermediary acting without a registration certificate presents its own semantic identifier, so end Relying Parties behind it share a pseudonym space.

### Parameters

This specification version enables the following function parameters.

| Parameter | Type | Presence | Description | Parameter restrictions |
| :-- | :-- | :-- | :-- | :-- |
| `config` | string | REQ | Identifier for standard configurations. | Allowed values are specified in the configurations below. |
| `ver` | integer | REQ | Version of the pseudonym function. | `1` in this version. |
| `prf` | string | REQ | The pseudorandom function. | `sha-256` (`mso_mdoc`, every configuration) or `hashdh-bls12381g1` (`bbs_cd`, `known-offender-matching-ssc` only). |
| `verifier_context` | string | CON | Additional context supplied by the verifier. | Required for account recovery. MUST NOT be present elsewhere. 1 to 64 bytes in its UTF-8 encoding, hashed as sent, without normalization. |

A Wallet Unit MUST treat the request as unsatisfiable if `verifier_context` is absent for a configuration that requires it, present for a configuration that does not allow it, or longer than 64 bytes.

A Wallet Unit MUST treat the request as unsatisfiable if `ver` is not `1`, or if `prf` is not defined for the Credential Query's `source_format` and the requested configuration.

### Configurations

With `prf` `sha-256`, all configurations generate the pseudonym as: `pseudonym = SHA256(DST || {secret, private}_seed || prover_input || verifier_input)`. The `config` determines which seed source to use. The `DST` is set to `nym_auth/v1/<config>` (UTF-8 encoded) for `ver` 1. The verifier MUST recompute and supply its own public inputs to the proof verification. `prf` `hashdh-bls12381g1` is defined after the configurations.

`known-offender-matching-ssc` is defined for `mso_mdoc` and `bbs_cd`; the other configurations for `mso_mdoc` only.

#### `known-offender-matching-ssc`

The `known-offender-matching-ssc` configuration is defined as follows:

1. For `mso_mdoc`, the circuit asserts `SHA256(secret_seed || birth_date) == bsc`, with `birth_date` the 10-byte `full-date` held by the Wallet Unit; generation uses `secret_seed`. For `bbs_cd`, generation uses the `secret_seed` attribute directly.
2. With `prf` `sha-256`, `prover_input` is null (32 zero bytes). `hashdh-bls12381g1` takes no `prover_input` in this version.
3. `verifier_input` is `SHA256(verifier_id)` with `prf` `sha-256`, and `UTF-8(verifier_id)` with `prf` `hashdh-bls12381g1`, with `verifier_id` as defined in the Verifier identity subsection.

The configuration's properties are as follows:

* The pseudonym value is distinct per `verifier_id`.
* The pseudonym can be remapped to an identity by the issuer, who knows the `secret_seed` value.
* It supports known offender matching.

> **NOTE 1**: If the issuer known seed changes, so does the pseudonym generated. A ban can be evaded by changing the issuer to one using a different issuer known seed.

> **NOTE 2**: If the `verifier_input` changes, so does the pseudonym generated. Known offender matching is not possible if the Verifier identity changes.

#### `known-offender-matching-psc`

1. For `mso_mdoc`, the `psc` (issuer unknown seed commitment) value from the `nym_auth` attestation is used to assert `SHA256(private_seed) == psc`; generation uses `private_seed`. If `psc` is 32 zero bytes, the Wallet Unit MUST treat the request as unsatisfiable.
2. `prover_input` is null (32 zero bytes).
3. `verifier_input` is `SHA256(verifier_id)`, with `verifier_id` as defined in the Verifier identity subsection.

The configuration's properties are as follows:

* The pseudonym value is distinct per `verifier_id`.
* Remapping the pseudonym to an identity is as hard as brute forcing the `private_seed`, which is intractable.
* To support known offender matching, the issuer MUST only allow one `psc` other than 32 zero bytes per identity subject.

> **NOTE 1**: If the issuer changes, it may allow a new `psc`, which changes the pseudonym generated.

> **NOTE 2**: If the `verifier_input` changes, so does the pseudonym generated. Known offender matching is not possible if the Verifier identity changes.

#### `account-recovery-ssc`

1. For `mso_mdoc`, the circuit asserts `SHA256(secret_seed || birth_date) == bsc`, with `birth_date` the 10-byte `full-date` held by the Wallet Unit; generation uses `secret_seed`.
2. `prover_input` is null (32 zero bytes).
3. `verifier_input` is `SHA256(SHA256(verifier_id) || SHA256(verifier_context))`, with `verifier_id` as defined in the Verifier identity subsection and `verifier_context` UTF-8 encoded as supplied by the Verifier.

The configuration's properties are as follows:

* The pseudonym value is distinct per `verifier_id` and `verifier_context`.
* The pseudonym can be remapped to an identity by the issuer, who knows the `secret_seed` value.
* Supports account recovery for a given account as identified by the `verifier_context`.
* Supports known offender matching per supplied `verifier_context`.

#### `user-managed-pseudonym-xsite-ssc`

1. For `mso_mdoc`, the circuit asserts `SHA256(secret_seed || birth_date) == bsc`, with `birth_date` the 10-byte `full-date` held by the Wallet Unit; generation uses `secret_seed`.
2. `prover_input` is the SHA256 digest of a user-supplied value; shared across the sites the user wants to be linked across.
3. `verifier_input` is null (32 zero bytes).

Wallet Units MAY add additional entropy to the user-supplied value.

The configuration's properties are as follows:

* The same pseudonym value can be presented to different verifiers.
* Remapping the pseudonym to an identity is as hard as brute forcing the `prover_input`, which is only intractable if that value has
  sufficient entropy.
* Does not offer sybil resistance.
* Does not support known offender matching.

### PRF `hashdh-bls12381g1`

Defined for `source_format` `bbs_cd` with configuration `known-offender-matching-ssc` only.

```
OP        = hash_to_curve_G1(u8(len(config)) || config || verifier_input, DST)
pseudonym = secret_seed · OP
```

* `secret_seed` is the committed message scalar.
* `config` is the configuration identifier, UTF-8 encoded; `verifier_input` is `UTF-8(verifier_id)`.
* `verifier_id` MUST be 1 to 255 bytes.
* `hash_to_curve_G1` is the hash-to-curve of the BLS12-381-SHA-256 ciphersuite (`BLS12381G1_XMD:SHA-256_SSWU_RO_`, RFC 9380), with `DST = "BBS-CD-PLUGINS/0.1/PSEUDONYM/OP"`.
* The output is `pseudonym` encoded with `point_to_octets_E1` of the BBS ciphersuite (compressed, 48 bytes).

The `pseudonym/0.1` plugin proves that `pseudonym` is computed from the committed `secret_seed`. The construction is a group-valued PRF, $F_s(x)=[s]H(x)$: it hashes the input to a curve point, then multiplies that point by the secret scalar. For a uniformly random secret scalar, it is pseudorandom under DDH in G1 when $H$ is modeled as a random oracle into G1.

## Date predicate function (`age_check`)

Proves that the Holder's age in whole years lies in a range, by comparison over the holder's `birth_date` (the `full-date` committed in `bsc` for `mso_mdoc`, the `date-packed` attribute for `bbs_cd`).

* Function identifier (`fn_id`): `"age_check"`.
* Source attribute: for `mso_mdoc`, `bsc`; the comparison does not use `bsc` directly, but its opening `birth_date`, and asserts `SHA256(secret_seed || birth_date) == bsc`. For `bbs_cd`, `birth_date`.
* Function type: assertion function; `return` MUST NOT be present.
* Output: none. The presentation proves that the predicate holds; `results` has no entry for it.

### Parameters

| Parameter | Type | Presence | Description |
| :-- | :-- | :-- | :-- |
| `range` | String | REQ | The allowed ages in whole years, bounds included. |

`range` has this syntax (RFC 5234):

```abnf
range = age "-" age   ; A-B: ages A to B, both included
      / age "+"       ; A+: age A or more
      / age "-"       ; B-: age B or less
age   = 1*DIGIT       ; base-10 integer
```

A Wallet Unit MUST treat the request as unsatisfiable if `range` does not match this syntax, or if it is `A-B` with A > B.

The Wallet Unit and the Verifier compute the date bounds E and C from `range` and D, the UTC date of `proof_time`:

* D minus N years keeps the month and day of D and subtracts N from its year. The result may be no calendar date, such as (2015, 02, 29); it compares with calendar dates in date order.
* C is the latest calendar date on or before D minus A years.
* E is the earliest calendar date after D minus (B + 1) years.
* `A+` has no E, and `B-` has no C. A system uses its widest value for a missing bound.

The proof shows E ≤ `birth_date` ≤ C. For `mso_mdoc`, the comparison runs on the committed `full-date`, whose character order preserves date order. For `bbs_cd`, it runs on the `date-packed` encoding, which preserves date order.

A `_req` MUST NOT contain more than one `age_check` item. A Wallet Unit MUST treat a request containing more than one `age_check` item as unsatisfiable.

If the predicate does not hold for the attestation's `birth_date`, the request is unsatisfiable and the Wallet Unit MUST NOT produce a presentation.

# Presentation

## Approved systems registry entries

The ecosystem maintains a registry of approved systems: circuits and schemes. Given the attestation type (`eu.europa.ec.eudi.nym_auth.1` or `eu.europa.ec.eudi.nym_auth.bbs.1`), the presentation format (`zkp_req`), and the requested functions in `_req`, the Wallet Unit and Verifier look up an approved system from the registry. Each system MUST have a unique identifier.

Each registry entry MUST specify:

* the system identifier,
* the proof system,
* the `source_format` and the doctype, schema identifier or vct,
* the supported functions and parameters, including the pseudonym `prf` values,
* the representation of the issuer key set and how many keys it may hold, and
* the Verifier's statement: for a circuit, the ordered list of public inputs with how the Verifier derives each one; for a scheme, its plugins and how the Verifier derives the scheme's request.

## Input and output classification

The following MUST be private: `secret_seed`, `private_seed`, `prover_input`, `birth_date`, all issuer-signed data and digests, the issuer signature, the device public key and device signature.

The following MUST be part of the Verifier's statement: `verifier_input`, the session binding values defined by the registry entry, all function parameter values in `_req` (for `age_check`, the bounds E and C), `proof_time` when validity is checked or `age_check` is requested, and the issuer key set.

The pseudonym is a public output. Predicates have no output: their parameters are part of the Verifier's statement, and the proof shows that they hold.

## The `zkp_req` format

### Credential Query

For `zkp_req`, the `meta` object MUST contain `source_format`, the format of the attestation the proof is made over, and exactly one type value for it:

| `source_format` | Type value |
| :--- | :--- |
| `mso_mdoc` | `doctype_value` (string): the ISO/IEC 18013-5 `docType` |
| `bbs_cd` | `schema_id_value` (string): the bbs-cd-plugins schema identifier |
| `dc+sd-jwt` | `vct_values` (array of strings): reserved for a future SD-JWT VC binding (not defined in this version) |

The `zkp_req` format does not use `claims`. All requests MUST be present in `_req`. This version does not define `_req_sets` (corresponding to `claim_sets`).

`require_cryptographic_holder_binding` MUST be absent or `true`. A Wallet Unit MUST treat a Credential Query with `require_cryptographic_holder_binding: false` as unsatisfiable.

### Metadata parameters

The following parameters MAY be used in the `zkp_req` object of `vp_formats_supported`, in Verifier metadata (`client_metadata`) and in Wallet metadata (`wallet_metadata`):

* `proof_system_values`: OPTIONAL. Non-empty array of proof system identifiers from the approved systems registry.
* `system_id_values`: OPTIONAL. Non-empty array of unique system identifiers (circuit and scheme identifiers) from the approved systems registry.

When the Verifier provides these parameters, the Wallet Unit MUST select an approved system whose proof system and identifier are both listed, whose `source_format` and type value match the Credential Query, and which supports every item in `_req`; if none exists, the Credential Query is unsatisfiable. The presentation MUST identify the system identifier used.

### Capability negotiation

The Verifier signals the proof systems and systems it accepts in `client_metadata.vp_formats_supported.zkp_req`, using the parameters defined above.

When the Authorization Request uses `request_uri_method=post`, the Wallet Unit MAY send the same parameters in `wallet_metadata.vp_formats_supported.zkp_req`, and the Verifier SHOULD tailor the Request Object to them.

Over the Digital Credentials API, the Wallet Unit cannot send `wallet_metadata`. The Verifier SHOULD therefore list every proof system and system identifier it accepts, and the Wallet Unit selects among them.

## Binding

A `zkp_req` presentation MUST be bound to the presentation session. The proof MUST verify holder binding over the session binding values defined by the registry entry of the selected system.

For `mso_mdoc`, the circuit MUST verify the device signature over the `DeviceAuthentication` structure, which contains the `SessionTranscript`. The `SessionTranscript` is `[null, null, Handover]`, with `Handover` as defined in OpenID4VP 1.0 for the channel that carried the Authorization Request:

| Channel | `Handover` | Defined in |
| :-- | :-- | :-- |
| Digital Credentials API | `OpenID4VPDCAPIHandover` = `["OpenID4VPDCAPIHandover", SHA-256(cbor([origin, nonce, jwkThumbprint]))]` | Appendix B.2.6.2 |
| Redirects, including a request fetched from a `request_uri` that a QR code or a link carries | `OpenID4VPHandover` = `["OpenID4VPHandover", SHA-256(cbor([client_id, nonce, jwkThumbprint, response_uri]))]` | Appendix B.2.6.1 |

The hash input is the CBOR encoding of the array itself. The values are:

* `origin`: the origin of the calling web page.
* `client_id`: the Client Identifier, including its Client Identifier Prefix.
* `nonce`: the `nonce` request parameter, as a text string.
* `response_uri`: the `response_uri` request parameter (or the `redirect_uri` parameter, when the Response Mode uses it).
* `jwkThumbprint`: the JWK SHA-256 Thumbprint (RFC 7638) of the Verifier's response-encryption key, as a 32-byte byte string. The response is always encrypted.

The Wallet Unit MUST take `client_id`, `nonce`, `response_uri` and the response-encryption key from the validated Request Object, and MUST use the `Handover` of the channel on which it received the request. The Verifier MUST compute the `Handover` itself, from the Request Object it sent and, over the Digital Credentials API, the origin of its web page. It MUST NOT take any `Handover` value from the presentation.

The device signature is a `deviceSignature` as defined in ISO/IEC 18013-5: a `COSE_Sign1` with a detached payload, `DeviceAuthenticationBytes`, and empty external data. `deviceMac` is not used. `DeviceNameSpaces` in `DeviceAuthentication` is the empty map. With a P-256 device key, the protected header is exactly `{1: -7}` (ES256).

For `bbs_cd`, the scheme's request binds the session. Its audience is SHA-256 of the `OpenID4VPHandoverInfo` bytes (OpenID4VP 1.0 Appendix B.2.6.1), or of the `OpenID4VPDCAPIHandoverInfo` bytes over the Digital Credentials API (Appendix B.2.6.2). Its nonce is the request's `nonce`. The `ecdsa-pop/0.1` plugin proves that the committed `device_key` signed a message bound to that request.

Over DC API the following applies to bind the pseudonym to the Verifier:

1. Requests for `nym_auth` attestation sent over the Digital Credentials API MUST use the `openid4vp-v1-signed` protocol. An unsigned request MUST be rejected.
2. The Wallet Unit MUST validate the Request Object signature and certificate chain according to the Client Identifier Prefix and, over the Digital Credentials API, MUST verify that the calling origin is contained in `expected_origins`.

Over redirects, including a request fetched from a `request_uri`, the following applies:

1. Requests for `nym_auth` attestation MUST be signed Request Objects. An unsigned request MUST be rejected, so the `redirect_uri` Client Identifier Prefix is not usable. The Wallet Unit MUST validate the Request Object signature and certificate chain according to the Client Identifier Prefix.
2. The Wallet Unit MUST send the Authorization Response only to the `response_uri` of the validated Request Object, the value it uses in the `Handover`.

## Response confidentiality

A `zkp_req` presentation MUST be encrypted to the Verifier. The Response Mode MUST be `direct_post.jwt` over redirects and `dc_api.jwt` over the Digital Credentials API, and the Request Object MUST carry the Verifier's response-encryption key in `client_metadata`. A Wallet Unit MUST treat a request with another Response Mode, or without a response-encryption key, as unsatisfiable.
