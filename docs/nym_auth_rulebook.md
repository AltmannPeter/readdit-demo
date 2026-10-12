---
title: "Nym-authentication Attestation Specification and Rulebook"
author: "Peter Altmann & Frederic Nieto"
version: "0.2"
status: "public draft"
date: "2026-10-09"
---

# Introduction and scope

## Scope

This document specifies the natural-person anonymous/pseudonymous authentication attestation (`eu.europa.ec.eudi.nym_auth.1`). This attestation enables a Holder to:

1. Generate a pseudonym with various properties for authentication, account binding, and known-offender matching.
2. Generate a zero-knowledge proof of correct pseudonym generation.
3. Prove zero-knowledge date-based predicates (e.g., age checks).

This version targets circuit-based Zero-Knowledge Proof (ZKP) presentations using the `circuit_zk` presentation format over an ISO/IEC 18013-5 compliant attestation. The following are out of scope:

* Non-circuit ZKPs (like BBS and other zero-knowledge signature formats).
* Non-ZKP fallbacks.
* SD-JWT VC encodings.
* Details on revocation and validity checks. The circuit checks these using a yet to be mandated mechanism.
* The relationship between the circuit provider and the circuit registry.
* The selection of a trusted issuer.

ZKP proof systems and circuit definitions referenced herein are defined externally in:

* Source for proof systems.
* Source for circuit definitions.

Pseudonym derivation is normatively defined in this document.

Approved circuit verification hashes and parameter mappings are maintained in a registry of approved circuits.

## System roles

* **Issuer:** Issues a signed attestation with attributes and statements about an identity subject.
* **Circuit provider:** Issues a signed circuit suitable for a specified presentation request.
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
| **birth_date** | `birth_date` | `#6.1004(tstr)` (`full-date`) | REQ | Day, month, and year of birth. Used as input for zero-knowledge date comparison predicates. |
| **secret_seed_commitment** | `ssc` | `bstr` (32 bytes) | REQ | **Issuer Known Seed Commitment**: $`C = \text{SHA-256}(\text{secret\_seed})`$ where $`\text{secret\_seed}`$ is a 16-byte random shared secret between the issuer and prover. |
| **private_seed_commitment** | `psc` | `bstr` (32 bytes) | OPT | **Issuer Unknown Seed Commitment**: $`C = \text{SHA-256}(\text{private\_seed})`$ where $`\text{private\_seed}`$ is a 16-byte random value known only to the prover. |

## Mobile Security Object requirements

For ISO/IEC 18013-5 encoded attestations:

* The MSO `validityInfo` MUST contain `signed`, `validFrom` and `validUntil` as defined in ISO/IEC 18013-5.
* The MSO `digestAlgorithm` MUST be `"SHA-256"`.
* `deviceKeyInfo.deviceKey` MUST contain the public key of a device key pair whose private key is protected by [hardware / WSCD reference].
* `issuerAuth` MUST carry the `x5chain` header parameter (label 33) in its unprotected header, containing the Document Signer certificate. The
  `issuerAuth` signature MUST verify under the public key in that certificate.

> **NOTE:** Attestation authenticity is established by the `issuerAuth` signature and its certificate chain. In a `circuit_zk` presentation the signature is verified inside the circuit against the issuer public key set. Certificate chain validation happens when the issuer public key set is built.

---

# ISO/IEC 18013-5 compliant encoding

## Document type and Namespace

For attestations complying with ISO/IEC 18013-5, the Document Type (`docType`) and Namespace MUST both be set to: `eu.europa.ec.eudi.nym_auth.1`

## Attribute encodings and CDDL specification

The complete attribute map for the `eu.europa.ec.eudi.nym_auth.1` namespace MUST conform to the following CDDL specification (RFC 8610):

```cddl
nym_auth_namespace = {
  "birth_date" => full_date,
  "ssc"       => ssc_type,
  ? "psc"     => psc_type
}

full_date = #6.1004(tstr)
ssc_type = bstr .size 32
psc_type = bstr .size 32
```

Each data element is issued as a separate `IssuerSignedItem` as defined in ISO/IEC 18013-5. `birth_date` MUST be a CBOR tag 1004 text string (RFC 8943) containing an RFC 3339 `full-date`.

Approved circuits MUST accept any encoding of these data elements and of the MSO that conforms to ISO/IEC 18013-5.

## Compact profile

An attestation conforms to the compact profile if, in addition to ISO/IEC 18013-5:

* it contains only the data elements defined in this document;
* each `random` value is 16 bytes;
* `digestID` values are assigned sequentially from 0;
* the MSO contains no optional members;
* `validityInfo` values have the form `YYYY-MM-DDTHH:MM:SSZ`;
* the device key and the Document Signer key are P-256 keys.

Issuers SHOULD issue attestations conforming to the compact profile.

A registry entry MAY target the compact profile. The registry MUST contain at least one approved circuit that supports every function and configuration defined in this document and accepts any ISO/IEC 18013-5 conformant encoding. A Wallet Unit SHOULD use a compact-profile circuit when its attestation conforms and the Verifier accepts one.

# DCQL profile and presentation syntax (`circuit_zk`)

## Overview and fail-closed design

This profile extends OpenID4VP Digital Credentials Query Language (DCQL) for zero-knowledge circuit presentations. 

A Wallet Unit that does not support the `circuit_zk` format cannot match a Credential Query that uses it, and therefore returns no presentation for it. For `"format": "circuit_zk"`, issuer-signed attributes are never disclosed directly. All calculations and assertions MUST be requested inside `req`.

### Unsatisfiable Credential Queries

An unsatisfiable request makes the affected Credential Query unsatisfiable; whether the Authorization Request can still be fulfilled follows the DCQL rules of OpenID4VP 1.0, including `credential_sets`. If it cannot, the Wallet Unit returns an Error Response (OpenID4VP 1.0, Section 8.5):

* `invalid_request` MAY be used if the cause is independent of the Holder's attestation data.
* Otherwise `access_denied` MUST be used, without `error_description`.

> **NOTE:** `access_denied` is also returned when the user declines, so data-dependent failures are indistinguishable from refusal. 

## Query structure

A Credential Query targeting `"eu.europa.ec.eudi.nym_auth.1"` MUST observe the following rules:

* `format` (REQUIRED): MUST be set to `"circuit_zk"`
* `meta` (REQUIRED): MUST contain doctype_value set to `"eu.europa.ec.eudi.nym_auth.1"`.
* `req` (REQUIRED): A non-empty array of objects specifying proven zero-knowledge calculations and predicates.

> **NOTE**: Proof system capability negotiation (e.g., supported ZK proof systems) occurs at the protocol level as defined in the capability negotiations subsection.

### `req` item member specification

Each object inside the `req` array MUST contain:

| Member | Type | Presence | Description |
| :--- | :--- | :--- | :--- |
| `id` | String | REQ | Function Type Identifier registered in Section 5 (e.g., `"pseudonym-v1-sha256"`, `"age_check"`). |
| `return` | String | REQ | An output handle unique within the Credential Query for mapping the result into `results`. |
| `params` | Object | OPT | Key-value mapping of declared parameters for the specified function. Omission applies the function's defined defaults. | 

## Response processing and results mapping

The Wallet Unit generates a proof, using one approved circuit, that covers all requested statements in `req` and is bound to the presentation session as defined in the Binding section.

> **NOTE:** It is possible to use two distinct attestations, one for age and one for pseudonym, but if both require 2FA the user experience is degraded. In this version, both age verification and pseudonym are satisfied using a single attestation `nym_auth`.

### Presentation encoding

In the `vp_token`, the value for each `circuit_zk` Credential Query `id` is an array of presentations as defined in OpenID4VP 1.0. Each presentation is the base64url-encoded (without padding) CBOR encoding of a `CircuitZkPresentation`:

```cddl
CircuitZkPresentation = {
  "circuit_id"     => tstr,            ; approved circuit used
  "proof"          => bstr,            ; proof as defined by the proof system
  "issuer_key_set" => IssuerKeySet,
  ? "proof_time"   => tdate,           ; present when the circuit checks validity
  "results"        => Results
}

IssuerKeySet = [+ bstr]                ; DER-encoded Document Signer certificates

Results = { + tstr => ResultValue }    ; keys are the `return` handles in `req`
ResultValue = PseudonymValue / PredicateValue
PseudonymValue = bstr .size 32
PredicateValue = true
```

The keys of `results` MUST be exactly the `return` handles of the items in `req`. The Verifier MUST reject a presentation with missing or additional keys.

`issuer_key_set` is given in the representation defined by the registry entry of `circuit_id`. For an explicit list, each element is a DER-encoded Document Signer certificate, and the Verifier MUST validate each certificate against its trust anchors.

`proof_time` is the time used by the circuit for validity checks. The Verifier MUST reject the presentation if `proof_time` deviates from its own clock by more than its tolerance.

### Verification

To verify a presentation, the Verifier:

1. looks up `circuit_id` in the approved circuit registry and confirms it is
   one it accepts;
2. validates `issuer_key_set`;
3. assembles the public inputs in the order defined by the registry entry,
   taking `issuer_key_set`, `proof_time` and the values in `results` from the
   presentation, and recomputing all other public inputs itself (session
   binding values, `verifier_input`, and the `req` parameters it sent);
4. verifies `proof` against the circuit and the assembled public inputs.

The Verifier MUST NOT take any public input other than `issuer_key_set`,
`proof_time` and `results` from the presentation.

Example `vp_token` (presentation shown in CBOR diagnostic notation before
encoding):

```json
{
  "nym_attestation": ["<base64url(CBOR(CircuitZkPresentation))>"]
}
```

```cbor-diag
{
  "circuit_id": "urn:circuits:longfellow:nym_auth:v1",
  "proof": h'...',
  "issuer_key_set": [h'3082...'],
  "results": {
    "nym-123": h'5f2a...e1',
    "age-range-123": true
  }
}
```

## Example DCQL request

The example shows the decoded payload of a signed Request Object (`openid4vp-v1-signed`), passed to the Digital Credentials API. The JWS is signed with the key of the Verifier's access certificate, carried in the `x5c` header; the leaf certificate MUST contain `rp.example.com` as a dNSName SAN.

> **NOTE:** The example will be updated to align with the OpenID drafts.

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
      "circuit_zk": {
        "circuit_proof_system_values": [
          "longfellow-libzk-v1"
        ],
        "circuit_id_values": [
          "urn:circuits:longfellow:nym_auth:v1"
        ]
      }
    }
  },
  "dcql_query": {
    "credentials": [
      {
        "id": "nym_attestation",
        "format": "circuit_zk",
        "meta": {
          "source_format": "mdoc_mso",
          "doctype_value": "eu.europa.ec.eudi.nym_auth.1"
        },
        "claims": {
          "_req": [
            {
              "fn_id": "pseudonym-v1-sha256",
              "id": "nym-123",
              "params": {
                "config": "known-offender-matching-ssc",
                "verifier_id_type": "x509_san_dns"
              }
            },
            {
              "fn_id": "age_check",
              "id": "age-range-123",
              "params": {
                "ge": "2008-10-10",
                "le": "2013-10-09"
              }
            }
          ]
        }
      }
    ]
  }
}
```
> NOTE: Check where the function outputs defined.

> **NOTE:** Show variations of the sibling vs nesting between `claims` and `_req`

# Function catalogue

Functions invoked inside req MUST be registered in this specification or an official extension profile. Each registered function defines:

1. The mathematical operation, possible intermediate values, and parameter constraints.
2. The implicit credential source attribute(s) bound to the computation.
3. The expected output representation in the presentation response `results` map.

If a Wallet Unit receives a request for a function `id` not defined below or not listed in an approved circuit for the `doctype_value`, the request is unsatisfiable.

## Pseudonym generation function (`pseudonym-v1-sha256`)

Derives a deterministic pseudonym using the SHA-256 instantiation.

* Function identifier (`id`): `"pseudonym-v1-sha256"`.
* Source attribute: `ssc` (or `psc` when configured). Note that the generation does not use `ssc` or `psc` directly, but their openings (`secret_seed` and `private_seed`).
* Output: a 32-byte value (`PseudonymValue`) placed in `results[<handle>]`.

A `req` MUST NOT contain more than one `pseudonym-v1-sha256` item. A Wallet Unit MUST treat a request containing more than one as unsatisfiable.

### Verifier identity

Configurations that use `verifier_input` derive it from `verifier_id`, a UTF-8 string whose form is selected by the Verifier with `verifier_id_type`:

* `semantic`: `"semantic_id:"` followed by the end Relying Party's semantic identifier as defined in ETSI TS 119 475, Section 5.1.3 (legal persons) or Section 5.1.5 (natural persons). The Wallet Unit MUST take it from the registration certificate when one is present, and otherwise from the access certificate.
* `x509_san_dns`: the Client Identifier, i.e. `"x509_san_dns:"` followed by the DNS name bound to the access certificate used to sign the request.

The Wallet Unit MUST treat the request as unsatisfiable if:

* the identifier of the requested type cannot be obtained from authenticated sources;
* `verifier_id_type` is `x509_san_dns` and the Client Identifier uses any other prefix (including `x509_hash`);
* `verifier_id_type` is `x509_san_dns` and the registration certificate identifies an intermediary.

> **NOTE 1:** The two identifier types yield unrelated pseudonyms for the same Relying Party. A Verifier that changes `verifier_id_type` or its identifier loses continuity with existing pseudonyms.
> **NOTE 2:** Outside the EUDIW ecosystem intermediaries cannot be detected; with `x509_san_dns` the pseudonym is then distinct per access-certificate holder, not per end Relying Party.
> **NOTE 3:** Within the EUDIW, an intermediary acting without a registration certificate presents its own semantic identifier, so end Relying Parties behind it share a pseudonym space.

### Parameters

This specification version enables the following function parameters.

| Parameter | Type | Presence | Description | Parameter restrictions | 
| :-- | :-- | :-- | :-- | :-- |
| `config` | string | REQ | Identifier for standard configurations. | Allowed values are specified in the configurations below. |
| `verifier_context` | string | CON | Additional context supplied by the verifier. | Required for account recovery. MUST NOT be present elsewhere. UTF-8, 1–64 bytes. |
| `verifier_id_type` | string | CON | Type of verifier identity used in `verifier_input`. | `semantic` or `x509_san_dns`. Required for configurations that use `verifier_input`; MUST NOT be present otherwise. |

A Wallet Unit MUST treat the request as unsatisfiable if `verifier_context` is absent for a configuration that requires it, present for a configuration that does not allow it, or longer than 64 bytes.

A Wallet Unit MUST treat the request as unsatisfiable if `verifier_id_type` is absent for a configuration that uses `verifier_input`, present for a configuration that does not, or has a value other than `semantic` or `x509_san_dns`.

### Configurations

All configurations generate the pseudonym as: `pseudonym = SHA256(DST || {secret, private}_seed || prover_input || verifier_input)`. The `attribute_source` determines which seed to use. The `DST` is set to `nym_auth/v1/<config>` (UTF-8 encoded). The verifier MUST recompute and supply its own public inputs to the circuit proof verification.

#### `known-offender-matching-ssc`

The `known-offender-matching-ssc` configuration is defined as follows:

1. `attribute_source` is the `ssc` (issuer known seed commitment) value from the `nym_auth` attestation. Used to assert `SHA256(secret_seed) == ssc`; generation uses `secret_seed`.
2. `prover_input` is null (32 zero bytes).
3. `verifier_input` is `SHA256(verifier_id)`, with `verifier_id` as defined in the Verifier identity subsection.

The configuration's properties are as follows:

* The pseudonym value is distinct per `verifier_id`.
* The pseudonym can be remapped to an identity by the issuer, who knows the `secret_seed` value.
* It supports known offender matching.

> **NOTE 1**: If the issuer known seed changes, so does the pseudonym generated. A ban can be evaded by changing the issuer to one using a different issuer known seed.
> **NOTE 2**: If the `verifier_input` changes, so does the pseudonym generated. Known offender matching is not possible if the Verifier identity changes.

#### `known-offender-matching-psc`

1. `attribute_source` is the `psc` (issuer unknown seed commitment) value from the `nym_auth` attestation. Used to assert `SHA256(private_seed) == psc`; generation uses `private_seed`.
2. `prover_input` is null (32 zero bytes).
3. `verifier_input` is `SHA256(verifier_id)`, with `verifier_id` as defined in the Verifier identity subsection.

The configuration's properties are as follows:

* The pseudonym value is distinct per `verifier_id`.
* Remapping the pseudonym to an identity is as hard as brute forcing the `private_seed`, which is intractable.
* To support known offender matching, the issuer MUST only allow one `psc` per identity subject.

> **NOTE 1**: If the issuer changes, it may allow a new `psc`, which changes the pseudonym generated.
> **NOTE 2**: If the `verifier_input` changes, so does the pseudonym generated. Known offender matching is not possible if the Verifier identity changes.

#### `account-recovery-ssc`

1. `attribute_source` is the `ssc` (issuer known seed commitment) value from the `nym_auth` attestation. Used to assert `SHA256(secret_seed) == ssc`; generation uses `secret_seed`.
2. `prover_input` is null (32 zero bytes).
3. `verifier_input` is `SHA256(SHA256(verifier_id) || SHA256(verifier_context))`, with `verifier_id` as defined in the Verifier identity subsection and `verifier_context` UTF-8 encoded as supplied by the Verifier.

The configuration's properties are as follows:

* The pseudonym value is distinct per `verifier_id` and `verifier_context`.
* The pseudonym can be remapped to an identity by the issuer, who knows the `secret_seed` value.
* Supports account recovery for a given account as identified by the `verifier_context`.
* Supports known offender matching per supplied `verifier_context`.

#### `user-managed-pseudonym-xsite-ssc`

1. `attribute_source` is the `ssc` (issuer known seed commitment) value from the `nym_auth` attestation. Used to assert `SHA256(secret_seed) == ssc`; generation uses `secret_seed`.
2. `prover_input` is the SHA256 digest of a user-supplied value; shared across the sites the user wants to be linked across.
3. `verifier_input` is null (32 zero bytes).

Wallet Units MAY add additional entropy to the user-supplied value.

The configuration's properties are as follows:

* The same pseudonym value can be presented to different verifiers.
* Remapping the pseudonym to an identity is as hard as brute forcing the `prover_input`, which is only intractable if that value has
  sufficient entropy.
* Does not offer sybil resistance.
* Does not support known offender matching.

## Date predicate function (`age_check`)

Zero-knowledge comparison operators operating strictly over the `birth_date` attribute (`#6.1004(tstr)`). Used to prove age thresholds, or ranges.

> **NOTE:** Date predicates in this version do not support exact date matches. Because a sufficiently narrow range is equivalent to an exact match, the interval between lower and upper bounds is restricted below. This restriction is specific to this attestation and is not a general rule for other date ranges.

* Function identifier (`id`): `"age_check"`.
* Source attribute: `birth_date`.
* Output: The assertion result `true` placed in `results[<handle>]`.

### Parameters

| Parameter | Type   | Presence | Description |
|-----------|--------|----------|-------------|
| `ge`      | String | OPT | Born on or after date: $`\text{birth\_date} \ge \text{date}`$. |
| `le`      | String | OPT | Born on or before date: $`\text{birth\_date} \le \text{date}`$. |

At least one parameter MUST be present. Dates are RFC 3339 `full-date` strings. Strict bounds are expressed by shifting the date by one day.

A `req` MUST NOT contain more than one `age_check` item. A Wallet Unit MUST treat a request containing more than one `age_check` item as unsatisfiable.

If both `ge` and `le` are present, the Wallet Unit MUST treat the request as unsatisfiable when `le < ge` or when `le − ge + 1` (counted in days) is less than 365.

If the predicate does not hold for the attestation's `birth_date`, the request is unsatisfiable and the Wallet Unit MUST NOT produce a presentation.

# Presentation

## Approved circuits registry entries

The ecosystem maintains a registry of approved circuits. Given the attestation type (`eu.europa.ec.eudi.nym_auth.1`), presentation format (`circuit_zk`), and the requested functions in `req`, the Wallet Unit and Verifier look up an approved circuit from the registry. Each circuit MUST have a unique identifier.

Each registry entry MUST specify: 

* the circuit identifier,
* the proof system,
* the underlying credential format and doctype/vct,
* the supported functions, and parameters,
* the representation of the issuer public key set, and
* the ordered list of public inputs with how the Verifier derives each one.

## Input and output classification

The following MUST be private inputs: `secret_seed`, `private_seed`, `prover_input`, `birth_date`, all issuer-signed data and digests, the issuer signature, the device public key and device signature.

The following MUST be public inputs: `verifier_input`, the session binding values defined by the registry entry, all function parameters values in `req`, `proof_time` when validity is checked, and the issuer public key set.

The pseudonym and predicate results are public outputs.

## The `circuit_zk` format

### Credential Query

For `circuit_zk`, the `meta` object MUST contain exactly one of:

* `doctype_value` (string): the ISO/IEC 18013-5 `docType` of the underlying ISO/IEC 18013-5 attestation.
* `vct_values` (array of strings): reserved for a future SD-JWT VC binding (not defined in this version).

The `circuit_zk` format does not use `claims`. All requests MUST be present in `req`. This version does not define `req_sets` (corresponding to `claim_sets`).

`require_cryptographic_holder_binding` MUST be absent or `true`. A Wallet Unit MUST treat a Credential Query with `require_cryptographic_holder_binding: false` as unsatisfiable.

### Metadata parameters

The following parameters MAY be used in the `circuit_zk` object of `vp_formats_supported`, in Verifier metadata (`client_metadata`) and in Wallet metadata (`wallet_metadata`):

* `circuit_proof_system_values`: OPTIONAL. Non-empty array of proof system identifiers from the approved circuit registry.
* `circuit_id_values`: OPTIONAL. Non-empty array of unique circuit identifiers from the approved circuit registry.

When the Verifier provides these parameters, the Wallet Unit MUST select an approved circuit whose proof system and identifier are both listed and which supports every item in `req`; if none exists, the request is unsatisfiable. The presentation response MUST identify the circuit identifier used.

### Capability negotiation

The Verifier signals the proof systems and circuits it accepts in `client_metadata.vp_formats_supported.circuit_zk`, using the parameters defined above.

When the Authorization Request uses `request_uri_method=post`, the Wallet Unit MAY send the same parameters in `wallet_metadata.vp_formats_supported.circuit_zk`, and the Verifier SHOULD tailor the Request Object to them.

Over the Digital Credentials API, the Wallet Unit cannot send `wallet_metadata`. The Verifier SHOULD therefore list every proof system and circuit identifier it accepts, and the Wallet Unit selects among them.

## Binding

A `circuit_zk` presentation MUST be bound to the presentation session. The circuit MUST verify holder binding over the session binding values defined by the registry entry of the selected circuit.

For attestations identified by `doctype_value` (ISO/IEC 18013-5), the circuit MUST verify the device signature over the `DeviceAuthentication` structure, which contains the `SessionTranscript`. The `SessionTranscript` is `[null, null, Handover]`, with `Handover` constructed as defined in OpenID4VP 1.0 Appendix B.2.6.

> **NOTE:** The validity date is also a range check, but may employ a different mechanism. As it is a required check, it is not something the verifier includes in `req`.

Over DC API the following applies to bind the pseudonym to the Verifier:

1. Requests for `eu.europa.ec.eudi.nym_auth.1` sent over the Digital Credentials API MUST use the `openid4vp-v1-signed` protocol. An unsigned request MUST be rejected.
2. The Wallet Unit MUST validate the Request Object signature and certificate chain according to the Client Identifier Prefix and, over the Digital Credentials API, MUST verify that the calling origin is contained in `expected_origins`.

