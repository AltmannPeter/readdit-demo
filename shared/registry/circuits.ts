// Approved systems registry (rulebook v0.4, "Approved systems registry entries"): circuits over
// mso_mdoc and schemes over bbs_cd. Each entry states the system id, the proof system, the
// source format and its type value, the supported functions and parameters (with the pseudonym
// PRFs), the issuer key set representation, and the Verifier's statement: for a circuit the
// ordered public inputs with how the Verifier derives each one, for a scheme its plugins and how
// the Verifier derives the scheme's request.
//
// Each entry is what an addon loads: Vega (native/vega), Longfellow (native/longfellow) and BBS
// (native/bbs). The site offers a system only when its verifier reports the same id and proof
// system, and for a circuit the same public-input names and order and the SHA-256 of the
// circuits as data, for a scheme the same schema digest and plugins (server/utils/vp.ts).

import { NYM_BBS_SCHEMA, NYM_DOCTYPE, type PseudonymConfig, type PseudonymPrf, type SourceFormat } from '../types/oid4vp'

export interface PublicInput {
  name: string
  source: 'presentation' | 'verifier'
  derivation: string
  /** Field elements the input takes in the circuit, where known. */
  values?: number
}

/** The pseudonym function as a system supports it. required: the system always reveals a
 *  pseudonym, so it proves only requests that ask for one. */
export interface PseudonymSupport {
  configs: PseudonymConfig[]
  prf: PseudonymPrf[]
  ver: number[]
  required?: boolean
}

export interface CircuitEntry {
  system_id: string
  proof_system: string
  label: string
  source_format: 'mso_mdoc'
  doctype: string
  /** 'any' = accepts any ISO/IEC 18013-5 conformant encoding; 'compact' = compact profile only;
   *  'decoy' = the decoy-digest layout (rulebook v0.6) only. */
  profile: 'any' | 'compact' | 'decoy'
  functions: {
    pseudonym?: PseudonymSupport
    age_check?: { params: Array<'ge' | 'le' | 'range'> }
  }
  issuer_key_set: 'x509-ds-cert-list'
  checks_validity: boolean
  public_inputs: PublicInput[]
  /** The circuit as data, pinned by hash: the services must report the same. */
  artifact?: { name: string; sha256: string }
  /** The rulebook version whose credential and requests the circuit reads (a demo profile's
   *  `rulebook.version`): v0.4 (birth_date, ssc) or v0.5 (bsc). */
  rulebook: string
}

/** A circuit's id (Peter, 2026-10-28): `urn:circuits:sha256:` and the SHA-256 of its archive as
 *  shipped, so each set of circuits has its own id. */
export const circuitId = (archiveSha256: string) => `urn:circuits:sha256:${archiveSha256}`

// Vega nym_auth (nym-auth-circuits, SPEC.md V3.2): 18 core public values in this order.
const VEGA_PUBLIC_INPUTS: PublicInput[] = [
  { name: 'issuer_key_set', source: 'presentation', values: 2, derivation: 'one DER Document Signer certificate, validated against the trust anchors; its P-256 key is the issuer key Q' },
  { name: 'age_check.ge', source: 'verifier', values: 1, derivation: 'E = req params as sent; 0000-00-00 when absent' },
  { name: 'age_check.le', source: 'verifier', values: 1, derivation: 'C = req params as sent; 9999-12-31 when absent' },
  { name: 'proof_time', source: 'presentation', values: 1, derivation: 'T, checked against the verifier clock within tolerance' },
  { name: 'session_transcript', source: 'verifier', values: 2, derivation: 'e2 = SHA-256(DeviceAuthentication Sig_structure), SessionTranscript [null, null, OpenID4VPHandover] from client_id, nonce, jwk_thumbprint (the thumbprint of the response encryption key), response_uri' },
  { name: 'doctype', source: 'verifier', values: 3, derivation: 'pattern of the docType eu.europa.ec.eudi.nym_auth.1' },
  { name: 'birth_date.identifier', source: 'verifier', values: 3, derivation: 'pattern of the element identifier birth_date' },
  { name: 'pseudonym.verifier_input', source: 'verifier', values: 3, derivation: 'SHA-256(verifier_id); the trust framework fixes the x509_san_dns form, so verifier_id = client_id' },
  { name: 'results.nym', source: 'presentation', values: 2, derivation: 'the pseudonym, 32 bytes' },
]

// Longfellow nym_auth (nym-auth-circuits, SPEC.md L3): the public slots of the hash circuit
// (GF(2^128)) and of the signature circuit (P-256), by input; values = elements in both.
const LONGFELLOW_PUBLIC_INPUTS: PublicInput[] = [
  { name: 'proof_time', source: 'presentation', values: 160, derivation: 'T, the bits of YYYY-MM-DDThh:mm:ssZ (hash circuit), checked against the verifier clock within tolerance' },
  { name: 'age_check.ge', source: 'verifier', values: 80, derivation: 'E = req params as sent; 0000-00-00 when absent (hash circuit)' },
  { name: 'age_check.le', source: 'verifier', values: 80, derivation: 'C = req params as sent; 9999-12-31 when absent (hash circuit)' },
  { name: 'pseudonym.verifier_input', source: 'verifier', values: 256, derivation: 'SHA-256(verifier_id), verifier_id = client_id (x509_san_dns form), as bits (hash circuit)' },
  { name: 'mac.tags', source: 'presentation', values: 774, derivation: 'the 6 MAC tags at the head of the proof, in both circuits: they tie the signed message and the device key the hash circuit reads to those the signature circuit verifies' },
  { name: 'mac.a_v', source: 'verifier', values: 129, derivation: "the verifier's MAC key share, drawn from the Fiat–Shamir transcript after both commitments, in both circuits" },
  { name: 'results.nym', source: 'presentation', values: 2, derivation: 'the pseudonym, 32 bytes, as two GF(2^128) halves (hash circuit)' },
  { name: 'issuer_key_set', source: 'presentation', values: 2, derivation: 'one DER Document Signer certificate, validated against the trust anchors; its P-256 key is the issuer key Q (signature circuit)' },
  { name: 'session_transcript', source: 'verifier', values: 256, derivation: 'e2 = SHA-256(DeviceAuthentication Sig_structure) as bits (signature circuit); the SessionTranscript [null, null, OpenID4VPHandover] also seeds the Fiat–Shamir transcript' },
]

// Longfellow nym_auth under rulebook v0.5: the nym-auth-zk bsc circuits (Peter's package
// nym-auth-longfellow v1.1, INTEGRATION.md §7), with their own id. Hash circuit 277 + 1 = 278 public
// slots, signature circuit 1154 + 1 = 1155; values = elements in both, circuit order.
const LONGFELLOW_V05_PUBLIC_INPUTS: PublicInput[] = [
  { name: 'doctype', source: 'verifier', values: 8, derivation: 'the pattern 67 "docType" 78 1c and the docType eu.europa.ec.eudi.nym_auth.1: two 16-byte limbs, then 6 byte elements (hash circuit)' },
  { name: 'proof_time', source: 'presentation', values: 2, derivation: 'T = YYYYMMDDhhmmss as x^(T+533333333333328) and x^(T+533333333333329) (hash circuit), checked against the verifier clock within tolerance, outside the proof' },
  { name: 'pseudonym.verifier_input', source: 'verifier', values: 256, derivation: 'SHA-256(verifier_id), verifier_id = client_id (x509_san_dns form), as bits (hash circuit)' },
  { name: 'results.nym', source: 'presentation', values: 2, derivation: 'the pseudonym, 32 bytes, as two 16-byte halves (hash circuit)' },
  { name: 'age_check.ge', source: 'verifier', values: 1, derivation: 'E from the range and the UTC date of proof_time, as x^(E+533333328); 0 when absent (hash circuit)' },
  { name: 'age_check.le', source: 'verifier', values: 1, derivation: 'C from the range and the UTC date of proof_time, as x^(C+533333328); 99999999 when absent (hash circuit)' },
  { name: 'mac.challenge', source: 'verifier', values: 129, derivation: 'c, 16 Fiat–Shamir bytes drawn after both commitments, in both circuits (bits in the signature circuit)' },
  { name: 'mac.tags', source: 'presentation', values: 774, derivation: 't_k = a_k + c·m_k, the six 16-byte words at the head of the proof, in both circuits: they tie the signed message and the device key the hash circuit reads to those the signature circuit verifies' },
  { name: 'issuer_key_set', source: 'presentation', values: 2, derivation: 'one DER Document Signer certificate, validated against the trust anchors; its P-256 key is the issuer key Q (signature circuit)' },
  { name: 'session_transcript', source: 'verifier', values: 256, derivation: 'e2 = SHA-256(DeviceAuthentication Sig_structure) as bits (signature circuit); the transcript starts from "nym_auth/v1/mdoc-bsc/longfellow" ‖ e2' },
]

// Longfellow nym_auth under rulebook v0.6: the nym-auth-zk-decoy circuits over the decoy-digest
// layout (Peter's package nym-auth-longfellow-decoy-v1, INTEGRATION.md §7), with their own id. Hash
// circuit 268 + 1 = 269 public slots, signature circuit 1154 + 1 = 1155; values = elements in both,
// circuit order (nym-longfellow/src/decoy.rs, PUBLIC_INPUTS). No doctype entry: the layout fixes it.
const LONGFELLOW_DECOY_PUBLIC_INPUTS: PublicInput[] = [
  { name: 'proof_time', source: 'presentation', values: 1, derivation: 'x^(T+533333333333328), T = YYYYMMDDhhmmss (UTC); tolerance checked outside the proof' },
  { name: 'pseudonym.verifier_input', source: 'verifier', values: 256, derivation: 'SHA-256(verifier_id), bit j of byte d at 8d+j; verifier_id = client_id' },
  { name: 'results.nym', source: 'presentation', values: 2, derivation: "the pseudonym's two 16-byte halves, LE" },
  { name: 'age_check.ge', source: 'verifier', values: 1, derivation: 'x^(E+533333328); E = 0 when absent' },
  { name: 'age_check.le', source: 'verifier', values: 1, derivation: 'x^(C+533333328); C = 99999999 when absent' },
  { name: 'mac.challenge', source: 'verifier', values: 129, derivation: 'c, 16 Fiat-Shamir bytes after both commitments (1 in the hash circuit, 128 bits in the signature circuit)' },
  { name: 'mac.tags', source: 'presentation', values: 774, derivation: 't_k = a_k + c m_k, the six words at the head of the proof (6 + 768 bits)' },
  { name: 'issuer_key_set', source: 'presentation', values: 2, derivation: "Q's x and y" },
  { name: 'session_transcript', source: 'verifier', values: 256, derivation: "e2's 256 bits, least significant first" },
]

// Vega nym_auth under rulebook v0.5: vega-age 0.2.0's bsc core (Peter's package nym-auth-vega v1,
// INTEGRATION.md §3), with its own id. 15 core public values in this order; the verifier names the
// first 13, the proof reports the last 2.
const VEGA_V05_PUBLIC_INPUTS: PublicInput[] = [
  { name: 'issuer_key_set', source: 'presentation', values: 2, derivation: 'one DER Document Signer certificate, validated against the trust anchors; its P-256 key is the issuer key Q (x, y)' },
  { name: 'age_check.ge', source: 'verifier', values: 1, derivation: 'E as YYYYMMDD from the range on the UTC date of proof_time; 0 when absent' },
  { name: 'age_check.le', source: 'verifier', values: 1, derivation: 'C as YYYYMMDD from the range on the UTC date of proof_time; 99999999 when absent' },
  { name: 'proof_time', source: 'presentation', values: 1, derivation: 'YYYYMMDDhhmmss (UTC), checked against the verifier clock within tolerance' },
  { name: 'session_transcript', source: 'verifier', values: 2, derivation: 'e2 = SHA-256(DeviceAuthentication Sig_structure), two 16-byte halves; SessionTranscript [null, null, OpenID4VPHandover]' },
  { name: 'doctype', source: 'verifier', values: 3, derivation: 'pattern of the docType eu.europa.ec.eudi.nym_auth.1' },
  { name: 'pseudonym.verifier_input', source: 'verifier', values: 3, derivation: 'SHA-256(verifier_id), verifier_id = client_id' },
  { name: 'results.nym', source: 'presentation', values: 2, derivation: 'the pseudonym, 32 bytes, two halves' },
]

export const CIRCUIT_REGISTRY: CircuitEntry[] = [
  {
    system_id: circuitId('b457ba5382eb7604ef035e790f2cb24f0cd5fdcd065f383ff1c2c49fab1bb4df'),
    proof_system: 'vega-v1',
    label: 'Vega nym_auth v1',
    source_format: 'mso_mdoc',
    doctype: NYM_DOCTYPE,
    profile: 'compact',
    functions: {
      pseudonym: { configs: ['known-offender-matching-ssc'], prf: ['sha-256'], ver: [1], required: true },
      age_check: { params: ['ge', 'le'] },
    },
    issuer_key_set: 'x509-ds-cert-list',
    checks_validity: true,
    public_inputs: VEGA_PUBLIC_INPUTS,
    artifact: { name: 'shapes.zst', sha256: 'b457ba5382eb7604ef035e790f2cb24f0cd5fdcd065f383ff1c2c49fab1bb4df' },
    rulebook: '0.4',
  },
  {
    system_id: circuitId('7df07fefef643512270e2de4964bc1f9b6238015225cfd872e2fb35e7bb80794'),
    proof_system: 'vega-v1',
    label: 'Vega nym_auth v0.5 (bsc)',
    source_format: 'mso_mdoc',
    doctype: NYM_DOCTYPE,
    profile: 'compact',
    functions: {
      pseudonym: { configs: ['known-offender-matching-ssc'], prf: ['sha-256'], ver: [1], required: true },
      age_check: { params: ['range'] },
    },
    issuer_key_set: 'x509-ds-cert-list',
    checks_validity: true,
    public_inputs: VEGA_V05_PUBLIC_INPUTS,
    artifact: { name: 'shapes.zst', sha256: '7df07fefef643512270e2de4964bc1f9b6238015225cfd872e2fb35e7bb80794' },
    rulebook: '0.5',
  },
  {
    system_id: circuitId('f4d75ee2a112c63adfb00f1da45347c4691085c8cca6ab13cee7b03f00cdbd52'),
    proof_system: 'longfellow-libzk-v1',
    label: 'Longfellow nym_auth v1 (bsc)',
    source_format: 'mso_mdoc',
    doctype: NYM_DOCTYPE,
    profile: 'compact',
    functions: {
      pseudonym: { configs: ['known-offender-matching-ssc'], prf: ['sha-256'], ver: [1], required: true },
      age_check: { params: ['range'] },
    },
    issuer_key_set: 'x509-ds-cert-list',
    checks_validity: true,
    public_inputs: LONGFELLOW_V05_PUBLIC_INPUTS,
    artifact: { name: 'nym_auth_mdoc_bsc.lfa2.zst', sha256: 'f4d75ee2a112c63adfb00f1da45347c4691085c8cca6ab13cee7b03f00cdbd52' },
    rulebook: '0.5',
  },
  {
    system_id: circuitId('5d7d2b5d094032df5b02f576d2ae7b99d3f0932d47516336693f8d670cfd63ac'),
    proof_system: 'longfellow-libzk-v1',
    label: 'Longfellow nym_auth v0.6 (decoy digests)',
    source_format: 'mso_mdoc',
    doctype: NYM_DOCTYPE,
    profile: 'decoy',
    functions: {
      pseudonym: { configs: ['known-offender-matching-ssc'], prf: ['sha-256'], ver: [1], required: true },
      age_check: { params: ['range'] },
    },
    issuer_key_set: 'x509-ds-cert-list',
    checks_validity: true,
    public_inputs: LONGFELLOW_DECOY_PUBLIC_INPUTS,
    artifact: { name: 'nym_auth_mdoc_decoy.lfa2.zst', sha256: '5d7d2b5d094032df5b02f576d2ae7b99d3f0932d47516336693f8d670cfd63ac' },
    rulebook: '0.6',
  },
  {
    system_id: circuitId('6c4b96ed431ee547a3a2e5b62621943a9a0a44646267653bf2db0fcc269b5c3b'),
    proof_system: 'longfellow-libzk-v1',
    label: 'Longfellow nym_auth v1',
    source_format: 'mso_mdoc',
    doctype: NYM_DOCTYPE,
    profile: 'compact',
    functions: {
      pseudonym: { configs: ['known-offender-matching-ssc'], prf: ['sha-256'], ver: [1], required: true },
      age_check: { params: ['ge', 'le'] },
    },
    issuer_key_set: 'x509-ds-cert-list',
    checks_validity: true,
    public_inputs: LONGFELLOW_PUBLIC_INPUTS,
    artifact: { name: 'circuits.zst', sha256: '6c4b96ed431ee547a3a2e5b62621943a9a0a44646267653bf2db0fcc269b5c3b' },
    rulebook: '0.4',
  },
]

export function findCircuit(id: string): CircuitEntry | undefined {
  return CIRCUIT_REGISTRY.find((x) => x.system_id === id)
}

// ---- bbs_cd: schemes (rulebook v0.4, "BBS committed-disclosure encoding"; docs/bbs_cd.md) ----
//
// A scheme is a BBS credential schema with the plugins that prove the request's functions.

export interface SchemeEntry {
  system_id: string
  proof_system: string
  label: string
  source_format: 'bbs_cd'
  /** The credential schema: its id and digest (the framework's H(Tr(schema))). */
  schema: { id: string; digest: string }
  /** The catalogue's name for the issuer (the BBS issuer parameters carry no name). */
  issuer: { name: string; country?: string }
  /** The plugins, in the order of the BBS request. */
  plugins: Array<{ id: string; attribute: string; proves: string }>
  functions: {
    pseudonym: PseudonymSupport
    age_check: { params: Array<'ge' | 'le' | 'range'> }
  }
  /** The issuer key set: one BBS issuer public key (96 bytes), so the Verifier sees the issuer. */
  issuer_key_set: 'bbs-issuer-pk'
  /** What both sides derive from the request (the BBS request's binding values). */
  statement: Array<{ name: string; derivation: string }>
}

export const SCHEME_REGISTRY: SchemeEntry[] = [
  {
    system_id: 'urn:mms:bbs-cd:nym_auth:v1',
    proof_system: 'bbs-cd-plugins-v0.1',
    label: 'BBS nym_auth v1',
    source_format: 'bbs_cd',
    schema: { id: NYM_BBS_SCHEMA, digest: 'ab4183a9ed0b57d6bfb8994c92b432bb9731a3e2fd974ac2f67422e2f7dfb7e1' },
    issuer: { name: 'Demo Issuer', country: 'SE' },
    plugins: [
      { id: 'ecdsa-pop/0.1', attribute: 'device_key', proves: 'the committed P-256 device key signed this request (hashed ECDSA)' },
      { id: 'pseudonym/0.1', attribute: 'secret_seed', proves: 'pseudonym = secret_seed·OP, OP = hash_to_curve_G1(u8(len(config)) ‖ config ‖ verifier_input), from the committed seed (hashdh-bls12381g1)' },
      { id: 'date-range/0.1', attribute: 'birth_date', proves: 'the committed birth date lies in [ge, le]' },
    ],
    functions: {
      pseudonym: { configs: ['known-offender-matching-ssc'], prf: ['hashdh-bls12381g1'], ver: [1], required: true },
      // ge/le: rulebook v0.4; range (ages in years, bounds from the date of proof_time): v0.5.
      age_check: { params: ['ge', 'le', 'range'] },
    },
    issuer_key_set: 'bbs-issuer-pk',
    statement: [
      { name: 'audience', derivation: 'SHA-256(OpenID4VPHandoverInfo): client_id, nonce, jwk_thumbprint (the thumbprint of the response encryption key), response_uri' },
      { name: 'nonce', derivation: 'the request nonce' },
      { name: 'credential', derivation: "the issuer's BBS public key and the schema digest, nothing disclosed" },
      { name: 'pseudonym.verifier_input', derivation: 'UTF-8(verifier_id), verifier_id = client_id (x509_san_dns form)' },
      { name: 'age_check', derivation: 'v0.4: ge and le as sent; v0.5: E and C from range and the UTC date of proof_time; as YYYYMMDD' },
    ],
  },
]

export function findScheme(id: string): SchemeEntry | undefined {
  return SCHEME_REGISTRY.find((s) => s.system_id === id)
}

export type SystemEntry = CircuitEntry | SchemeEntry

/** Every approved system, in the order of preference: Vega, Longfellow, BBS. */
export const SYSTEM_REGISTRY: SystemEntry[] = [...CIRCUIT_REGISTRY, ...SCHEME_REGISTRY]

export function findSystem(id: string): SystemEntry | undefined {
  return SYSTEM_REGISTRY.find((s) => s.system_id === id)
}

/** The approved systems for rulebook `version` (a demo profile's): the circuits that read its
 *  credential and requests, and the schemes (BBS reads both versions). */
export function registryFor(version?: string): SystemEntry[] {
  return SYSTEM_REGISTRY.filter((e) => e.source_format !== 'mso_mdoc' || !version || e.rulebook === version)
}

/** The type value a system is for: the doctype (mso_mdoc) or the schema id (bbs_cd). */
export const typeValueOfSystem = (e: SystemEntry) => (e.source_format === 'mso_mdoc' ? e.doctype : e.schema.id)

/** The proof systems the site can accept, by backend: a label for /tech and the guide. */
export const PROOF_SYSTEMS = [
  { id: 'vega-v1', source_format: 'mso_mdoc', label: 'Vega (mdoc circuit)' },
  { id: 'longfellow-libzk-v1', source_format: 'mso_mdoc', label: 'Longfellow (mdoc circuits)' },
  { id: 'bbs-cd-plugins-v0.1', source_format: 'bbs_cd', label: 'BBS (committed disclosures)' },
] as const satisfies ReadonlyArray<{ id: string; source_format: SourceFormat; label: string }>
export type ProofSystemId = (typeof PROOF_SYSTEMS)[number]['id']
