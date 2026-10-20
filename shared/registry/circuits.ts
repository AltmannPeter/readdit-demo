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
  /** 'any' = accepts any ISO/IEC 18013-5 conformant encoding; 'compact' = compact profile only. */
  profile: 'any' | 'compact'
  functions: {
    pseudonym?: PseudonymSupport
    age_check?: { params: Array<'ge' | 'le'> }
  }
  issuer_key_set: 'x509-ds-cert-list'
  checks_validity: boolean
  public_inputs: PublicInput[]
  /** The circuit as data, pinned by hash: the services must report the same. */
  artifact?: { name: string; sha256: string }
}

// Vega nym_auth (nym-auth-circuits, SPEC.md V3.2): 18 core public values in this order.
const VEGA_PUBLIC_INPUTS: PublicInput[] = [
  { name: 'issuer_key_set', source: 'presentation', values: 2, derivation: 'one DER Document Signer certificate, validated against the trust anchors; its P-256 key is the issuer key Q' },
  { name: 'age_check.ge', source: 'verifier', values: 1, derivation: 'E = req params as sent; 0000-00-00 when absent' },
  { name: 'age_check.le', source: 'verifier', values: 1, derivation: 'C = req params as sent; 9999-12-31 when absent' },
  { name: 'proof_time', source: 'presentation', values: 1, derivation: 'T, checked against the verifier clock within tolerance' },
  { name: 'session_transcript', source: 'verifier', values: 2, derivation: 'e2 = SHA-256(DeviceAuthentication Sig_structure), SessionTranscript [null, null, OpenID4VPHandover] from client_id, nonce, jwk_thumbprint (null), response_uri' },
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

export const CIRCUIT_REGISTRY: CircuitEntry[] = [
  {
    system_id: 'urn:circuits:vega:nym_auth:v1',
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
  },
  {
    system_id: 'urn:circuits:longfellow:nym_auth:v1',
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
  },
]

export function findCircuit(id: string): CircuitEntry | undefined {
  return CIRCUIT_REGISTRY.find((c) => c.system_id === id)
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
    age_check: { params: Array<'ge' | 'le'> }
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
      age_check: { params: ['ge', 'le'] },
    },
    issuer_key_set: 'bbs-issuer-pk',
    statement: [
      { name: 'audience', derivation: 'SHA-256(OpenID4VPHandoverInfo): client_id, nonce, jwk_thumbprint (null), response_uri' },
      { name: 'nonce', derivation: 'the request nonce' },
      { name: 'credential', derivation: "the issuer's BBS public key and the schema digest, nothing disclosed" },
      { name: 'pseudonym.verifier_input', derivation: 'UTF-8(verifier_id), verifier_id = client_id (x509_san_dns form)' },
      { name: 'age_check', derivation: 'ge and le as sent, as YYYYMMDD' },
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

/** The type value a system is for: the doctype (mso_mdoc) or the schema id (bbs_cd). */
export const typeValueOfSystem = (e: SystemEntry) => (e.source_format === 'mso_mdoc' ? e.doctype : e.schema.id)

/** The proof systems the site can accept, by backend: a label for /tech and the guide. */
export const PROOF_SYSTEMS = [
  { id: 'vega-v1', source_format: 'mso_mdoc', label: 'Vega (mdoc circuit)' },
  { id: 'longfellow-libzk-v1', source_format: 'mso_mdoc', label: 'Longfellow (mdoc circuits)' },
  { id: 'bbs-cd-plugins-v0.1', source_format: 'bbs_cd', label: 'BBS (committed disclosures)' },
] as const satisfies ReadonlyArray<{ id: string; source_format: SourceFormat; label: string }>
export type ProofSystemId = (typeof PROOF_SYSTEMS)[number]['id']
