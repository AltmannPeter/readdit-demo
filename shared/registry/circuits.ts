// Approved circuit registry (rulebook, "Approved circuits registry entries").
// Each entry states: circuit id, proof system, credential format and doctype,
// supported functions and parameters, issuer key set representation, and the
// ordered public inputs with how the Verifier derives each one.
//
// The Vega entry is what the Vega addon (native/vega) loads: the site offers a circuit only when
// the verifier reports the same id, proof system, public-input names and order, and the SHA-256
// of the circuits as data (server/utils/vp.ts). The Longfellow entry is the demo's working value;
// nothing in this package runs it.

import { NYM_BBS_SCHEMA, NYM_DOCTYPE, type PseudonymConfig } from '../types/oid4vp'

export interface PublicInput {
  name: string
  source: 'presentation' | 'verifier'
  derivation: string
  /** Field elements the input takes in the circuit, where known. */
  values?: number
}

export interface CircuitEntry {
  circuit_id: string
  proof_system: string
  label: string
  credential_format: 'mso_mdoc'
  doctype: string
  /** 'any' = accepts any ISO/IEC 18013-5 conformant encoding; 'compact' = compact profile only. */
  profile: 'any' | 'compact'
  functions: {
    /** required: the circuit always reveals a pseudonym, so it proves only requests that ask for one. */
    'pseudonym-v1-sha256'?: { configs: PseudonymConfig[]; verifier_id_types: Array<'semantic' | 'x509_san_dns'>; required?: boolean }
    age_check?: { params: Array<'ge' | 'le'> }
  }
  issuer_key_set: 'x509-ds-cert-list'
  checks_validity: boolean
  public_inputs: PublicInput[]
  /** The circuit as data, pinned by hash: the services must report the same. */
  artifact?: { name: string; sha256: string }
}

const NYM_PUBLIC_INPUTS: PublicInput[] = [
  { name: 'issuer_key_set', source: 'presentation', derivation: 'DER Document Signer certificates, validated against trust anchors' },
  { name: 'proof_time', source: 'presentation', derivation: 'checked against the verifier clock within tolerance' },
  { name: 'session_transcript', source: 'verifier', derivation: '[null, null, OpenID4VPHandover] from client_id, nonce, jwk_thumbprint, response_uri' },
  { name: 'pseudonym.config', source: 'verifier', derivation: 'req params as sent' },
  { name: 'pseudonym.verifier_input', source: 'verifier', derivation: 'SHA-256(verifier_id), verifier_id = client_id' },
  { name: 'age_check.ge', source: 'verifier', derivation: 'req params as sent (absent = unbounded)' },
  { name: 'age_check.le', source: 'verifier', derivation: 'req params as sent (absent = unbounded)' },
  { name: 'results', source: 'presentation', derivation: 'pseudonym (32 bytes) and predicate result' },
]

// Vega nym_auth (nym-auth-circuits, SPEC.md V3.2): 18 core public values in this order.
const VEGA_PUBLIC_INPUTS: PublicInput[] = [
  { name: 'issuer_key_set', source: 'presentation', values: 2, derivation: 'one DER Document Signer certificate, validated against the trust anchors; its P-256 key is the issuer key Q' },
  { name: 'age_check.ge', source: 'verifier', values: 1, derivation: 'E = req params as sent; 0000-00-00 when absent' },
  { name: 'age_check.le', source: 'verifier', values: 1, derivation: 'C = req params as sent; 9999-12-31 when absent' },
  { name: 'proof_time', source: 'presentation', values: 1, derivation: 'T, checked against the verifier clock within tolerance' },
  { name: 'session_transcript', source: 'verifier', values: 2, derivation: 'e2 = SHA-256(DeviceAuthentication Sig_structure), SessionTranscript [null, null, OpenID4VPHandover] from client_id, nonce, jwk_thumbprint (null), response_uri' },
  { name: 'doctype', source: 'verifier', values: 3, derivation: 'pattern of the docType eu.europa.ec.eudi.nym_auth.1' },
  { name: 'birth_date.identifier', source: 'verifier', values: 3, derivation: 'pattern of the element identifier birth_date' },
  { name: 'pseudonym.verifier_input', source: 'verifier', values: 3, derivation: 'SHA-256(verifier_id), verifier_id = client_id (x509_san_dns)' },
  { name: 'results.nym', source: 'presentation', values: 2, derivation: 'the pseudonym, 32 bytes' },
]

const NYM_FUNCTIONS: CircuitEntry['functions'] = {
  'pseudonym-v1-sha256': {
    configs: ['known-offender-matching-ssc', 'known-offender-matching-psc', 'account-recovery-ssc', 'user-managed-pseudonym-xsite-ssc'],
    verifier_id_types: ['x509_san_dns', 'semantic'],
  },
  age_check: { params: ['ge', 'le'] },
}

export const CIRCUIT_REGISTRY: CircuitEntry[] = [
  {
    circuit_id: 'urn:circuits:longfellow:nym_auth:v1',
    proof_system: 'longfellow-libzk-v1',
    label: 'Longfellow nym_auth v1',
    credential_format: 'mso_mdoc',
    doctype: NYM_DOCTYPE,
    profile: 'any',
    functions: NYM_FUNCTIONS,
    issuer_key_set: 'x509-ds-cert-list',
    checks_validity: true,
    public_inputs: NYM_PUBLIC_INPUTS,
  },
  {
    circuit_id: 'urn:circuits:vega:nym_auth:v1',
    proof_system: 'vega-v1',
    label: 'Vega nym_auth v1',
    credential_format: 'mso_mdoc',
    doctype: NYM_DOCTYPE,
    profile: 'compact',
    functions: {
      'pseudonym-v1-sha256': { configs: ['known-offender-matching-ssc'], verifier_id_types: ['x509_san_dns'], required: true },
      age_check: { params: ['ge', 'le'] },
    },
    issuer_key_set: 'x509-ds-cert-list',
    checks_validity: true,
    public_inputs: VEGA_PUBLIC_INPUTS,
    artifact: { name: 'shapes.zst', sha256: 'b457ba5382eb7604ef035e790f2cb24f0cd5fdcd065f383ff1c2c49fab1bb4df' },
  },
]

export function findCircuit(id: string): CircuitEntry | undefined {
  return CIRCUIT_REGISTRY.find((c) => c.circuit_id === id)
}

// ---- mms_zk: multi-message-signature schemes (docs/mms_zk.md) ----
//
// A scheme is a BBS credential schema with the plugins that prove the request's functions. The
// site offers a scheme only when the BBS verifier reports the same id, proof system and schema
// digest (server/utils/vp.ts), as for circuits.

export interface SchemeEntry {
  scheme_id: string
  proof_system: string
  label: string
  credential_format: 'mms_zk'
  /** The credential schema: its id and digest (the framework's H(Tr(schema))). */
  schema: { id: string; digest: string }
  /** The catalogue's name for the issuer (the BBS issuer parameters carry no name). */
  issuer: { name: string; country?: string }
  /** The plugins, in the order of the BBS request. */
  plugins: Array<{ id: string; attribute: string; proves: string }>
  functions: {
    'pseudonym-bbs-v1': { configs: Array<'known-offender-matching-ssc'>; verifier_id_types: Array<'x509_san_dns'>; required: true }
    age_check: { params: Array<'ge' | 'le'> }
  }
  /** What both sides derive from the request (the BBS request's binding values). */
  statement: Array<{ name: string; derivation: string }>
}

export const SCHEME_REGISTRY: SchemeEntry[] = [
  {
    scheme_id: 'urn:mms:bbs-cd:nym_auth:v1',
    proof_system: 'bbs-cd-plugins-v0.1',
    label: 'BBS nym_auth v1',
    credential_format: 'mms_zk',
    schema: { id: NYM_BBS_SCHEMA, digest: '2b39f8559b7bf2888502ccac0a681538f218bbf792d826cbad482ee487fb6793' },
    issuer: { name: 'Demo Issuer', country: 'SE' },
    plugins: [
      { id: 'ecdsa-pop/0.1', attribute: 'device_key', proves: 'the committed P-256 device key signed this request (hashed ECDSA)' },
      { id: 'pseudonym/0.1', attribute: 'nym_seed', proves: 'nym = seed·OP, OP = hash_to_curve(config ‖ client_id), from the committed seed' },
      { id: 'date-range/0.1', attribute: 'birth_date', proves: 'the committed birth date lies in [ge, le]' },
    ],
    functions: {
      'pseudonym-bbs-v1': { configs: ['known-offender-matching-ssc'], verifier_id_types: ['x509_san_dns'], required: true },
      age_check: { params: ['ge', 'le'] },
    },
    statement: [
      { name: 'audience', derivation: 'SHA-256(OpenID4VPHandoverInfo): client_id, nonce, jwk_thumbprint (null), response_uri' },
      { name: 'nonce', derivation: 'the request nonce' },
      { name: 'credential', derivation: "the issuer's BBS public key and the schema digest, nothing disclosed" },
      { name: 'pseudonym.verifier_input', derivation: 'client_id (x509_san_dns)' },
      { name: 'age_check', derivation: 'ge and le as sent, as YYYYMMDD' },
    ],
  },
]

export function findScheme(id: string): SchemeEntry | undefined {
  return SCHEME_REGISTRY.find((s) => s.scheme_id === id)
}

/** The proof systems the site can accept, by backend: a label for /tech and the guide. */
export const PROOF_SYSTEMS = [
  { id: 'vega-v1', format: 'circuit_zk', label: 'Vega (mdoc circuit)' },
  { id: 'bbs-cd-plugins-v0.1', format: 'mms_zk', label: 'BBS (committed disclosures)' },
] as const
export type ProofSystemId = (typeof PROOF_SYSTEMS)[number]['id']
