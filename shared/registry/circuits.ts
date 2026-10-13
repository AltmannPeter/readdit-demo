// Approved circuit registry (rulebook, "Approved circuits registry entries").
// Each entry states: circuit id, proof system, credential format and doctype,
// supported functions and parameters, issuer key set representation, and the
// ordered public inputs with how the Verifier derives each one.
//
// The Vega entry is what the Vega addon (native/vega) loads: the site offers a circuit only when
// the verifier reports the same id, proof system, public-input names and order, and the SHA-256
// of the circuits as data (server/utils/vp.ts). The Longfellow entry is the demo's working value;
// nothing in this package runs it.

import { NYM_DOCTYPE, type PseudonymConfig } from '../types/oid4vp'

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
