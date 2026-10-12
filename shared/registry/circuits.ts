// Approved circuit registry (rulebook, "Approved circuits registry entries").
// Each entry states: circuit id, proof system, credential format and doctype,
// supported functions and parameters, issuer key set representation, and the
// ordered public inputs with how the Verifier derives each one.
//
// The identifiers and public-input order below are the demo's working values.
// They must match the circuits the prover/verifier services actually load.

import { NYM_DOCTYPE, type PseudonymConfig } from '../types/oid4vp'

export interface PublicInput {
  name: string
  source: 'presentation' | 'verifier'
  derivation: string
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
    'pseudonym-v1-sha256'?: { configs: PseudonymConfig[]; verifier_id_types: Array<'semantic' | 'x509_san_dns'> }
    age_check?: { params: Array<'ge' | 'le'> }
  }
  issuer_key_set: 'x509-ds-cert-list'
  checks_validity: boolean
  public_inputs: PublicInput[]
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
    profile: 'any',
    functions: NYM_FUNCTIONS,
    issuer_key_set: 'x509-ds-cert-list',
    checks_validity: true,
    public_inputs: NYM_PUBLIC_INPUTS,
  },
]

export function findCircuit(id: string): CircuitEntry | undefined {
  return CIRCUIT_REGISTRY.find((c) => c.circuit_id === id)
}
