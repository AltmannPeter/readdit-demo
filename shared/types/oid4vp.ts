// OpenID4VP 1.0 + `circuit_zk` shapes from the Nym-authentication rulebook (v0.2).

export const NYM_DOCTYPE = 'eu.europa.ec.eudi.nym_auth.1'

export type PseudonymConfig =
  | 'known-offender-matching-ssc'
  | 'known-offender-matching-psc'
  | 'account-recovery-ssc'
  | 'user-managed-pseudonym-xsite-ssc'

export interface PseudonymReq {
  id: 'pseudonym-v1-sha256'
  return: string
  params: {
    config: PseudonymConfig
    verifier_id_type?: 'semantic' | 'x509_san_dns'
    verifier_context?: string
  }
}

export interface AgeCheckReq {
  id: 'age_check'
  return: string
  params: { ge?: string; le?: string }
}

export type ReqItem = PseudonymReq | AgeCheckReq

export interface CircuitZkCredentialQuery {
  id: string
  format: 'circuit_zk'
  meta: { doctype_value: string }
  req: ReqItem[]
  require_cryptographic_holder_binding?: true
}

export interface DcqlQuery {
  credentials: CircuitZkCredentialQuery[]
}

export interface CircuitZkFormats {
  circuit_proof_system_values?: string[]
  circuit_id_values?: string[]
}

/** `wallet_metadata` posted to request_uri when request_uri_method=post. */
export interface WalletMetadata {
  vp_formats_supported: { circuit_zk?: CircuitZkFormats }
}

/** Decoded payload of the Request Object fetched from `request_uri`. */
export interface RequestObject {
  iss?: string
  aud?: string
  iat?: number
  wallet_nonce?: string
  response_type: 'vp_token'
  response_mode: 'direct_post' | 'direct_post.jwt'
  response_uri: string
  client_id: string
  nonce: string
  state: string
  dcql_query: DcqlQuery
  client_metadata: {
    client_name?: string
    vp_formats_supported: { circuit_zk: CircuitZkFormats }
  }
}

/** Decoded `results`: pseudonyms as hex (CBOR bstr on the wire), predicates as true. */
export type Results = Record<string, string | true>

/**
 * vp_token: Credential Query id -> array of presentations, each
 * base64url(CBOR(CircuitZkPresentation)) without padding. Opaque to the site.
 */
export type VpToken = Record<string, string[]>

/** Body posted to `response_uri` (form-encoded on the wire; vp_token as JSON). */
export type AuthorizationResponse =
  | { state: string; vp_token: VpToken }
  | { state: string; error: 'access_denied' | 'invalid_request'; error_description?: string }
