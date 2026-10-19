// OpenID4VP 1.0 + `circuit_zk` shapes from the Nym-authentication rulebook (v0.2), and the
// demo's `mms_zk` profile for BBS credentials with committed disclosures (docs/mms_zk.md).

export const NYM_DOCTYPE = 'eu.europa.ec.eudi.nym_auth.1'
/** The nym_auth attestation as a BBS credential (mms_zk). */
export const NYM_BBS_SCHEMA = 'eu.europa.ec.eudi.nym_auth.bbs.1'

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

/** mms_zk: a pseudonym from the BBS credential's committed seed, nym = seed·OP, returned as
 *  SHA-256(nym). The configuration names its properties, as in pseudonym-v1-sha256. */
export interface PseudonymBbsReq {
  id: 'pseudonym-bbs-v1'
  return: string
  params: { config: 'known-offender-matching-ssc'; verifier_id_type: 'x509_san_dns' }
}

export type MmsReqItem = PseudonymBbsReq | AgeCheckReq

export interface MmsZkCredentialQuery {
  id: string
  format: 'mms_zk'
  meta: { schema_id_value: string }
  req: MmsReqItem[]
  require_cryptographic_holder_binding?: true
}

export type CredentialQuery = CircuitZkCredentialQuery | MmsZkCredentialQuery

/** DCQL credential set: the wallet answers with one of the options (each a list of query ids). */
export interface CredentialSet {
  options: string[][]
  required?: boolean
}

export interface DcqlQuery {
  credentials: CredentialQuery[]
  credential_sets?: CredentialSet[]
}

export interface CircuitZkFormats {
  circuit_proof_system_values?: string[]
  circuit_id_values?: string[]
}

/** mms_zk metadata: the multi-message-signature schemes (schema + plugins) and proof systems. */
export interface MmsZkFormats {
  proof_system_values?: string[]
  scheme_id_values?: string[]
}

/** vp_formats_supported: the formats a verifier accepts, or a wallet supports. */
export interface VpFormats {
  circuit_zk?: CircuitZkFormats
  mms_zk?: MmsZkFormats
}

/** `wallet_metadata` posted to request_uri when request_uri_method=post. */
export interface WalletMetadata {
  vp_formats_supported: VpFormats
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
    vp_formats_supported: VpFormats
  }
}

/** Decoded `results`: pseudonyms as hex (CBOR bstr on the wire), predicates as true. */
export type Results = Record<string, string | true>

/**
 * vp_token: Credential Query id -> array of presentations: for circuit_zk
 * base64url(CBOR(CircuitZkPresentation)), for mms_zk base64url of the BBS-CD envelope, without
 * padding. Opaque to the site.
 */
export type VpToken = Record<string, string[]>

/** Body posted to `response_uri` (form-encoded on the wire; vp_token as JSON). */
export type AuthorizationResponse =
  | { state: string; vp_token: VpToken }
  | { state: string; error: 'access_denied' | 'invalid_request'; error_description?: string }
