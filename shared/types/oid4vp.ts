// OpenID4VP 1.0 with the `zkp_req` format of the Nym-authentication rulebook (v0.4 and v0.5, by
// demo profile, shared/profiles): one DCQL
// format for zero-knowledge presentations over either encoding of the nym_auth attestation,
// ISO/IEC 18013-5 (`mso_mdoc`, proved with circuits) and BBS committed disclosures (`bbs_cd`,
// proved with a scheme and its plugins).

export const NYM_DOCTYPE = 'eu.europa.ec.eudi.nym_auth.1'
/** The nym_auth attestation's bbs_cd schema id. */
export const NYM_BBS_SCHEMA = 'eu.europa.ec.eudi.nym_auth.bbs.1'

/** The attestation encodings a zkp_req query can name in `meta.source_format`. */
export type SourceFormat = 'mso_mdoc' | 'bbs_cd'

export type PseudonymConfig =
  | 'known-offender-matching-ssc'
  | 'known-offender-matching-psc'
  | 'account-recovery-ssc'
  | 'user-managed-pseudonym-xsite-ssc'

/** The pseudonym's PRF: `sha-256` (mso_mdoc), `hashdh-bls12381g1` (bbs_cd, a 48-byte G1 point). */
export type PseudonymPrf = 'sha-256' | 'hashdh-bls12381g1'

export interface PseudonymReq {
  fn_id: 'pseudonym'
  return: string
  params: {
    config: PseudonymConfig
    ver: 1
    prf: PseudonymPrf
    verifier_context?: string
  }
}

/** age_check: a value function in v0.4 (`return`, params `ge`/`le` birth-date bounds), an
 *  assertion in v0.5 (no `return`, param `range` in whole years). The profile decides
 *  (shared/protocol/request.ts). */
export interface AgeCheckReq {
  fn_id: 'age_check'
  return?: string
  params: { ge?: string; le?: string; range?: string }
}

export type ReqItem = PseudonymReq | AgeCheckReq

/** `meta` of a zkp_req query: the source format and its type value. */
export type ZkpReqMeta = { source_format: 'mso_mdoc'; doctype_value: string } | { source_format: 'bbs_cd'; schema_id_value: string }

export interface ZkpReqCredentialQuery {
  id: string
  format: 'zkp_req'
  meta: ZkpReqMeta
  /** Proven, never disclosed. */
  _req: ReqItem[]
  require_cryptographic_holder_binding?: true
}

export type CredentialQuery = ZkpReqCredentialQuery

/** The type value of a query's meta: the doctype (mso_mdoc) or the schema id (bbs_cd). */
export const typeValueOf = (m: ZkpReqMeta) => (m.source_format === 'mso_mdoc' ? m.doctype_value : m.schema_id_value)

/** DCQL credential set: the wallet answers with one of the options (each a list of query ids). */
export interface CredentialSet {
  options: string[][]
  required?: boolean
}

export interface DcqlQuery {
  credentials: CredentialQuery[]
  credential_sets?: CredentialSet[]
}

/** `vp_formats_supported.zkp_req`: proof systems and system ids (circuits and schemes). */
export interface ZkpReqFormats {
  proof_system_values?: string[]
  system_id_values?: string[]
}

/** vp_formats_supported: the formats a verifier accepts, or a wallet supports. */
export interface VpFormats {
  zkp_req?: ZkpReqFormats
}

/** `wallet_metadata` posted to request_uri when request_uri_method=post. */
export interface WalletMetadata {
  vp_formats_supported: VpFormats
  /** The response encryption the wallet supports (direct_post.jwt). */
  authorization_encryption_alg_values_supported?: string[]
  authorization_encryption_enc_values_supported?: string[]
}

/** The Response Modes the demo uses: direct_post.cwt (zkp_req.md §6.2: a CBOR response in a
 *  COSE_Encrypt, the body itself) and direct_post.jwt (OpenID4VP 1.0: a JSON response in a JWE,
 *  posted as `response`); plain direct_post only for an error the wallet cannot encrypt. */
export type ResponseMode = 'direct_post' | 'direct_post.jwt' | 'direct_post.cwt'
/** The encrypted Response Modes the site can ask for (/tech's switch). */
export const ENCRYPTED_RESPONSE_MODES = ['direct_post.cwt', 'direct_post.jwt'] as const
export type EncryptedResponseMode = (typeof ENCRYPTED_RESPONSE_MODES)[number]

/** Decoded payload of the Request Object fetched from `request_uri`. */
export interface RequestObject {
  iss?: string
  aud?: string
  iat?: number
  wallet_nonce?: string
  response_type: 'vp_token'
  response_mode: ResponseMode
  response_uri: string
  client_id: string
  nonce: string
  state: string
  dcql_query: DcqlQuery
  client_metadata: {
    client_name?: string
    vp_formats_supported: VpFormats
    /** direct_post.cwt and direct_post.jwt: the verifier's ephemeral key to encrypt the response to. */
    jwks?: { keys: EncryptionJwk[] }
    /** Absent: A128GCM only (OpenID4VP 1.0). */
    encrypted_response_enc_values_supported?: string[]
  }
}

/** A public key in client_metadata.jwks. */
export interface EncryptionJwk {
  kty: string
  crv?: string
  x?: string
  y?: string
  kid?: string
  use?: string
  alg?: string
}

/** Decoded `results`: pseudonyms as hex (CBOR bstr on the wire: 32 bytes for sha-256, 48 for
 *  hashdh-bls12381g1), predicates as true. */
export type Results = Record<string, string | true>

/**
 * vp_token: Credential Query id -> array of presentations, each base64url(CBOR(ZkpPresentation))
 * without padding. Opaque to the site.
 */
export type VpToken = Record<string, string[]>

/** The response parameters. direct_post.jwt: the payload of the JWE posted as `response`
 *  (vp_token as a JSON object). Unencrypted direct_post: form fields, vp_token as JSON text. */
export type AuthorizationResponse =
  | { state: string; vp_token: VpToken }
  | { state: string; error: 'access_denied' | 'invalid_request'; error_description?: string }
