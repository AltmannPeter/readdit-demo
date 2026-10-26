import type { BirthDateRange } from '../types'
import { findSystem } from '../registry/circuits'
import {
  NYM_BBS_SCHEMA,
  NYM_DOCTYPE,
  type DcqlQuery,
  type EncryptionJwk,
  type ReqItem,
  type RequestObject,
  type SourceFormat,
  type VpFormats,
  type ZkpReqCredentialQuery,
} from '../types/oid4vp'

/** The query over the mdoc (mso_mdoc). */
export const CREDENTIAL_QUERY_ID = 'nym_attestation'
/** The query over the same attestation as a BBS credential (bbs_cd). */
export const BBS_QUERY_ID = 'nym_attestation_bbs'
export const RETURN_PSEUDONYM = 'nym'
export const RETURN_AGE = 'age'

/** The pseudonym's PRF per source format (rulebook v0.4, "Parameters"). */
export const PRF_FOR: Record<SourceFormat, 'sha-256' | 'hashdh-bls12381g1'> = { mso_mdoc: 'sha-256', bbs_cd: 'hashdh-bls12381g1' }

/** A zkp_req query over `source`: the pseudonym always; age_check when a birth-date range is required. */
export function buildCredentialQuery(source: SourceFormat, age?: BirthDateRange): ZkpReqCredentialQuery {
  const _req: ReqItem[] = [{ fn_id: 'pseudonym', return: RETURN_PSEUDONYM, params: { config: 'known-offender-matching-ssc', ver: 1, prf: PRF_FOR[source] } }]
  if (age) _req.push({ fn_id: 'age_check', return: RETURN_AGE, params: { ...age } })
  return source === 'mso_mdoc'
    ? { id: CREDENTIAL_QUERY_ID, format: 'zkp_req', meta: { source_format: 'mso_mdoc', doctype_value: NYM_DOCTYPE }, _req }
    : { id: BBS_QUERY_ID, format: 'zkp_req', meta: { source_format: 'bbs_cd', schema_id_value: NYM_BBS_SCHEMA }, _req }
}

/** The source formats of the systems an offer lists, in the offer's order. */
export function sourcesOf(offer: VpFormats): SourceFormat[] {
  const ids = offer.zkp_req?.system_id_values ?? []
  return [...new Set(ids.map((id) => findSystem(id)?.source_format).filter((f): f is SourceFormat => !!f))]
}

/**
 * The DCQL query for the systems the site accepts (`offer`): one zkp_req credential query per
 * source format, in the offer's order (mso_mdoc, then bbs_cd), and, with more than one, a
 * credential set whose options are the alternatives, so the wallet answers exactly one of them.
 */
export function buildDcqlQuery(offer: VpFormats, age?: BirthDateRange): DcqlQuery {
  const credentials = sourcesOf(offer).map((f) => buildCredentialQuery(f, age))
  return credentials.length > 1 ? { credentials, credential_sets: [{ options: credentials.map((q) => [q.id]) }] } : { credentials }
}

export function clientIdFor(host: string): string {
  return `x509_san_dns:${host}`
}

export function requestUriFor(origin: string, sessionId: string): string {
  return `${origin}/api/vp/request/${sessionId}`
}

export function responseUriFor(origin: string, sessionId: string): string {
  return `${origin}/api/vp/response/${sessionId}`
}

/** Cross-device invocation URL shown as QR code. POST lets the wallet send wallet_metadata. */
export function authorizationUrl(host: string, requestUri: string): string {
  const q = new URLSearchParams({ client_id: clientIdFor(host), request_uri: requestUri, request_uri_method: 'post' })
  return `openid4vp://?${q.toString()}`
}

export function buildRequestObject(o: {
  host: string
  origin: string
  siteName: string
  sessionId: string
  nonce: string
  state: string
  dcql: DcqlQuery
  formats: VpFormats
  walletNonce?: string
  /** The session's response encryption key: direct_post.jwt with this key in client_metadata.jwks. */
  encryptionJwk: EncryptionJwk
}): RequestObject {
  return {
    aud: 'https://self-issued.me/v2',
    iat: Math.floor(Date.now() / 1000),
    ...(o.walletNonce && { wallet_nonce: o.walletNonce }),
    response_type: 'vp_token',
    response_mode: 'direct_post.jwt',
    response_uri: responseUriFor(o.origin, o.sessionId),
    client_id: clientIdFor(o.host),
    nonce: o.nonce,
    state: o.state,
    dcql_query: o.dcql,
    client_metadata: {
      client_name: o.siteName,
      vp_formats_supported: o.formats,
      jwks: { keys: [o.encryptionJwk] },
    },
  }
}
