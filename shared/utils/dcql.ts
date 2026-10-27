import { findSystem } from '../registry/circuits'
import type { Profile } from '../profiles'
import { typeValue } from '../profiles'
import { buildReq } from '../protocol/request'
import type { DcqlQuery, EncryptionJwk, RequestObject, SourceFormat, VpFormats, ZkpReqCredentialQuery } from '../types/oid4vp'

/** The query over the mdoc (mso_mdoc). */
export const CREDENTIAL_QUERY_ID = 'nym_attestation'
/** The query over the same attestation as a BBS credential (bbs_cd). */
export const BBS_QUERY_ID = 'nym_attestation_bbs'
/** The pseudonym's return handle (every profile's pseudonym function returns under it). */
export const RETURN_PSEUDONYM = 'nym'

/**
 * A zkp_req query over `source`, as the profile writes it: the pseudonym always; age_check when
 * the site asks for an age (`ageParams`, written by the profile's operator: v0.4 birth-date bounds,
 * v0.5 a range in years).
 */
export function buildCredentialQuery(source: SourceFormat, profile: Profile, ageParams?: Record<string, string>): ZkpReqCredentialQuery {
  const _req = buildReq(profile, source, ageParams)
  const type = typeValue(profile, source)
  if (!type) throw new Error(`profile ${profile.id} has no ${source} encoding`)
  return source === 'mso_mdoc'
    ? { id: CREDENTIAL_QUERY_ID, format: 'zkp_req', meta: { source_format: 'mso_mdoc', doctype_value: type }, _req }
    : { id: BBS_QUERY_ID, format: 'zkp_req', meta: { source_format: 'bbs_cd', schema_id_value: type }, _req }
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
export function buildDcqlQuery(offer: VpFormats, profile: Profile, ageParams?: Record<string, string>): DcqlQuery {
  const credentials = sourcesOf(offer).map((f) => buildCredentialQuery(f, profile, ageParams))
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
