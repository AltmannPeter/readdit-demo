import type { BirthDateRange } from '../types'
import {
  NYM_BBS_SCHEMA,
  NYM_DOCTYPE,
  type CircuitZkCredentialQuery,
  type DcqlQuery,
  type MmsReqItem,
  type MmsZkCredentialQuery,
  type ReqItem,
  type RequestObject,
  type VpFormats,
} from '../types/oid4vp'

export const CREDENTIAL_QUERY_ID = 'nym_attestation'
/** The mms_zk query: the same attestation as a BBS credential. */
export const BBS_QUERY_ID = 'nym_attestation_bbs'
export const RETURN_PSEUDONYM = 'nym'
export const RETURN_AGE = 'age'

/** Pseudonym always; age_check when a birth-date range is required. */
export function buildCredentialQuery(age?: BirthDateRange): CircuitZkCredentialQuery {
  const req: ReqItem[] = [
    {
      id: 'pseudonym-v1-sha256',
      return: RETURN_PSEUDONYM,
      params: { config: 'known-offender-matching-ssc', verifier_id_type: 'x509_san_dns' },
    },
  ]
  if (age) req.push({ id: 'age_check', return: RETURN_AGE, params: { ...age } })
  return {
    id: CREDENTIAL_QUERY_ID,
    format: 'circuit_zk',
    meta: { doctype_value: NYM_DOCTYPE },
    req,
  }
}

/** mms_zk: the BBS pseudonym always; age_check when a birth-date range is required. */
export function buildBbsCredentialQuery(age?: BirthDateRange): MmsZkCredentialQuery {
  const req: MmsReqItem[] = [
    { id: 'pseudonym-bbs-v1', return: RETURN_PSEUDONYM, params: { config: 'known-offender-matching-ssc', verifier_id_type: 'x509_san_dns' } },
  ]
  if (age) req.push({ id: 'age_check', return: RETURN_AGE, params: { ...age } })
  return { id: BBS_QUERY_ID, format: 'mms_zk', meta: { schema_id_value: NYM_BBS_SCHEMA }, req }
}

/**
 * The DCQL query for the formats the site accepts (`offer`), in the offer's order (circuit_zk,
 * then mms_zk): one credential query per format and, with more than one, a credential set whose
 * options are the alternatives, so the wallet answers exactly one of them.
 */
export function buildDcqlQuery(offer: VpFormats, age?: BirthDateRange): DcqlQuery {
  const credentials = [
    ...(offer.circuit_zk ? [buildCredentialQuery(age)] : []),
    ...(offer.mms_zk ? [buildBbsCredentialQuery(age)] : []),
  ]
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
}): RequestObject {
  return {
    aud: 'https://self-issued.me/v2',
    iat: Math.floor(Date.now() / 1000),
    ...(o.walletNonce && { wallet_nonce: o.walletNonce }),
    response_type: 'vp_token',
    response_mode: 'direct_post',
    response_uri: responseUriFor(o.origin, o.sessionId),
    client_id: clientIdFor(o.host),
    nonce: o.nonce,
    state: o.state,
    dcql_query: o.dcql,
    client_metadata: {
      client_name: o.siteName,
      vp_formats_supported: o.formats,
    },
  }
}
