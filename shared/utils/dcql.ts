import type { BirthDateRange } from '../types'
import { NYM_DOCTYPE, type CircuitZkCredentialQuery, type CircuitZkFormats, type ReqItem, type RequestObject } from '../types/oid4vp'

export const CREDENTIAL_QUERY_ID = 'nym_attestation'
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
  query: CircuitZkCredentialQuery
  formats: CircuitZkFormats
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
    dcql_query: { credentials: [o.query] },
    client_metadata: {
      client_name: o.siteName,
      vp_formats_supported: { circuit_zk: o.formats },
    },
  }
}
