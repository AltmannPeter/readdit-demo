import { CompactEncrypt, compactVerify, decodeProtectedHeader, importJWK } from 'jose'
import type { AuthorizationResponse, RequestObject, WalletMetadata } from '#shared/types/oid4vp'
import { CWT_CONTENT_TYPE, coseEncOf, encodeAuthorizationResponse, encryptCwt } from '#shared/utils/cwt'

/** How the wallet talks to the verifier: fetch request_uri, post to response_uri. */
export interface WalletTransport {
  fetchRequest(o: {
    requestUri: string
    method: 'get' | 'post'
    clientId: string
    walletMetadata?: WalletMetadata
  }): Promise<VerifiedRequest>
  /** Encrypts the response to the request's key first (encryptResponse), in the request's Response
   *  Mode, unless the caller passes the encrypted response. */
  postResponse(request: RequestObject, body: AuthorizationResponse, encrypted?: EncryptedResponse | null): Promise<void>
}

/** How the response was encrypted, for the technical view, and what is posted. */
export type EncryptedResponse =
  | { mode: 'direct_post.jwt'; jwe: string; header: { alg: string; enc: string; kid?: string }; bytes: number; encrypt_ms: number }
  | { mode: 'direct_post.cwt'; cwt: Uint8Array; header: { alg: string; enc: string; kid?: string }; bytes: number; encrypt_ms: number }

/**
 * Encrypts the response to the first usable key in client_metadata.jwks (ECDH on P-256, `enc`
 * A128GCM by default, the key's `kid` passed on), in the request's Response Mode:
 * - direct_post.cwt (zkp_req.md §6.2): the CBOR Authorization Response, each ZkpPresentation the
 *   CBOR map itself, in a COSE_Encrypt (ECDH-ES + HKDF-256), posted as the body;
 * - direct_post.jwt (OpenID4VP 1.0): the JSON parameters in a JWE (ECDH-ES), posted as `response`.
 * Null when the request asks for no encryption or gives no usable key.
 */
export async function encryptResponse(request: RequestObject, body: AuthorizationResponse): Promise<EncryptedResponse | null> {
  if (request.response_mode !== 'direct_post.jwt' && request.response_mode !== 'direct_post.cwt') return null
  const jwk = encryptionKeyOf(request)
  const enc = responseEncOf(request)
  if (!jwk || !enc) return null
  const t0 = performance.now()
  const ms = () => Math.round((performance.now() - t0) * 100) / 100
  if (request.response_mode === 'direct_post.cwt') {
    const { bytes, header } = await encryptCwt(encodeAuthorizationResponse(body), jwk, coseEncOf(enc))
    return { mode: 'direct_post.cwt', cwt: bytes, header, bytes: bytes.length, encrypt_ms: ms() }
  }
  const header = { alg: jwk.alg!, enc, ...(jwk.kid && { kid: jwk.kid }) }
  const key = await importJWK({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, jwk.alg)
  const jwe = await new CompactEncrypt(new TextEncoder().encode(JSON.stringify(body))).setProtectedHeader(header).encrypt(key)
  return { mode: 'direct_post.jwt', jwe, header, bytes: jwe.length, encrypt_ms: ms() }
}

/** What is posted to response_uri: the COSE_Encrypt as the body (direct_post.cwt), `response`
 *  (direct_post.jwt), or the parameters as form fields. Only an error response goes unencrypted
 *  (OpenID4VP allows it when the wallet cannot encrypt). */
export async function responseBody(request: RequestObject, body: AuthorizationResponse, encrypted?: EncryptedResponse | null): Promise<{ contentType: string; body: BodyInit }> {
  const e = encrypted === undefined ? await encryptResponse(request, body) : encrypted
  if (e?.mode === 'direct_post.cwt') return { contentType: CWT_CONTENT_TYPE, body: e.cwt as BufferSource }
  if (e) return { contentType: 'application/x-www-form-urlencoded', body: new URLSearchParams({ response: e.jwe }) }
  if (!('error' in body)) throw new Error('the request gives no key to encrypt the presentation to')
  return { contentType: 'application/x-www-form-urlencoded', body: new URLSearchParams({ state: body.state, error: body.error }) }
}

/** An HTTP refusal from request_uri or response_uri: its status and the code in its error body. */
export class TransportError extends Error {
  constructor(
    public endpoint: 'request_uri' | 'response_uri',
    public status: number,
    public code?: string,
  ) {
    super(`${endpoint} ${status}${code ? ` ${code}` : ''}`)
  }
}

/** The refusal code in an error body (`data.error`), if the body is the server's JSON error. */
async function codeOf(res: Response): Promise<string | undefined> {
  try {
    const body = (await res.json()) as { data?: { error?: unknown } }
    return typeof body?.data?.error === 'string' ? body.data.error : undefined
  } catch {
    return undefined
  }
}

/** A Request Object whose signature and certificate SAN checked out, with the signer's subject. */
export interface VerifiedRequest {
  request: RequestObject
  signer: { subject: string }
}

const ES256 = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const

/**
 * Verifies a signed Request Object for an x509_san_dns client: ES256 signature by the
 * x5c leaf, and a dNSName SAN equal to the client_id host. Trust-anchor validation of
 * the chain is not done in this demo wallet.
 */
async function verifyRequestJws(jws: string, clientId: string): Promise<VerifiedRequest> {
  // @peculiar/x509 needs the Reflect metadata polyfill loaded first.
  await import('reflect-metadata')
  const x509 = await import('@peculiar/x509')
  const header = decodeProtectedHeader(jws)
  if (header.alg !== 'ES256' || !header.x5c?.length) throw new Error('unsigned or unsupported request')
  const leaf = new x509.X509Certificate(header.x5c[0]!)
  const host = clientId.replace(/^x509_san_dns:/, '')
  const san = leaf.getExtension(x509.SubjectAlternativeNameExtension)
  if (!san?.names.toJSON().some((n) => n.type === "dns" && n.value === host)) throw new Error('certificate does not match client_id')
  const key = await leaf.publicKey.export(ES256, ['verify'])
  const { payload } = await compactVerify(jws, key)
  const request = JSON.parse(new TextDecoder().decode(payload)) as RequestObject
  if (request.client_id !== clientId) throw new Error('client_id mismatch')
  return { request, signer: { subject: leaf.subject } }
}

/** OpenID4VP over HTTP, as a phone would do it. */
export const httpTransport: WalletTransport = {
  async fetchRequest({ requestUri, method, clientId, walletMetadata }) {
    let res: Response
    let walletNonce: string | undefined
    if (method === 'post') {
      walletNonce = crypto.randomUUID()
      const form = new URLSearchParams({ wallet_nonce: walletNonce })
      if (walletMetadata) form.set('wallet_metadata', JSON.stringify(walletMetadata))
      res = await fetch(requestUri, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form })
    } else {
      res = await fetch(requestUri)
    }
    if (!res.ok) throw new TransportError('request_uri', res.status, await codeOf(res))
    const verified = await verifyRequestJws((await res.text()).trim(), clientId)
    if (walletNonce && verified.request.wallet_nonce !== walletNonce) throw new Error('wallet_nonce mismatch')
    return verified
  },
  async postResponse(request, body, encrypted) {
    const post = await responseBody(request, body, encrypted)
    const res = await fetch(request.response_uri, { method: 'POST', headers: { 'content-type': post.contentType }, body: post.body })
    if (!res.ok) throw new TransportError('response_uri', res.status, await codeOf(res))
  },
}
