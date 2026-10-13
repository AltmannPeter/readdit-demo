import { compactVerify, decodeProtectedHeader } from 'jose'
import type { AuthorizationResponse, RequestObject, WalletMetadata } from '#shared/types/oid4vp'

/** How the wallet talks to the verifier: fetch request_uri, post to response_uri. */
export interface WalletTransport {
  fetchRequest(o: {
    requestUri: string
    method: 'get' | 'post'
    clientId: string
    walletMetadata?: WalletMetadata
  }): Promise<VerifiedRequest>
  postResponse(responseUri: string, body: AuthorizationResponse): Promise<void>
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
    if (!res.ok) throw new Error(`request_uri ${res.status}`)
    const verified = await verifyRequestJws((await res.text()).trim(), clientId)
    if (walletNonce && verified.request.wallet_nonce !== walletNonce) throw new Error('wallet_nonce mismatch')
    return verified
  },
  async postResponse(responseUri, body) {
    const form = new URLSearchParams({ state: body.state })
    if ('error' in body) form.set('error', body.error)
    else form.set('vp_token', JSON.stringify(body.vp_token))
    const res = await fetch(responseUri, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form })
    if (!res.ok) throw new Error(`response_uri ${res.status}`)
  },
}
