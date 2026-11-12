// Encrypted responses (OpenID4VP 1.0, "Encrypted Responses"): the verifier puts an ephemeral
// ECDH-ES public key in client_metadata.jwks, and the wallet encrypts its response to it: a JWE
// posted as `response` (direct_post.jwt), or a COSE_Encrypt as the body (direct_post.cwt,
// zkp_req.md §6.2, shared/utils/cwt.ts). In both, the key's JWK thumbprint (RFC 7638, SHA-256)
// goes into the handover, so the proof is bound to the key the response is encrypted to.
import { calculateJwkThumbprint, type JWK } from 'jose'
import type { EncryptionJwk, RequestObject } from '../types/oid4vp'

/** The only key agreement the demo uses: ECDH-ES on P-256. */
export const RESPONSE_ALG = 'ECDH-ES'
/** The default `enc` of OpenID4VP; the request leaves out encrypted_response_enc_values_supported. */
export const RESPONSE_ENC = 'A128GCM'

/** The encryption key of the request: the first key in client_metadata.jwks whose `use` is
 *  `enc` or absent and whose `alg` is ECDH-ES on P-256. */
export function encryptionKeyOf(request: Pick<RequestObject, 'client_metadata'>): EncryptionJwk | undefined {
  return request.client_metadata?.jwks?.keys?.find(
    (k) => (k.use === undefined || k.use === 'enc') && k.alg === RESPONSE_ALG && k.kty === 'EC' && k.crv === 'P-256' && typeof k.x === 'string' && typeof k.y === 'string',
  )
}

/** The `enc` the wallet uses: A128GCM, unless the request lists values without it. */
export function responseEncOf(request: Pick<RequestObject, 'client_metadata'>): string | undefined {
  const listed = request.client_metadata?.encrypted_response_enc_values_supported
  if (!listed) return RESPONSE_ENC
  return ['A128GCM', 'A256GCM'].find((e) => listed.includes(e))
}

/** RFC 7638 thumbprint (SHA-256, base64url) of a public key: the handover's jwkThumbprint. */
export function thumbprintOf(jwk: EncryptionJwk): Promise<string> {
  return calculateJwkThumbprint({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } as JWK, 'sha256')
}

/** Whether a Response Mode encrypts the response (and so puts jwk_thumbprint in the handover). */
export const encrypts = (mode: string | undefined) => mode === 'direct_post.jwt' || mode === 'direct_post.cwt'

/** The OpenID4VPHandover values of a request: jwk_thumbprint for an encrypted response (direct_post.jwt,
 *  direct_post.cwt: "the thumbprint of the key the Wallet encrypted to"), else null. */
export async function handoverOf(request: Pick<RequestObject, 'client_id' | 'nonce' | 'response_uri' | 'response_mode' | 'client_metadata'>) {
  const key = encrypts(request.response_mode) ? encryptionKeyOf(request) : undefined
  return { client_id: request.client_id, nonce: request.nonce, response_uri: request.response_uri, jwk_thumbprint: key ? await thumbprintOf(key) : null }
}
