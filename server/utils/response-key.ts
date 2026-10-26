import { exportJWK, generateKeyPair } from 'jose'
import type { EncryptionJwk } from '#shared/types/oid4vp'
import { randomHex } from '#shared/utils/bytes'

/** A session's response encryption key (direct_post.jwt): ephemeral ECDH-ES on P-256, made when
 *  the session starts and dropped with it. The private key never leaves the server. */
export interface ResponseKey {
  jwk: EncryptionJwk
  privateKey: CryptoKey
  /** RFC 7638 thumbprint, base64url: the handover's jwkThumbprint. */
  thumbprint: string
}

export async function newResponseKey(): Promise<ResponseKey> {
  const { publicKey, privateKey } = await generateKeyPair(RESPONSE_ALG, { crv: 'P-256' })
  const pub = await exportJWK(publicKey)
  const jwk: EncryptionJwk = { kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y, kid: randomHex(8), use: 'enc', alg: RESPONSE_ALG }
  return { jwk, privateKey: privateKey as CryptoKey, thumbprint: await thumbprintOf(jwk) }
}
