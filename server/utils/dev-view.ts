import { Decoder, Tag } from 'cbor-x'
import { authorizationUrl, requestUriFor } from '#shared/utils/dcql'
import { fromBase64url } from '#shared/utils/mdoc'
import type { VpSessionRecord } from './store'

const cbor = new Decoder({ mapsAsObjects: true, useRecords: false })

/** Byte strings as h'…' with their length, the way the developer view shows CBOR. */
function readable(v: unknown): unknown {
  if (v instanceof Uint8Array) {
    const hex = Buffer.from(v).toString('hex')
    return `h'${hex.length > 48 ? `${hex.slice(0, 24)}…${hex.slice(-8)}` : hex}' (${v.length} bytes)`
  }
  if (v instanceof Tag) return { [`tag ${v.tag}`]: readable(v.value) }
  if (v instanceof Date) return v.toISOString()
  if (Array.isArray(v)) return v.map(readable)
  if (v && typeof v === 'object') return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, readable(x)]))
  return v
}

/** base64url(CBOR(ZkpPresentation)), decoded for display; null if it does not decode. */
export function decodePresentation(b64: string): unknown {
  try {
    return readable(cbor.decode(fromBase64url(b64)))
  } catch {
    return null
  }
}

/** A short form of a long string: its start, its end and its length. */
export const ellipsize = (s: string, keep = 24) => (s.length > keep * 2 + 1 ? `${s.slice(0, keep)}…${s.slice(-8)} (${s.length} chars)` : s)

/** Everything the developer view shows of one session. The response key's private half stays out. */
export async function devSessionView(s: VpSessionRecord) {
  const signer = await requestSigner()
  return {
    id: s.id,
    purpose: s.purpose,
    phone: s.phone ?? null,
    status: s.status,
    createdAt: s.createdAt,
    expiresAt: s.expiresAt,
    authorizationUrl: authorizationUrl(s.host, requestUriFor(s.origin, s.id)),
    dcql: s.dcql,
    offer: s.offer,
    responseKey: s.responseKey.jwk,
    walletMetadata: s.walletMetadata ?? null,
    tailored: s.tailored ?? false,
    request: s.request ?? null,
    requestJwsHeader: s.request ? { alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: signer.x5c.map((c) => ellipsize(c)) } : null,
    requestJwsBytes: s.requestJwsBytes ?? null,
    response: s.response
      ? {
          jwe: s.response.jwe,
          ...(s.response.presentation && {
            presentation: { base64url: ellipsize(s.response.presentation), chars: s.response.presentation.length, decoded: decodePresentation(s.response.presentation) },
          }),
        }
      : null,
    answered: s.answered ?? null,
    outcome: s.outcome ?? null,
    completion: s.completion ?? null,
    verification: s.verification ?? null,
    trace: s.trace,
  }
}
