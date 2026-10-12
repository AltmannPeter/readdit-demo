import type { WalletMetadata } from '#shared/types/oid4vp'
import { buildRequestObject } from '#shared/utils/dcql'
import { tailorFormats } from '#shared/utils/negotiation'

/**
 * request_uri. GET, or POST with wallet_metadata and wallet_nonce (request_uri_method=post).
 * Returns the signed Request Object (application/oauth-authz-req+jwt). Single use.
 */
export default defineEventHandler(async (event) => {
  const method = event.method
  if (method !== 'GET' && method !== 'POST') throw createError({ statusCode: 405 })
  const s = getVpSession(getRouterParam(event, 'id')!)
  if (s.status !== 'waiting') throw createError({ statusCode: 410, statusMessage: 'request already used' })

  let walletMetadata: WalletMetadata | undefined
  let walletNonce: string | undefined
  if (method === 'POST') {
    const form = await readBody<Record<string, string>>(event)
    if (form?.wallet_metadata) {
      try {
        walletMetadata = JSON.parse(form.wallet_metadata)
      } catch {
        throw createError({ statusCode: 400, statusMessage: 'invalid wallet_metadata' })
      }
    }
    walletNonce = form?.wallet_nonce || undefined
  }

  const { formats, tailored } = tailorFormats(s.offer, walletMetadata?.vp_formats_supported?.circuit_zk)
  const cfg = useRuntimeConfig(event)
  const request = buildRequestObject({
    host: String(cfg.public.siteHost),
    origin: s.origin,
    siteName: String(cfg.public.siteName),
    sessionId: s.id,
    nonce: s.nonce,
    state: s.state,
    query: s.query,
    formats,
    walletNonce,
  })
  const jws = await signRequestObject(request)

  s.request = request
  s.walletMetadata = walletMetadata
  s.tailored = tailored
  s.requestJwsBytes = jws.length
  s.status = 'scanned'
  addTrace(s, 'request', `Request Object fetched (${method})`, {
    wallet_metadata: walletMetadata ?? null,
    offered: s.offer,
    sent: formats,
    tailored,
    bytes: jws.length,
  })

  setHeader(event, 'content-type', 'application/oauth-authz-req+jwt')
  setHeader(event, 'cache-control', 'no-store')
  return jws
})
