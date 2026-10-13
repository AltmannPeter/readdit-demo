import type { CircuitZkFormats, WalletMetadata } from '#shared/types/oid4vp'
import { buildRequestObject } from '#shared/utils/dcql'
import { tailorFormats } from '#shared/utils/negotiation'

const strings = (v: unknown) => v === undefined || (Array.isArray(v) && v.every((x) => typeof x === 'string'))

/** wallet_metadata as the wallet posted it, or a 400 when it is not JSON or not the expected shape. */
function parseWalletMetadata(text: unknown): WalletMetadata | undefined {
  if (text === undefined || text === '') return undefined
  let m: unknown
  try {
    m = JSON.parse(String(text))
  } catch {
    throw refusal(400, 'invalid_wallet_metadata', 'wallet_metadata is not valid JSON.')
  }
  const formats = (m as { vp_formats_supported?: unknown } | null)?.vp_formats_supported
  const zk = (formats as { circuit_zk?: unknown } | undefined)?.circuit_zk as CircuitZkFormats | undefined
  if (
    !m ||
    typeof m !== 'object' ||
    (formats !== undefined && (typeof formats !== 'object' || formats === null)) ||
    (zk !== undefined && (typeof zk !== 'object' || zk === null || !strings(zk.circuit_id_values) || !strings(zk.circuit_proof_system_values)))
  ) {
    throw refusal(400, 'invalid_wallet_metadata', 'wallet_metadata does not have the expected shape.')
  }
  return m as WalletMetadata
}

/**
 * request_uri. GET, or POST with wallet_metadata and wallet_nonce (request_uri_method=post).
 * Returns the signed Request Object (application/oauth-authz-req+jwt). Single use: 410 with
 * `already_used`, `expired` or `cancelled` once the session has moved on.
 */
export default defineEventHandler(async (event) => {
  const method = event.method
  if (method !== 'GET' && method !== 'POST') throw refusal(405, 'method_not_allowed', 'Use GET or POST.')
  const s = getVpSession(getRouterParam(event, 'id')!)
  const ended = endedReason(s)
  if (ended) throw goneRefusal(ended)
  if (s.status !== 'waiting') throw refusal(410, 'already_used', 'This request has already been used.')

  let walletMetadata: WalletMetadata | undefined
  let walletNonce: string | undefined
  if (method === 'POST') {
    const form = await readObject<Record<string, unknown>>(event)
    walletMetadata = parseWalletMetadata(form.wallet_metadata)
    walletNonce = typeof form.wallet_nonce === 'string' && form.wallet_nonce ? form.wallet_nonce : undefined
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
