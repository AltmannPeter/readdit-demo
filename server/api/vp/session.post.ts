import { findCommunity } from '#shared/data/communities'
import { buildCredentialQuery, authorizationUrl, requestUriFor } from '#shared/utils/dcql'
import { gateRange, todayISO } from '#shared/utils/age'
import { randomHex } from '#shared/utils/bytes'
import type { VpPurpose, VpSessionRecord } from '../../utils/store'

/** Site: start a cross-device OpenID4VP session. Body: { purpose: 'signin' } | { purpose: 'age', community }. */
export default defineEventHandler(async (event) => {
  const body = await readBody<{ purpose?: string; community?: string }>(event)
  const b = await browserSession(event)

  let purpose: VpPurpose
  let gate
  if (body?.purpose === 'signin') {
    purpose = { kind: 'signin' }
  } else if (body?.purpose === 'age' && body.community) {
    const c = findCommunity(body.community)
    if (!c?.gate) throw createError({ statusCode: 400, statusMessage: 'This community has no age requirement.' })
    const account = b.data.pseudonym ? store().accounts.get(b.data.pseudonym) : undefined
    if (!account || account.banned) throw createError({ statusCode: 401, statusMessage: 'Log in to verify your age.' })
    purpose = { kind: 'age', community: c.slug }
    gate = c.gate
  } else {
    throw createError({ statusCode: 400, statusMessage: 'Unknown purpose.' })
  }

  let offer
  try {
    offer = await verifierOffer()
  } catch (e) {
    console.error(`[vp] no offer: ${(e as Error).message}`)
    throw createError({ statusCode: 503, statusMessage: 'The verifier is not available.' })
  }

  const cfg = useRuntimeConfig(event)
  const origin = getRequestURL(event).origin
  const id = randomHex(16)
  const query = buildCredentialQuery(gate ? gateRange(gate, todayISO()) : undefined)
  const s: VpSessionRecord = {
    id,
    purpose,
    gate,
    ownerSid: b.data.sid!,
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_TTL_MS,
    origin,
    nonce: randomHex(16),
    state: randomHex(16),
    query,
    offer,
    status: 'waiting',
    trace: [],
  }
  store().sessions.set(id, s)
  store().byState.set(s.state, id)
  addTrace(s, 'created', 'Session created', { purpose, req: query.req, offer })

  return { id, authorizationUrl: authorizationUrl(String(cfg.public.siteHost), requestUriFor(origin, id)) }
})
