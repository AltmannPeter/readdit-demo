import { findCommunity } from '#shared/data/communities'
import { buildDcqlQuery, authorizationUrl, clientIdFor, requestUriFor } from '#shared/utils/dcql'
import { decideGate, gateRange, todayISO } from '#shared/utils/age'
import { randomHex } from '#shared/utils/bytes'
import type { VpPurpose, VpSessionRecord } from '../../utils/store'

/**
 * Site: start a cross-device OpenID4VP session.
 * Body: { purpose: 'signin', intent: 'signup' | 'login', community? } | { purpose: 'age', community }
 * | { purpose: 'community', community }, and optionally `origin`, the page's address, for
 * request_uri and response_uri (see publicOrigin), and `phone`, the demo phone on screen.
 * community: the pseudonym of a community with its own verifier identity (Community.nymHost); the
 * request's client_id is x509_san_dns:<nymHost>, so the pseudonym is specific to that community.
 * signin with `community` (a logged-out visitor at an age-restricted community): one request for
 * the pseudonym and the community's age range, which logs in (or signs up) and records the age.
 * An age check alone needs a logged-in account, and only when the site cannot decide from the ages
 * already proven (shared/utils/age.ts, decideGate): a settled gate gets no wallet request.
 */
export default defineEventHandler(async (event) => {
  const body = await readObject<{ purpose: unknown; intent: unknown; community: unknown; origin: unknown; phone: unknown; link: unknown }>(event)
  const b = await browserSession(event)
  const cfg = useRuntimeConfig(event)
  let host = String(cfg.public.siteHost)

  let purpose: VpPurpose
  let gate
  if (body.purpose === 'signin') {
    const intent = body.intent ?? 'signup'
    if (intent !== 'signup' && intent !== 'login') throw refusal(400, 'bad_request', 'intent must be signup or login.')
    if (body.community !== undefined) {
      const c = typeof body.community === 'string' ? findCommunity(body.community) : undefined
      if (!c?.gate) throw refusal(400, 'bad_request', 'This community has no age requirement.')
      purpose = { kind: 'signin', intent, community: c.slug }
      gate = c.gate
    } else {
      purpose = { kind: 'signin', intent }
    }
  } else if (body.purpose === 'age' && typeof body.community === 'string') {
    const c = findCommunity(body.community)
    if (!c?.gate) throw refusal(400, 'bad_request', 'This community has no age requirement.')
    const account = mainAccount(b.data.pseudonym)
    if (!account || account.banned) throw refusal(401, 'login_required', 'Log in to verify your age.')
    const decision = decideGate(c.gate, account.birthDateRange, todayISO())
    if (decision === 'deny') throw refusal(403, 'age_refused', 'The age already verified for this account does not meet this requirement.')
    if (decision === 'allow') throw refusal(409, 'age_verified', 'The age already verified for this account meets this requirement.')
    purpose = { kind: 'age', community: c.slug }
    gate = c.gate
  } else if (body.purpose === 'community' && typeof body.community === 'string') {
    const c = findCommunity(body.community)
    if (!c?.nymHost) throw refusal(400, 'bad_request', 'This community has no pseudonym of its own.')
    const main = mainAccount(b.data.pseudonym)
    const loggedIn = !!main && !main.banned
    // Logged in, the person chooses: join and link, or log out first and join separately.
    if (loggedIn && body.link !== true) throw refusal(400, 'link_required', 'Logged in: join and link, or log out first.')
    purpose = { kind: 'community', community: c.slug, link: loggedIn }
    host = c.nymHost
  } else {
    throw refusal(400, 'bad_request', 'Unknown purpose.')
  }

  let offer
  try {
    offer = await verifierOffer()
  } catch (e) {
    console.error(`[vp] no offer: ${(e as Error).message}`)
    throw refusal(503, 'unavailable', 'The verifier is not available.')
  }

  const origin = publicOrigin(event, body.origin)
  const id = randomHex(16)
  const ttl = sessionTtlMs()
  const age = gate ? gateRange(gate, todayISO()) : undefined
  const dcql = buildDcqlQuery(offer, age)
  const s: VpSessionRecord = {
    id,
    purpose,
    gate,
    ownerSid: b.data.sid!,
    host,
    ...(typeof body.phone === 'string' && body.phone.length <= 40 && { phone: body.phone }),
    createdAt: Date.now(),
    expiresAt: Date.now() + ttl,
    origin,
    nonce: randomHex(16),
    state: randomHex(16),
    ...(age && { age }),
    dcql,
    offer,
    status: 'waiting',
    trace: [],
  }
  store().sessions.set(id, s)
  store().byState.set(s.state, id)
  addTrace(s, 'created', 'Session created', {
    purpose,
    client_id: clientIdFor(host),
    queries: dcql.credentials.map((q) => ({ id: q.id, format: q.format, req: q.req })),
    offer,
    ...(s.phone && { phone: s.phone }),
  })

  return { id, authorizationUrl: authorizationUrl(host, requestUriFor(origin, id)), expiresIn: Math.round(ttl / 1000) }
})

/**
 * The site's address as the browser sees it, for request_uri and response_uri. Behind a proxy that
 * rewrites the request (GitHub Codespaces forwards to localhost:3000 and does not keep the public
 * address), the server cannot tell it from the request, so the page sends its own
 * (`location.origin`). Then the browser's Origin header; without either (a script), the request's
 * forwarded host and protocol. The address only decides where this session's own wallet requests go.
 */
function publicOrigin(event: Parameters<typeof getRequestURL>[0], fromPage: unknown): string {
  for (const candidate of [fromPage, getRequestHeader(event, 'origin')]) {
    if (typeof candidate !== 'string') continue
    try {
      const u = new URL(candidate)
      if (u.protocol === 'https:' || u.protocol === 'http:') return u.origin
    } catch {
      /* not a URL: try the next */
    }
  }
  return getRequestURL(event, { xForwardedHost: true, xForwardedProto: true }).origin
}
