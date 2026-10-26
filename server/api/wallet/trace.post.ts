const STEPS = new Set(['authenticate', 'match', 'consent', 'decline', 'encrypt'])
const MAX_BYTES = 8192

/**
 * Mock phone: a step inside the wallet, for the session's trace (the developer view, /tech). The
 * session is found by the request's `state`, which only the wallet that fetched the request knows.
 * Recorded as step `wallet.<step>`. 204, also for a state the site does not know (a demo reset,
 * another verifier), which records nothing; 400 for an unknown step or too much data.
 */
export default defineEventHandler(async (event) => {
  const body = await readObject<{ state: unknown; step: unknown; label: unknown; data: unknown }>(event)
  if (typeof body.step !== 'string' || !STEPS.has(body.step) || typeof body.label !== 'string' || body.label.length > 80) {
    throw refusal(400, 'bad_request', 'Unknown wallet step.')
  }
  const data = body.data && typeof body.data === 'object' && !Array.isArray(body.data) ? (body.data as Record<string, unknown>) : undefined
  if (data && JSON.stringify(data).length > MAX_BYTES) throw refusal(400, 'bad_request', 'Too much data.')
  const id = typeof body.state === 'string' ? store().byState.get(body.state) : undefined
  const s = id ? store().sessions.get(id) : undefined
  if (s) addTrace(s, `wallet.${body.step}`, body.label, data)
  setResponseStatus(event, 204)
  return null
})
