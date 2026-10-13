/**
 * Site: the dialog was closed before the session ended. The session ends as failed with reason
 * `cancelled`, so a later answer from the phone gets 410 and nothing is applied. A session that
 * already ended is left as it is.
 */
export default defineEventHandler(async (event) => {
  const { s } = await getOwnedVpSession(event, getRouterParam(event, 'id')!)
  if (s.status === 'completed' || s.status === 'failed') return { status: s.status }
  s.status = 'failed'
  s.outcome = { ok: false, reason: 'cancelled' }
  addTrace(s, 'failed', 'Cancelled by the site', { reason: 'cancelled' })
  return { status: s.status }
})
