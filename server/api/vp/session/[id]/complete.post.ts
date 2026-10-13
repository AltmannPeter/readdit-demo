import { findCommunity } from '#shared/data/communities'

/**
 * Site: apply a verified session to the browser that started it.
 * The phone never sets the browser's login; only the owning browser can complete.
 */
export default defineEventHandler(async (event) => {
  const { s, b } = await getOwnedVpSession(event, getRouterParam(event, 'id')!)
  if (s.completion) return s.completion
  if (s.status === 'failed' && s.outcome && !s.outcome.ok) return (s.completion = { ok: false, kind: s.outcome.reason })
  if (s.status !== 'verified' || !s.outcome?.ok) throw createError({ statusCode: 409, statusMessage: 'The presentation has not been verified yet.' })

  const { pseudonym } = s.outcome
  if (s.purpose.kind === 'signin') {
    const { account, created } = getOrCreateAccount(pseudonym)
    if (account.banned) {
      s.completion = { ok: false, kind: 'banned', handle: account.handle }
    } else {
      await b.update({ pseudonym })
      s.completion = { ok: true, kind: created ? 'created' : 'logged_in', handle: account.handle }
    }
  } else {
    const account = b.data.pseudonym ? store().accounts.get(b.data.pseudonym) : undefined
    const gate = findCommunity(s.purpose.community)?.gate
    if (!account || account.pseudonym !== pseudonym) {
      s.completion = { ok: false, kind: 'mismatch' }
    } else if (account.banned) {
      s.completion = { ok: false, kind: 'banned', handle: account.handle }
    } else if (!gate || !s.outcome.age) {
      s.completion = { ok: false, kind: 'invalid' }
    } else {
      recordAgeProof(account, gate)
      s.completion = { ok: true, kind: 'age', handle: account.handle }
    }
  }
  s.status = 'completed'
  addTrace(s, 'completed', s.completion.ok ? 'Applied to account' : 'Not applied', { ...s.completion })
  return s.completion
})
