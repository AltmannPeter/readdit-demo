import { findCommunity } from '#shared/data/communities'

/**
 * Site: apply a verified session to the browser that started it.
 * The phone never sets the browser's login; only the owning browser can complete.
 *
 * Sign-in: `signup` creates the account, and answers `account_exists` (logging nothing in) when the
 * pseudonym already has one; `login` logs in only, and answers `no_account` (creating nothing) when
 * the pseudonym has no account. A banned account is refused either way. A sign-in for an
 * age-restricted community creates the account or logs in to the existing one, and also records the proven age range
 * for the account it logs in to: the pseudonym and the age result come from one presentation.
 * Age check: the proven pseudonym must be the logged-in account's.
 */
export default defineEventHandler(async (event) => {
  const { s, b } = await getOwnedVpSession(event, getRouterParam(event, 'id')!)
  if (s.completion) return s.completion
  if (s.status === 'failed' && s.outcome && !s.outcome.ok) return (s.completion = { ok: false, kind: s.outcome.reason })
  if (s.status !== 'verified' || !s.outcome?.ok) throw refusal(409, 'not_verified', 'The presentation has not been verified yet.')

  const { pseudonym } = s.outcome
  const accounts = store().accounts
  if (s.purpose.kind === 'signin') {
    const existing = accounts.get(pseudonym)
    if (existing?.banned) {
      s.completion = { ok: false, kind: 'banned', handle: existing.handle }
    } else if (!existing && s.purpose.intent === 'login') {
      s.completion = { ok: false, kind: 'no_account' }
    } else if (existing && s.purpose.intent === 'signup' && !s.purpose.community) {
      s.completion = { ok: false, kind: 'account_exists' }
    } else {
      const { account, created } = getOrCreateAccount(pseudonym)
      const gate = s.purpose.community ? findCommunity(s.purpose.community)?.gate : undefined
      if (gate && s.outcome.age) recordAgeProof(account, gate)
      await b.update({ pseudonym })
      s.completion = { ok: true, kind: created ? 'created' : 'logged_in', handle: account.handle, ...(gate && s.outcome.age && { age: true as const }) }
    }
  } else {
    const current = b.data.pseudonym ? accounts.get(b.data.pseudonym) : undefined
    const proven = accounts.get(pseudonym)
    const gate = findCommunity(s.purpose.community)?.gate
    if (current && current.pseudonym !== pseudonym) {
      s.completion = { ok: false, kind: 'mismatch' }
    } else if (proven?.banned) {
      // A ban ends the login, so the browser may already be logged out (GET /api/me).
      s.completion = { ok: false, kind: 'banned', handle: proven.handle }
    } else if (!current) {
      s.completion = { ok: false, kind: 'logged_out' }
    } else if (!gate || !s.outcome.age) {
      s.completion = { ok: false, kind: 'invalid' }
    } else {
      recordAgeProof(current, gate)
      s.completion = { ok: true, kind: 'age', handle: current.handle }
    }
  }
  s.status = 'completed'
  addTrace(s, 'completed', s.completion.ok ? 'Applied to account' : 'Not applied', { ...s.completion })
  return s.completion
})
