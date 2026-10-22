import { DEV_GATES } from '../../../../utils/store'
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
 * Developer view: creates the account or logs in, and records the proven age range, if any.
 * Age check: the proven pseudonym must be the logged-in account's.
 * Community (a community with its own pseudonym): creates the community account or logs in to it.
 * With a Community account logged in, it also links the two, at most one community account per
 * Community account and one Community account per community account: `other_pseudonym` when the
 * Community account is linked to another pseudonym of the community (another person's wallet),
 * `linked_elsewhere` when the community account is linked to another Community account.
 */
export default defineEventHandler(async (event) => {
  const { s, b } = await getOwnedVpSession(event, getRouterParam(event, 'id')!)
  if (s.completion) return s.completion
  if (s.status === 'failed' && s.outcome && !s.outcome.ok) return (s.completion = { ok: false, kind: s.outcome.reason })
  if (s.status !== 'verified' || !s.outcome?.ok) throw refusal(409, 'not_verified', 'The presentation has not been verified yet.')

  const { pseudonym } = s.outcome
  if (s.purpose.kind === 'community') {
    const slug = s.purpose.community
    const existing = communityAccount(slug, pseudonym)
    // Linking only when the person chose "Join and link" (purpose.link) and is still logged in.
    const loggedIn = mainAccount(b.data.pseudonym)
    const main = s.purpose.link && loggedIn && !loggedIn.banned ? loggedIn : undefined
    const linked = main ? linkedCommunityAccount(slug, main.pseudonym) : undefined
    if (existing?.banned) {
      s.completion = { ok: false, kind: 'banned', handle: existing.handle, community: slug }
    } else if (linked && linked.pseudonym !== pseudonym) {
      s.completion = { ok: false, kind: 'other_pseudonym', handle: linked.handle, community: slug }
    } else if (main && existing?.linkedTo && existing.linkedTo !== main.pseudonym) {
      s.completion = { ok: false, kind: 'linked_elsewhere', handle: existing.handle, community: slug }
    } else {
      const { account, created } = getOrCreateAccount(pseudonym, slug, s.outcome.format)
      const link = !!main && !account.linkedTo
      if (link) account.linkedTo = main!.pseudonym
      await b.update({ communities: { ...b.data.communities, [slug]: pseudonym } })
      s.completion = { ok: true, kind: created ? 'created' : 'logged_in', handle: account.handle, community: slug, ...(link && { linked: true as const }) }
    }
    s.status = 'completed'
    addTrace(s, 'completed', s.completion.ok ? 'Applied to the community account' : 'Not applied', { ...s.completion })
    return s.completion
  }
  if (s.purpose.kind === 'dev') {
    // The developer view: create the account or log in, and record the age range if one was proven.
    const existing = mainAccount(pseudonym)
    if (existing?.banned) {
      s.completion = { ok: false, kind: 'banned', handle: existing.handle }
    } else {
      const { account, created } = getOrCreateAccount(pseudonym, undefined, s.outcome.format)
      const gate = DEV_GATES[s.purpose.age]
      if (gate && s.outcome.age) recordAgeProof(account, gate)
      await b.update({ pseudonym })
      s.completion = { ok: true, kind: created ? 'created' : 'logged_in', handle: account.handle, ...(gate && s.outcome.age && { age: true as const }) }
    }
  } else if (s.purpose.kind === 'signin') {
    const existing = mainAccount(pseudonym)
    if (existing?.banned) {
      s.completion = { ok: false, kind: 'banned', handle: existing.handle }
    } else if (!existing && s.purpose.intent === 'login') {
      s.completion = { ok: false, kind: 'no_account' }
    } else if (existing && s.purpose.intent === 'signup' && !s.purpose.community) {
      s.completion = { ok: false, kind: 'account_exists' }
    } else {
      const { account, created } = getOrCreateAccount(pseudonym, undefined, s.outcome.format)
      const gate = s.purpose.community ? findCommunity(s.purpose.community)?.gate : undefined
      if (gate && s.outcome.age) recordAgeProof(account, gate)
      await b.update({ pseudonym })
      s.completion = { ok: true, kind: created ? 'created' : 'logged_in', handle: account.handle, ...(gate && s.outcome.age && { age: true as const }) }
    }
  } else {
    const current = mainAccount(b.data.pseudonym)
    const proven = mainAccount(pseudonym)
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
