import { communities } from '#shared/data/communities'
import type { CommunityMembership } from '#shared/types'

/**
 * Current account of this browser. A ban ends the login and leaves a notice once.
 * `communities`: for each community with its own pseudonym, the community account this browser acts
 * as there (memberAccount): with a Readdit account logged in, the one linked to it; otherwise the
 * one it logged in to. A banned one is reported as banned, and its own login ends.
 */
export default defineEventHandler(async (event) => {
  const b = await browserSession(event)
  const { bannedNotices } = store()
  const account = mainAccount(b.data.pseudonym)
  if (account?.banned) {
    await b.update({ pseudonym: undefined })
    bannedNotices.set(b.data.sid!, account.handle)
  }
  if (b.data.pseudonym && !account) await b.update({ pseudonym: undefined })
  const main = account && !account.banned ? account : undefined

  const memberships: Record<string, CommunityMembership> = {}
  const sessions = { ...b.data.communities }
  for (const c of communities) {
    if (!c.nymHost) continue
    const own = communityAccount(c.slug, sessions[c.slug])
    if (sessions[c.slug] && (!own || own.banned)) delete sessions[c.slug]
    const a = memberAccount(c.slug, { pseudonym: main?.pseudonym, communities: b.data.communities })
    if (a) memberships[c.slug] = { handle: a.handle, linked: !!main && a.linkedTo === main.pseudonym, banned: !!a.banned, bannedWith: a.banned?.cascade && a.linkedTo ? (store().accounts.get(a.linkedTo)?.handle ?? null) : null }
  }
  if (Object.keys(sessions).length !== Object.keys(b.data.communities ?? {}).length) await b.update({ communities: sessions })

  const bannedHandle = main ? null : (bannedNotices.get(b.data.sid!) ?? null)
  return { account: main ? publicAccount(main) : null, bannedHandle, communities: memberships }
})
