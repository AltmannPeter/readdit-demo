import { findPost } from '#shared/data/posts'
import { findCommunity } from '#shared/data/communities'
import { decideGate, todayISO } from '#shared/utils/age'

export default defineEventHandler(async (event) => {
  const { postId, body } = await readObject<{ postId: unknown; body: unknown }>(event)
  const b = await browserSession(event)
  const post = typeof postId === 'string' ? findPost(postId) : undefined
  const text = typeof body === 'string' ? body.trim() : ''
  if (!post) throw refusal(400, 'bad_request', 'Unknown post.')
  const community = findCommunity(post.community)
  // A community with its own pseudonym: the comment is the community account's, never the Readdit account's.
  const account = community?.nymHost ? memberAccount(community.slug, b.data) : mainAccount(b.data.pseudonym)
  if (!account || account.banned) {
    throw community?.nymHost ? refusal(403, 'registration_required', 'Join this community with your wallet first.') : refusal(401, 'login_required', 'Log in to comment.')
  }
  if (!text || text.length > 2000) throw refusal(400, 'bad_request', 'A comment has 1 to 2,000 characters.')
  const gate = community?.gate ?? null
  if (gate && decideGate(gate, account.birthDateRange, todayISO()) !== 'allow') throw refusal(403, 'age_required', 'This community needs an age check first.')
  const c = {
    id: crypto.randomUUID(),
    postId: post.id,
    community: post.community,
    pseudonym: account.pseudonym,
    handle: account.handle,
    body: text,
    at: Date.now(),
  }
  store().comments.push(c)
  return { id: c.id, handle: c.handle, body: c.body, at: c.at }
})
