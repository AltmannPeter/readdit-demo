import { findPost } from '#shared/data/posts'
import { findCommunity } from '#shared/data/communities'
import { decideGate, todayISO } from '#shared/utils/age'

export default defineEventHandler(async (event) => {
  const { postId, body } = await readBody<{ postId?: string; body?: string }>(event)
  const b = await browserSession(event)
  const account = b.data.pseudonym ? store().accounts.get(b.data.pseudonym) : undefined
  if (!account || account.banned) throw createError({ statusCode: 401, statusMessage: 'log in first' })
  const post = findPost(String(postId))
  const text = String(body ?? '').trim()
  if (!post || !text || text.length > 2000) throw createError({ statusCode: 400 })
  const gate = findCommunity(post.community)?.gate ?? null
  if (gate && decideGate(gate, account.birthDateRange, todayISO()) !== 'allow') throw createError({ statusCode: 403 })
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
