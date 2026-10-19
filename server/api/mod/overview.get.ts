import { findPost } from '#shared/data/posts'

/** Moderator view: accounts and recent comments. Demo only: no authentication. */
export default defineEventHandler(() => {
  const { accounts, comments } = store()
  return {
    accounts: [...accounts.values()].map((a) => ({
      ...publicAccount(a),
      community: a.community ?? null,
      format: a.format ?? null,
      linkedTo: a.linkedTo ? (accounts.get(a.linkedTo)?.handle ?? null) : null,
      banned: a.banned ?? null,
      comments: comments.filter((c) => c.pseudonym === a.pseudonym).length,
    })),
    comments: [...comments]
      .reverse()
      .slice(0, 50)
      .map((c) => ({
        id: c.id,
        handle: c.handle,
        pseudonym: c.pseudonym,
        community: c.community,
        postTitle: findPost(c.postId)?.title ?? '',
        body: c.body,
        at: c.at,
        banned: !!accounts.get(c.pseudonym)?.banned,
      })),
  }
})
