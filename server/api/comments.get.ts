/** Comments written during the demo for a post. */
export default defineEventHandler((event) => {
  const postId = String(getQuery(event).postId ?? '')
  const banned = (p: string) => !!store().accounts.get(p)?.banned
  return store()
    .comments.filter((c) => c.postId === postId && !banned(c.pseudonym))
    .map(({ id, handle, body, at }) => ({ id, handle, body, at }))
})
