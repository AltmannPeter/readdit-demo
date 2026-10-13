export default defineEventHandler(async (event) => {
  const { pseudonym } = await readObject<{ pseudonym: unknown }>(event)
  if (typeof pseudonym !== 'string') throw refusal(400, 'bad_request', 'pseudonym is required.')
  const a = store().accounts.get(pseudonym)
  if (!a) throw refusal(404, 'unknown_account', 'Unknown account.')
  delete a.banned
  return { ok: true }
})
