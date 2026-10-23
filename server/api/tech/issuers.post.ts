/**
 * /tech's trusted issuers (server/utils/issuers.ts). Body { trust_new }: the "Trust new issuers"
 * switch; or { forget: <fingerprint> }: removes an added issuer. Demo only: no authentication, as /mod.
 */
export default defineEventHandler(async (event) => {
  const { trust_new, forget } = await readObject<{ trust_new: unknown; forget: unknown }>(event)
  if (typeof trust_new === 'boolean') {
    store().trustNewIssuers = trust_new
    return { ok: true, trustNewIssuers: trust_new }
  }
  if (typeof forget === 'string') {
    if (!(await forgetIssuer(forget))) throw refusal(404, 'unknown_issuer', 'No added issuer with this fingerprint.')
    return { ok: true }
  }
  throw refusal(400, 'bad_request', 'Send trust_new (a boolean) or forget (a fingerprint).')
})
