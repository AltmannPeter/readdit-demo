/** Site: poll session status. */
export default defineEventHandler(async (event) => {
  const { s } = await getOwnedVpSession(event, getRouterParam(event, 'id')!)
  return {
    status: s.status,
    failure: s.outcome && !s.outcome.ok ? s.outcome.reason : undefined,
    completion: s.completion,
  }
})
