/** Site: poll session status, with the verifier's timings once a presentation was verified or refused. */
export default defineEventHandler(async (event) => {
  const { s } = await getOwnedVpSession(event, getRouterParam(event, 'id')!)
  return {
    status: s.status,
    failure: s.outcome && !s.outcome.ok ? s.outcome.reason : undefined,
    completion: s.completion,
    verification: s.verification,
    proof: s.outcome?.ok ? { format: s.outcome.format, id: s.outcome.proofId } : undefined,
  }
})
