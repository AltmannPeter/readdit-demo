import { findCircuit } from '#shared/registry/circuits'

/** Technical view: services and the latest sessions with their traces. */
export default defineEventHandler(async () => {
  const sessions = [...store().sessions.values()].sort((a, b) => b.createdAt - a.createdAt).slice(0, 8)
  const signer = await requestSigner()
  return {
    services: await servicesStatus(),
    signer: { subject: signer.subject, selfSigned: signer.selfSigned },
    sessions: sessions.map((s) => {
      const circuitId = s.outcome?.ok ? s.outcome.circuitId : undefined
      return {
        id: s.id,
        purpose: s.purpose,
        phone: s.phone ?? null,
        status: s.status,
        createdAt: s.createdAt,
        query: s.query,
        offer: s.offer,
        walletMetadata: s.walletMetadata ?? null,
        tailored: s.tailored ?? false,
        request: s.request ?? null,
        requestJwsBytes: s.requestJwsBytes ?? null,
        circuit: circuitId ? findCircuit(circuitId) ?? { circuit_id: circuitId } : null,
        outcome: s.outcome ?? null,
        completion: s.completion ?? null,
        trace: s.trace,
      }
    }),
  }
})
