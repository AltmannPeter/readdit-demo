import { findCircuit, findScheme } from '#shared/registry/circuits'

/** Technical view: services and the latest sessions with their traces. */
export default defineEventHandler(async () => {
  const sessions = [...store().sessions.values()].sort((a, b) => b.createdAt - a.createdAt).slice(0, 8)
  const signer = await requestSigner()
  return {
    services: await servicesStatus(),
    acceptedProofSystems: store().acceptedProofSystems,
    multithreading: store().multithreading,
    measurements: measurementSummary(),
    signer: { subject: signer.subject, selfSigned: signer.selfSigned },
    sessions: sessions.map((s) => {
      const done = s.outcome?.ok ? s.outcome : undefined
      return {
        id: s.id,
        purpose: s.purpose,
        phone: s.phone ?? null,
        status: s.status,
        createdAt: s.createdAt,
        dcql: s.dcql,
        answered: s.answered ?? null,
        offer: s.offer,
        walletMetadata: s.walletMetadata ?? null,
        tailored: s.tailored ?? false,
        request: s.request ?? null,
        requestJwsBytes: s.requestJwsBytes ?? null,
        circuit: done?.format === 'circuit_zk' ? (findCircuit(done.proofId) ?? { circuit_id: done.proofId }) : null,
        scheme: done?.format === 'mms_zk' ? (findScheme(done.proofId) ?? { scheme_id: done.proofId }) : null,
        outcome: s.outcome ?? null,
        completion: s.completion ?? null,
        trace: s.trace,
      }
    }),
  }
})
