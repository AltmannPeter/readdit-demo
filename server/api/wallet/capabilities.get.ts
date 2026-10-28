/**
 * Mock phone: what the wallet can prove, from the prover backends that are loaded: the circuits
 * (mso_mdoc: Vega and Longfellow) and the schemes (bbs_cd: BBS), each with its system_id. Used for wallet_metadata and the wallet's
 * selection. 503 when neither prover is available.
 * `rulebook`: the version the site runs (the demo profile). The demo phones hold a v0.4 and a v0.5
 * mdoc per holder, and a request that asks for a pseudonym only reads the same under both, so the
 * demo wallet answers with the version the site runs (a real wallet holds one).
 */
export default defineEventHandler(async () => {
  const [vega, bbs] = await Promise.allSettled([prover.info(), bbsProver.info()])
  if (vega.status === 'rejected' && bbs.status === 'rejected') {
    throw createError({ statusCode: 503, statusMessage: 'The prover is not available.' })
  }
  return {
    circuits: vega.status === 'fulfilled' ? vega.value.circuits : [],
    schemes: bbs.status === 'fulfilled' ? bbs.value.schemes : [],
    rulebook: activeProfile().rulebook.version,
  }
})
