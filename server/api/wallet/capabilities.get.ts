/**
 * Mock phone: what the wallet can prove, from the prover backends that are loaded: the circuits
 * (circuit_zk, Vega and Longfellow) and the schemes (mms_zk, BBS). Used for wallet_metadata and the wallet's
 * selection. 503 when neither prover is available.
 */
export default defineEventHandler(async () => {
  const [vega, bbs] = await Promise.allSettled([prover.info(), bbsProver.info()])
  if (vega.status === 'rejected' && bbs.status === 'rejected') {
    throw createError({ statusCode: 503, statusMessage: 'The prover is not available.' })
  }
  return {
    circuits: vega.status === 'fulfilled' ? vega.value.circuits : [],
    schemes: bbs.status === 'fulfilled' ? bbs.value.schemes : [],
  }
})
