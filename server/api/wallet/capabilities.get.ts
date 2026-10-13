/** Mock phone: circuits the wallet (prover service) can run. Used for wallet_metadata and circuit selection. */
export default defineEventHandler(async () => {
  try {
    const info = await prover.info()
    return { circuits: info.circuits }
  } catch {
    throw createError({ statusCode: 503, statusMessage: 'The prover is not available.' })
  }
})
