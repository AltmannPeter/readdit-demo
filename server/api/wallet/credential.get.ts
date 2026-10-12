/** Mock phone: the holder's nym_auth credential, decoded by the prover service. */
export default defineEventHandler(async () => {
  try {
    return await prover.credential(String(useRuntimeConfig().demoHolder))
  } catch (e) {
    throw createError({ statusCode: e instanceof ServiceError ? e.status : 500, statusMessage: 'prover unavailable' })
  }
})
