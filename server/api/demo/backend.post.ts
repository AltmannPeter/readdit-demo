/** Switch between the Vega addon and the built-in offline simulation. */
export default defineEventHandler(async (event) => {
  const body = await readBody<{ mode?: string; phoneFactor?: number }>(event)
  const state = backendMode()
  if (body?.mode === 'native' || body?.mode === 'offline') state.mode = body.mode
  if (body?.phoneFactor != null) state.phoneFactor = clampFactor(Number(body.phoneFactor))
  return { ...state }
})
