// Checks the demo profiles (profiles/*/profile.json) against their schema when the server starts.
// A profile that does not fit is a configuration error: the built server stops with the reason
// (exit code 1); the development server logs it and keeps running.
export default defineNitroPlugin(() => {
  try {
    validateProfiles()
    console.log(`[profiles] ${activeProfile().label} (${activeProfile().id})`)
  } catch (e) {
    console.error(`[profiles] ${(e as Error).message}`)
    if (!import.meta.dev) process.exit(1)
  }
})
