import { findProfile, PROFILES } from '#shared/profiles'

/**
 * /tech's Demo profile: switches the version of the rulebook the site runs (shared/profiles), and
 * resets the demo, since accounts, pseudonyms and requests belong to one version. Body { profile }.
 * The choice stays across later demo resets. Refused: 400 bad_request (unknown profile). Demo only:
 * no authentication, as /mod.
 */
export default defineEventHandler(async (event) => {
  const { profile } = await readObject<{ profile: unknown }>(event)
  if (typeof profile !== 'string' || !findProfile(profile)) {
    throw refusal(400, 'bad_request', `profile must be one of ${PROFILES.map((p) => p.id).join(', ')}.`)
  }
  const was = activeProfile().id
  const p = setActiveProfile(profile)
  resetStore()
  console.log(`[profiles] ${was} -> ${p.id}; demo reset`)
  return { ok: true, profile: p.id }
})
