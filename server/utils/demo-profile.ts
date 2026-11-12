// The demo profile the site runs (shared/profiles; /tech's Demo profile). One at a time: the
// requests the site builds, how it reads the presentations, and which proof systems it can offer
// follow it. The choice survives a demo reset; switching it resets the demo (POST
// /api/tech/profile). At start it is runtime config demoProfile (NUXT_DEMO_PROFILE), else the
// default. Every profile is checked against profiles/schema/profile.schema.json when the server
// starts, and a profile that does not fit stops it.

import Ajv2020 from 'ajv/dist/2020.js'
import addFormats from 'ajv-formats'
import schema from '../../profiles/schema/profile.schema.json'
import { PROFILES, findProfile, profileOrDefault, type Profile } from '#shared/profiles'
import { AGE_OPERATORS } from '#shared/protocol/operators'

const g = globalThis as unknown as { __communityProfile?: string }

/** Checks every profile against the schema, and that the operators it names exist. Throws. */
export function validateProfiles(): void {
  const ajv = new Ajv2020({ allErrors: true, strict: false })
  ;(addFormats as unknown as (a: unknown) => void)(ajv)
  const check = ajv.compile(schema as object)
  const ids = new Set<string>()
  for (const p of PROFILES) {
    const id = p.id
    if (!check(p)) throw new Error(`profile ${id}: ${ajv.errorsText(check.errors)}`)
    if (ids.has(p.id)) throw new Error(`profile ${p.id} appears twice`)
    ids.add(p.id)
    if (!(p.functions.age_check.wire in AGE_OPERATORS)) throw new Error(`profile ${p.id}: no age operator ${p.functions.age_check.wire}`)
    if (!p.pseudonym_configs.some((c) => c.requested)) throw new Error(`profile ${p.id}: no pseudonym configuration is marked requested`)
  }
  const configured = String(useRuntimeConfig().demoProfile || '')
  if (configured && !findProfile(configured)) throw new Error(`runtime config demoProfile ${configured} is not a profile (${PROFILES.map((p) => p.id).join(', ')})`)
}

/** The profile the site runs now. */
export function activeProfile(): Profile {
  g.__communityProfile ??= profileOrDefault(String(useRuntimeConfig().demoProfile || '')).id
  return profileOrDefault(g.__communityProfile)
}

/** Switches the profile (the caller resets the demo). */
export function setActiveProfile(id: string): Profile {
  const p = findProfile(id)
  if (!p) throw new Error(`no profile ${id}`)
  g.__communityProfile = p.id
  return p
}

/** The profile a session was created under (a switch resets the demo, so this is the active one
 *  for every live session; old records fall back to the default). */
export function sessionProfile(s: { profile?: string }): Profile {
  return profileOrDefault(s.profile)
}
