// What the rulebook states about each pseudonym configuration, from the demo profile the request
// was read under (profiles/<id>/profile.json, `pseudonym_configs`). The consent screen phrases these
// properties for the request at hand; it claims nothing else.

import { DEFAULT_PROFILE_ID, configSpec, findProfile, type Profile, type PseudonymConfigSpec } from '#shared/profiles'

export type ConfigProperties = PseudonymConfigSpec['properties'] & { seed: PseudonymConfigSpec['seed'] }

/** The properties of `config` in `profile` (the default profile when the request was not read). */
export function configProperties(profile: Profile | undefined, config: string): ConfigProperties {
  const p = profile ?? findProfile(DEFAULT_PROFILE_ID)!
  const spec = configSpec(p, config)
  if (!spec) throw new Error(`profile ${p.id} does not define ${config}`)
  return { ...spec.properties, seed: spec.seed }
}
