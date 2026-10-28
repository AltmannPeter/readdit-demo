// Demo profiles (profiles/<id>/profile.json, schema profiles/schema/profile.schema.json): one version
// of the nym_auth rulebook as Community runs it. A profile names the credential and its encodings,
// the functions a request can ask for (how each is written in a request, read, and what is proven),
// the pseudonym configurations with their properties, and which proof systems the version can use.
// The site runs one profile at a time (/tech's Demo profile; server/utils/profiles.ts); the demo
// wallet supports all of them and reads each request under the profile its items fit
// (shared/protocol/request.ts).

import v04 from '../../profiles/nym-auth-v0.4/profile.json'
import v05 from '../../profiles/nym-auth-v0.5/profile.json'
import type { PseudonymConfig, SourceFormat } from '../types/oid4vp'

export interface ProfileAttribute {
  id: string
  role: 'value' | 'commitment' | 'hidden'
  opens?: string[]
  presence?: 'required' | 'optional'
  description: string
}

export interface FunctionSpec {
  kind: 'value' | 'assertion'
  return?: string
  /** The operator that writes and reads the params (shared/protocol/operators.ts). */
  wire: string
  bounds_date?: 'request' | 'proof_time'
  params?: Record<string, unknown>
  meaning: string
  translation: string[]
  proof: string
  source_attributes?: Partial<Record<SourceFormat, string[]>>
}

export interface PseudonymConfigSpec {
  id: PseudonymConfig
  seed: 'secret_seed' | 'private_seed'
  seed_attribute?: Partial<Record<SourceFormat, string>>
  prf: Partial<Record<SourceFormat, 'sha-256' | 'hashdh-bls12381g1'>>
  requested?: boolean
  properties: { distinctPerVerifier: boolean; sameAcrossVerifiers: boolean; issuerCanLink: boolean; knownOffenderMatching: boolean }
}

export interface ProfileSystem {
  proof_system: string
  /** Absent for a pending system whose circuits do not exist yet. */
  system_id?: string
  status: 'available' | 'pending'
  note?: string
  proof_time?: 'always' | 'with-age_check' | 'never'
}

export interface Profile {
  id: string
  label: string
  rulebook: { title: string; version: string; date: string; document: string }
  source: { repository: string; commit: string | null; branch?: string }
  credential: {
    id: string
    label: string
    encodings: {
      mso_mdoc?: { doctype: string; attributes: ProfileAttribute[] }
      bbs_cd?: { schema_id: string; schema_digest: string; attributes: ProfileAttribute[] }
    }
    metadata?: Array<{ label: string; file: string }>
  }
  functions: { pseudonym: FunctionSpec; age_check: FunctionSpec }
  pseudonym_configs: PseudonymConfigSpec[]
  systems: ProfileSystem[]
}

/** Every profile, oldest first. */
export const PROFILES: Profile[] = [v04 as unknown as Profile, v05 as unknown as Profile]

/** The profile the site runs at start (runtime config demoProfile overrides it). */
export const DEFAULT_PROFILE_ID = 'nym-auth-v0.4'

export const findProfile = (id: string): Profile | undefined => PROFILES.find((p) => p.id === id)

export function profileOrDefault(id: string | undefined | null): Profile {
  return (id && findProfile(id)) || findProfile(DEFAULT_PROFILE_ID)!
}

/** The pseudonym configuration Community asks for in this profile. */
export function requestedConfig(p: Profile): PseudonymConfigSpec {
  return p.pseudonym_configs.find((c) => c.requested) ?? p.pseudonym_configs[0]!
}

export const configSpec = (p: Profile, id: string): PseudonymConfigSpec | undefined => p.pseudonym_configs.find((c) => c.id === id)

/** Whether the profile can use a proof system now (pending: waiting for circuits, say). */
export function systemStatus(p: Profile, proofSystem: string): ProfileSystem | undefined {
  return p.systems.find((s) => s.proof_system === proofSystem)
}
export const systemAvailable = (p: Profile, proofSystem: string) => systemStatus(p, proofSystem)?.status === 'available'

/** The type value of an encoding in this profile: the doctype or the schema id. */
export function typeValue(p: Profile, source: SourceFormat): string | undefined {
  return source === 'mso_mdoc' ? p.credential.encodings.mso_mdoc?.doctype : p.credential.encodings.bbs_cd?.schema_id
}

/** The commit the profile is based on, on GitHub; null until it is committed. */
export function commitUrl(p: Profile): string | null {
  return p.source.commit ? `${p.source.repository}/commit/${p.source.commit}` : null
}

/** The rulebook document on GitHub, at the profile's commit (or its branch until it has one). */
export function documentUrl(p: Profile, file = p.rulebook.document, folder = false): string {
  const ref = p.source.commit ?? p.source.branch ?? 'main'
  const path = folder ? `profiles/${p.id}/${file}` : file
  return `${p.source.repository}/blob/${ref}/${path}`
}

/** What /tech and /dev show of a profile: its version, the links to its commit and rulebook, and
 *  the parts a version changes. */
export interface ProfileManifest {
  id: string
  label: string
  version: string
  date: string
  commit: string | null
  commitUrl: string | null
  documentUrl: string
  credential: Profile['credential'] & { metadataUrls: Array<{ label: string; url: string }> }
  functions: Array<{ id: string; kind: string; return?: string; wire: string; boundsDate?: string; meaning: string; translation: string[]; proof: string }>
  pseudonymConfigs: Array<{ id: string; seed: string; encodings: string[]; requested: boolean }>
  systems: ProfileSystem[]
}

export function profileManifest(p: Profile): ProfileManifest {
  return {
    id: p.id,
    label: p.label,
    version: p.rulebook.version,
    date: p.rulebook.date,
    commit: p.source.commit,
    commitUrl: commitUrl(p),
    documentUrl: documentUrl(p),
    credential: { ...p.credential, metadataUrls: (p.credential.metadata ?? []).map((m) => ({ label: m.label, url: documentUrl(p, m.file, true) })) },
    functions: (Object.entries(p.functions) as Array<[string, FunctionSpec]>).map(([id, f]) => ({
      id,
      kind: f.kind,
      ...(f.return && { return: f.return }),
      wire: f.wire,
      ...(f.bounds_date && { boundsDate: f.bounds_date }),
      meaning: f.meaning,
      translation: f.translation,
      proof: f.proof,
    })),
    pseudonymConfigs: p.pseudonym_configs.map((c) => ({ id: c.id, seed: c.seed, encodings: Object.keys(c.prf), requested: !!c.requested })),
    systems: p.systems,
  }
}
