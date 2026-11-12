// The request interpreter: writes the `_req` items Community asks for, and reads `_req` items back
// into what they mean, from a profile's function specs (profiles/<id>/profile.json) and the
// operators they name (./operators.ts). Nothing here knows a rulebook version: a profile says
// whether a function is a value function (with a return handle) or an assertion, which operator
// writes and reads its params, and where an age check's date comes from.

import type { AgeGate } from '../types'
import type { AgeCheckReq, PseudonymReq, ReqItem, SourceFormat } from '../types/oid4vp'
import { PROFILES, requestedConfig, type FunctionSpec, type Profile } from '../profiles'
import { ageOperator, type AgeMeaning } from './operators'

/** The `_req` items for a request: the pseudonym, and the age check when the site asks for one. */
export function buildReq(profile: Profile, source: SourceFormat, ageParams?: Record<string, string>): ReqItem[] {
  const cfg = requestedConfig(profile)
  const nym = profile.functions.pseudonym
  const prf = cfg.prf[source]
  if (!prf) throw new Error(`profile ${profile.id}: ${cfg.id} has no prf for ${source}`)
  const items: ReqItem[] = [{ fn_id: 'pseudonym', return: nym.return!, params: { config: cfg.id, ver: 1, prf } } as PseudonymReq]
  if (ageParams) {
    const age = profile.functions.age_check
    items.push({ fn_id: 'age_check', ...(age.kind === 'value' && { return: age.return! }), params: { ...ageParams } } as AgeCheckReq)
  }
  return items
}

/** The age_check params for a community's age gate, as the profile writes them. */
export function ageParamsFor(profile: Profile, gate: AgeGate, today: string): Record<string, string> {
  return ageOperator(profile.functions.age_check.wire).build(gate, today)
}

export type ReadItem =
  | { fn: 'pseudonym'; handle: string; params: PseudonymReq['params'] }
  | ({ fn: 'age'; handle?: string; boundsDate: 'request' | 'proof_time'; params: Record<string, unknown> } & AgeMeaning)

export type ReadReq = { ok: true; profile: Profile; items: ReadItem[] } | { ok: false; reason: string }

/** The function spec of a `fn_id`, or null when the profile has no such function. */
function specOf(profile: Profile, fnId: string): FunctionSpec | null {
  return fnId === 'pseudonym' || fnId === 'age_check' ? profile.functions[fnId] : null
}

/**
 * Reads `_req` under one profile: each item's function is in the profile's catalogue, carries
 * `return` exactly when it is a value function (handles unique), and its params read with the
 * function's operator; at most one item per function. `date`: the UTC date age bounds are
 * computed for when the profile takes them from proof_time (the wallet: its date now).
 */
export function readReq(profile: Profile, req: unknown[], date: string): ReadReq {
  const items: ReadItem[] = []
  const handles = new Set<string>()
  const seen = new Set<string>()
  for (const raw of req) {
    const r = raw as { fn_id?: unknown; return?: unknown; params?: unknown }
    const fnId = String(r.fn_id)
    const spec = specOf(profile, fnId)
    if (!spec) return { ok: false, reason: `function ${fnId} is not in the rulebook's catalogue` }
    if (seen.has(fnId)) return { ok: false, reason: 'more than one pseudonym or age_check in _req' }
    seen.add(fnId)
    const handle = r.return
    if (spec.kind === 'value') {
      if (typeof handle !== 'string' || !handle) return { ok: false, reason: `${fnId} is a value function: return is required` }
      if (handles.has(handle)) return { ok: false, reason: `return handle ${handle} is not unique` }
      handles.add(handle)
    } else if (handle !== undefined) {
      return { ok: false, reason: `${fnId} is an assertion: return must not be present` }
    }
    const params = (r.params ?? {}) as Record<string, unknown>
    if (typeof params !== 'object' || Array.isArray(params)) return { ok: false, reason: `${fnId}.params is not an object` }
    if (fnId === 'pseudonym') {
      items.push({ fn: 'pseudonym', handle: handle as string, params: params as PseudonymReq['params'] })
    } else {
      const read = ageOperator(spec.wire).read(params, date)
      if (!read.ok) return read
      items.push({ fn: 'age', ...(typeof handle === 'string' && { handle }), boundsDate: spec.bounds_date ?? 'request', params, ...read.value })
    }
  }
  return { ok: true, profile, items }
}

/**
 * The profile a request's `_req` fits, among `candidates` (newest first): the first under which
 * every item reads. A request with only a pseudonym fits every profile; the newest wins. With no
 * fit, the reason the newest candidate gives.
 */
export function readReqAnyProfile(req: unknown[], date: string, candidates: Profile[] = PROFILES): ReadReq {
  const ordered = [...candidates].reverse()
  let first: ReadReq | null = null
  for (const p of ordered) {
    const r = readReq(p, req, date)
    if (r.ok) return r
    first ??= r
  }
  return first ?? { ok: false, reason: 'no profile' }
}
