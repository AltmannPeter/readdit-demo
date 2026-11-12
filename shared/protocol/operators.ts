// The operators a profile's function specs name (`wire` in profiles/<id>/profile.json): how a
// function's params are written into a request from what the site wants, and read back into what
// they mean. The profile chooses the operator; the operator is code, versioned by name, so a new
// rulebook version adds operators instead of changing old ones.

import type { AgeGate, BirthDateRange } from '../types'
import { gateRange } from '../utils/age'

/** What an age_check item means, as the wallet and the site read it. `minAge`/`maxAge`: in whole
 *  years; `ge`/`le`: the birth-date bounds for the date the reader used. */
export interface AgeMeaning {
  minAge?: number
  maxAge?: number
  ge?: string
  le?: string
}

export type Read<T> = { ok: true; value: T } | { ok: false; reason: string }

export interface AgeOperator {
  /** The params for a community's age gate. `today`: the site's UTC date (bounds sent as dates). */
  build(gate: AgeGate, today: string): Record<string, string>
  /** What params mean on `date` (the UTC date the bounds are computed for). */
  read(params: Record<string, unknown>, date: string): Read<AgeMeaning>
  /** The age gate the params state, in whole years, where they state one. */
  gate(params: Record<string, unknown>): AgeGate | null
}

/** Whole years between a birth date and `date`. */
export function ageOn(birth: string, date: string): number {
  const [by, bm, bd] = birth.split('-').map(Number) as [number, number, number]
  const [ty, tm, td] = date.split('-').map(Number) as [number, number, number]
  return ty - by - (tm < bm || (tm === bm && td < bd) ? 1 : 0)
}

function daysBetween(a: string, b: string): number {
  return Math.round((Date.parse(`${b}T00:00:00Z`) - Date.parse(`${a}T00:00:00Z`)) / 86_400_000)
}

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/
const isCalendarDate = (s: string) => ISO_DATE.test(s) && new Date(`${s}T00:00:00Z`).toISOString().slice(0, 10) === s

/** v0.4: `{ ge, le }`, the birth-date bounds themselves (RFC 3339 full-date), at least one; when
 *  both, at least 365 days apart (rulebook v0.4, "Date predicate function"). */
const birthDateBounds: AgeOperator = {
  // gateRange's own key order (le, then ge), as v0.4 requests always had it.
  build: (gate, today) => ({ ...gateRange(gate, today) }) as Record<string, string>,
  read: (params, date) => {
    const keys = Object.keys(params)
    const unknown = keys.find((k) => k !== 'ge' && k !== 'le')
    if (unknown) return { ok: false, reason: `age_check parameter ${unknown} is not defined` }
    const { ge, le } = params as { ge?: unknown; le?: unknown }
    if (ge == null && le == null) return { ok: false, reason: 'age_check without ge or le' }
    for (const [k, v] of [['ge', ge], ['le', le]] as const) {
      if (v != null && (typeof v !== 'string' || !isCalendarDate(v))) return { ok: false, reason: `age_check.${k} is not a YYYY-MM-DD calendar date` }
    }
    const g = ge as string | undefined
    const l = le as string | undefined
    if (g && l && (l < g || daysBetween(g, l) + 1 < 365)) return { ok: false, reason: 'age_check bounds span less than 365 days' }
    return {
      ok: true,
      value: { ...(g && { ge: g, maxAge: ageOn(g, date) }), ...(l && { le: l, minAge: ageOn(l, date) }) },
    }
  },
  gate: () => null,
}

const RANGE = /^(?:(\d+)-(\d+)|(\d+)\+|(\d+)-)$/

/** Parses a v0.5 `range`: "A-B", "A+" or "B-" (rulebook v0.5, "Date predicate function"). */
export function parseRange(range: unknown): Read<AgeGate> {
  if (typeof range !== 'string') return { ok: false, reason: 'age_check.range is not a string' }
  const m = RANGE.exec(range)
  if (!m) return { ok: false, reason: `age_check.range ${range} is not A-B, A+ or B-` }
  if (m[1] != null) {
    const a = Number(m[1])
    const b = Number(m[2])
    if (a > b) return { ok: false, reason: `age_check.range ${range}: A is greater than B` }
    return { ok: true, value: { minAge: a, maxAge: b } }
  }
  if (m[3] != null) return { ok: true, value: { minAge: Number(m[3]) } }
  return { ok: true, value: { maxAge: Number(m[4]) } }
}

/** The `range` of an age gate: "13-17", "18+", "17-". */
export function rangeOf(gate: AgeGate): string {
  if (gate.minAge != null && gate.maxAge != null) return `${gate.minAge}-${gate.maxAge}`
  if (gate.minAge != null) return `${gate.minAge}+`
  return `${gate.maxAge}-`
}

/**
 * The birth-date bounds E (ge) and C (le) of an age range on D, the UTC date of proof_time
 * (rulebook v0.5): C is the latest calendar date on or before D minus A years, E the earliest
 * calendar date after D minus (B + 1) years; no E for A+, no C for B-. `gateRange` computes
 * exactly this (29 February: D minus N years that is no calendar date clamps to 28 February,
 * and the day after is 1 March).
 */
export function rangeBounds(gate: AgeGate, date: string): BirthDateRange {
  return gateRange(gate, date)
}

/** v0.5: `{ range }`, ages in whole years; the bounds are computed from the UTC date of proof_time. */
const yearsRange: AgeOperator = {
  build: (gate) => ({ range: rangeOf(gate) }),
  read: (params, date) => {
    const unknown = Object.keys(params).find((k) => k !== 'range')
    if (unknown) return { ok: false, reason: `age_check parameter ${unknown} is not defined` }
    const g = parseRange((params as { range?: unknown }).range)
    if (!g.ok) return g
    return { ok: true, value: { ...g.value, ...rangeBounds(g.value, date) } }
  },
  gate: (params) => {
    const g = parseRange((params as { range?: unknown }).range)
    return g.ok ? g.value : null
  },
}

export const AGE_OPERATORS: Record<string, AgeOperator> = {
  'age.birth-date-bounds@1': birthDateBounds,
  'age.years-range@1': yearsRange,
}

export function ageOperator(wire: string): AgeOperator {
  const op = AGE_OPERATORS[wire]
  if (!op) throw new Error(`no age operator ${wire}`)
  return op
}
