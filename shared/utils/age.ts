import type { AgeGate, BirthDateRange, GateDecision } from '../types'

const pad = (n: number) => String(n).padStart(2, '0')

export function todayISO(now = new Date()): string {
  return now.toISOString().slice(0, 10)
}

/** Same calendar day `years` earlier; 29 Feb clamps to 28 Feb. */
export function subtractYears(iso: string, years: number): string {
  const [y, m, d] = iso.split('-').map(Number) as [number, number, number]
  const ty = y - years
  const lastDay = new Date(Date.UTC(ty, m, 0)).getUTCDate()
  return `${ty}-${pad(m)}-${pad(Math.min(d, lastDay))}`
}

export function addDays(iso: string, days: number): string {
  return new Date(Date.parse(`${iso}T00:00:00Z`) + days * 86_400_000).toISOString().slice(0, 10)
}

/**
 * Birth-date interval that satisfies an age gate on `today`.
 * minAge N  -> born on or before today - N years          (le)
 * maxAge N  -> born after today - (N + 1) years           (ge = that date + 1 day)
 */
export function gateRange(gate: AgeGate, today: string): BirthDateRange {
  const r: BirthDateRange = {}
  if (gate.minAge != null) r.le = subtractYears(today, gate.minAge)
  if (gate.maxAge != null) r.ge = addDays(subtractYears(today, gate.maxAge + 1), 1)
  return r
}

export function intersectRanges(a: BirthDateRange | null, b: BirthDateRange): BirthDateRange {
  if (!a) return { ...b }
  const ge = [a.ge, b.ge].filter(Boolean).sort().pop()
  const le = [a.le, b.le].filter(Boolean).sort().shift()
  return { ...(ge && { ge }), ...(le && { le }) }
}

/**
 * Decide access from what the site already knows.
 * allow: proven interval lies inside the gate interval.
 * deny:  proven interval does not overlap the gate interval (no need to ask the wallet).
 * ask:   unknown or partly overlapping; request a proof.
 */
export function decideGate(gate: AgeGate | null, proven: BirthDateRange | null, today: string): GateDecision {
  if (!gate) return 'allow'
  if (!proven) return 'ask'
  const g = gateRange(gate, today)
  const inside =
    (g.ge == null || (proven.ge != null && proven.ge >= g.ge)) &&
    (g.le == null || (proven.le != null && proven.le <= g.le))
  if (inside) return 'allow'
  const disjoint =
    (g.ge != null && proven.le != null && proven.le < g.ge) ||
    (g.le != null && proven.ge != null && proven.ge > g.le)
  return disjoint ? 'deny' : 'ask'
}

export function gateLabel(gate: AgeGate): string {
  if (gate.minAge != null && gate.maxAge != null) return `${gate.minAge}–${gate.maxAge}`
  if (gate.minAge != null) return `${gate.minAge}+`
  return `Under ${gate.maxAge! + 1}`
}

export function isAdultGate(gate: AgeGate | null): boolean {
  return !!gate && gate.minAge != null && gate.minAge >= 18
}
