// /tech's Profiling switch and the Benchmark's breakdowns.
//
// With Profiling on, each addon step samples where its time goes (server/utils/services.ts passes
// `profile`, the addons return the folded stacks and, for Vega, vega-prover's own phases). A
// presentation's profiles stay on its session (`detail`, never in a trace or an API answer about
// the session) until it is verified; then one record per presentation is appended to a JSON-lines
// file next to the measurements (runtime config profilesFile), so profiles survive restarts and
// switching Profiling off. /tech asks for one Benchmark row's profiles when its time is opened
// (GET /api/tech/profile). /tech's Clear empties this file with the measurements'.
//
// The bytes of a presentation by part (`presentationParts`) are counted here, from the
// ZkpPresentation's CBOR; the proof's own parts come from the addons (`proof_parts`).
import { appendFile, mkdir, readFile, writeFile } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import type { Machine, Measurement } from './measurements'
import type { PhaseNode, SizePart, StepProfile } from './services'
import type { SessionDetail, VpSessionRecord } from './store'

type Step = keyof SessionDetail['profiles']

/** Keeps a step's profile on its session until the presentation is verified. */
export function keepProfile(s: VpSessionRecord | undefined, step: Step, profile: StepProfile | undefined) {
  if (!s || !profile) return
  s.detail ??= { profiles: {} }
  s.detail.profiles[step] = profile
}

/** Keeps the bytes of a presentation and its proof by part. */
export function keepParts(s: VpSessionRecord | undefined, presentation: string, proofParts: SizePart[] | undefined) {
  if (!s) return
  s.detail ??= { profiles: {} }
  s.detail.proofParts = proofParts ?? null
  s.detail.presentationParts = presentationParts(presentation)
}

/** The offset just past the CBOR data item at `off` (RFC 8949: definite lengths; an indefinite
 *  length or a truncated item throws). */
function itemEnd(b: Buffer, off: number): number {
  const major = b[off]! >> 5
  const info = b[off]! & 0x1f
  let p = off + 1
  let n: number
  if (info < 24) n = info
  else if (info === 24) (n = b.readUInt8(p)), (p += 1)
  else if (info === 25) (n = b.readUInt16BE(p)), (p += 2)
  else if (info === 26) (n = b.readUInt32BE(p)), (p += 4)
  else if (info === 27) (n = Number(b.readBigUInt64BE(p))), (p += 8)
  else throw new Error('indefinite length')
  if (major === 0 || major === 1 || major === 7) return p
  if (major === 2 || major === 3) {
    if (p + n > b.length) throw new Error('truncated')
    return p + n
  }
  if (major === 4) {
    for (let i = 0; i < n; i++) p = itemEnd(b, p)
    return p
  }
  if (major === 5) {
    for (let i = 0; i < 2 * n; i++) p = itemEnd(b, p)
    return p
  }
  return itemEnd(b, p) // major 6: a tag and its item
}

/**
 * The ZkpPresentation's bytes by field (rulebook v0.4, "Presentation encoding"): each entry of its
 * CBOR map, key and value, and the map's own header, read from the bytes as they are. Null when
 * it is not a CBOR map that ends where the presentation ends.
 */
export function presentationParts(b64: string): SizePart[] | null {
  try {
    const b = Buffer.from(b64, 'base64url')
    if (b[0]! >> 5 !== 5) return null
    const info = b[0]! & 0x1f
    const headerBytes = info < 24 ? 1 : info === 24 ? 2 : info === 25 ? 3 : info === 26 ? 5 : 9
    if (info > 26) return null
    const count = info < 24 ? info : info === 24 ? b[1]! : info === 25 ? b.readUInt16BE(1) : b.readUInt32BE(1)
    const parts: SizePart[] = []
    let p = headerBytes
    for (let i = 0; i < count; i++) {
      const keyEnd = itemEnd(b, p)
      const name = cborText(b, p) ?? `key ${i}`
      const end = itemEnd(b, keyEnd)
      parts.push({ name, bytes: end - p, code: true, children: [] })
      p = end
    }
    if (p !== b.length) return null
    return [...parts, { name: 'CBOR map header', bytes: headerBytes, children: [] }]
  } catch {
    return null
  }
}

/** The text of the CBOR text string at `off`, if it is one. */
function cborText(b: Buffer, off: number): string | null {
  if (b[off]! >> 5 !== 3) return null
  const end = itemEnd(b, off)
  const info = b[off]! & 0x1f
  const head = info < 24 ? 1 : info === 24 ? 2 : info === 25 ? 3 : info === 26 ? 5 : 9
  return b.subarray(off + head, end).toString('utf8')
}

export interface ProfileRecord {
  at: string
  /** The Benchmark row this run belongs to (measurements.ts, rowKey). */
  row: string
  proof_system: string
  statement: Measurement['statement']
  threads: number | null
  machine: Machine
  prove: Partial<Record<'sign' | 'witness' | 'prove', StepProfile>>
  verify: StepProfile | null
}

function file(): string {
  return resolve(process.cwd(), String(useRuntimeConfig().profilesFile))
}

/** Appends the verified presentation's profiles, if it has any. */
export async function recordProfiles(s: VpSessionRecord, m: Measurement, row: string) {
  const p = s.detail?.profiles
  if (!p || !Object.keys(p).length) return
  const r: ProfileRecord = {
    at: m.at,
    row,
    proof_system: m.proof_system,
    statement: m.statement,
    threads: m.prove.threads,
    machine: m.machine,
    prove: { ...(p.sign && { sign: p.sign }), ...(p.witness && { witness: p.witness }), ...(p.prove && { prove: p.prove }) },
    verify: p.verify ?? null,
  }
  try {
    await mkdir(dirname(file()), { recursive: true })
    await appendFile(file(), `${JSON.stringify(r)}\n`)
  } catch (e) {
    console.warn(`[profiles] cannot write ${file()}: ${(e as Error).message}`)
  }
}

async function records(): Promise<ProfileRecord[]> {
  if (!existsSync(file())) return []
  const out: ProfileRecord[] = []
  for (const line of (await readFile(file(), 'utf8')).split('\n')) {
    if (!line.trim()) continue
    try {
      out.push(JSON.parse(line) as ProfileRecord)
    } catch {
      /* a torn line */
    }
  }
  return out
}

/** Profiled runs per Benchmark row. */
export async function profiledRuns(): Promise<Map<string, number>> {
  const n = new Map<string, number>()
  for (const r of await records()) n.set(r.row, (n.get(r.row) ?? 0) + 1)
  return n
}

export async function clearProfiles() {
  await mkdir(dirname(file()), { recursive: true })
  await writeFile(file(), '')
}

/** One side's profile over a row's runs: the samples summed (each step a root of its own), and
 *  the phases with each one's median over the runs that ran it. */
export interface SideProfile {
  runs: number
  samples: number
  other: number
  /** Samples whose stack the unwinder could not walk. */
  lost: number
  hz: number | null
  stacks: Record<string, number>
  phases: PhaseNode[] | null
}

const STEP_LABELS: Record<string, string> = { sign: 'Device signature', witness: 'Witness', prove: 'Proof', verify: 'Verification' }

function median(values: number[]): number {
  const v = [...values].sort((a, b) => a - b)
  const mid = Math.floor(v.length / 2)
  return v.length % 2 ? v[mid]! : (v[mid - 1]! + v[mid]!) / 2
}

/** The phases of several runs as one tree: the latest run's shape, each phase's runs, time and
 *  heap the median over the runs that have it. */
function mergePhases(runs: PhaseNode[][]): PhaseNode[] | null {
  if (!runs.length) return null
  const level = (lists: PhaseNode[][]): PhaseNode[] => {
    const names: string[] = []
    for (const l of [...lists].reverse()) for (const n of l) if (!names.includes(n.name)) names.push(n.name)
    return names.map((name) => {
      const same = lists.flatMap((l) => l.filter((n) => n.name === name))
      const mbs = same.map((n) => n.mb).filter((x): x is number => x != null)
      return {
        name,
        n: Math.round(median(same.map((n) => n.n))),
        ms: Math.round(median(same.map((n) => n.ms)) * 100) / 100,
        mb: mbs.length ? Math.round(median(mbs) * 10) / 10 : null,
        children: level(same.map((n) => n.children)),
      }
    })
  }
  return level(runs)
}

function side(steps: Array<Record<string, StepProfile | null | undefined>>, prefix: boolean): SideProfile {
  const out: SideProfile = { runs: steps.length, samples: 0, other: 0, lost: 0, hz: null, stacks: {}, phases: null }
  const phases: PhaseNode[][] = []
  for (const run of steps) {
    const runPhases: PhaseNode[] = []
    for (const [step, p] of Object.entries(run)) {
      if (!p) continue
      out.samples += p.samples ?? 0
      out.other += p.other ?? 0
      out.lost += p.lost ?? 0
      out.hz ??= p.hz ?? null
      const root = STEP_LABELS[step] ?? step
      for (const [stack, n] of Object.entries(p.stacks ?? {})) {
        const key = prefix ? `${root};${stack}` : stack
        out.stacks[key] = (out.stacks[key] ?? 0) + n
      }
      if (p.phases?.length) runPhases.push(...(prefix ? [{ name: root, n: 1, ms: p.phases.reduce((t, x) => t + x.ms, 0), mb: null, children: p.phases }] : p.phases))
    }
    if (runPhases.length) phases.push(runPhases)
  }
  out.phases = mergePhases(phases)
  return out
}

/** A Benchmark row's profiles: the prover's (each step a root: device signature, witness, proof)
 *  and the verifier's, over every profiled run of the row. */
export async function rowProfile(row: string) {
  const runs = (await records()).filter((r) => r.row === row)
  return {
    row,
    runs: runs.length,
    prove: side(runs.map((r) => r.prove), Object.keys(runs.at(-1)?.prove ?? {}).length > 1),
    verify: side(runs.map((r) => ({ verify: r.verify })), false),
  }
}
