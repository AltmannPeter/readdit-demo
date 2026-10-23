// The real numbers of /tech: one record per presentation that was proved through the mocked phone
// and verified, appended to a JSON-lines file (runtime config measurementsFile), so they survive
// restarts. /tech groups them by proof system, statement, threads and machine; its Clear button
// empties the file. A demo reset leaves them.
import { appendFile, mkdir, writeFile } from 'node:fs/promises'
import { existsSync, readFileSync } from 'node:fs'
import { availableParallelism, cpus, arch, platform, totalmem } from 'node:os'
import { dirname, resolve } from 'node:path'
import { PROOF_SYSTEMS, findSystem } from '#shared/registry/circuits'
import type { SourceFormat } from '#shared/types/oid4vp'
import type { VpSessionRecord } from './store'
import type { SizePart } from './services'
import { clearProfiles, profiledRuns, recordProfiles } from './profiles'

/** A step of a prove or verify and its time, in the order the step runs. */
export interface StepTime {
  name: string
  ms: number
}

export interface Machine {
  cpu: string
  cores: number
  platform: string
  memory_gb: number
}

export interface Measurement {
  at: string
  proof_system: string
  /** The source format (records made before rulebook v0.4 say circuit_zk or mms_zk). */
  format: SourceFormat | 'circuit_zk' | 'mms_zk'
  proof_id: string
  /** What was proven: the pseudonym, or the pseudonym and an age range. */
  statement: 'pseudonym' | 'pseudonym and age'
  prove: {
    threads: number | null
    /** The phone's work for one presentation: device signature, witness and proof (mso_mdoc), or the whole BBS presentation (bbs_cd). */
    total_ms: number | null
    sign_ms: number | null
    witness_ms: number | null
    prove_ms: number | null
    proof_bytes: number | null
    presentation_bytes: number | null
    /** The proof's working memory: the most heap the prover's own code held (absent in older records). */
    heap_mb?: number | null
    /** The heap the prover's loaded keys or circuits hold, and the witness held into the prove step. */
    keys_mb?: number | null
    witness_mb?: number | null
    /** The server process's peak resident set during the step (Linux only). */
    peak_memory_mb: number | null
    /** The time by step, adding up to total_ms (the rest as "Other"). */
    steps?: StepTime[]
    /** The bytes by part: the proof's (from the addon) and the presentation's. */
    proof_parts?: SizePart[] | null
    presentation_parts?: SizePart[] | null
  }
  verify: { threads: number | null; total_ms: number | null; verify_ms: number | null; heap_mb?: number | null; keys_mb?: number | null; peak_memory_mb: number | null; steps?: StepTime[] }
  machine: Machine
  /** Run with Profiling on: the sampler costs a little time, so the Benchmark leaves these runs
   *  out of its figures when the row has others. */
  profiled?: boolean
}

/** The Benchmark row of a record: proof system, statement, prover threads, machine. */
export function rowKey(m: Pick<Measurement, 'proof_system' | 'statement' | 'machine'> & { prove: { threads: number | null } }): string {
  return [m.proof_system, m.statement, m.prove.threads, m.machine.cpu, m.machine.cores, m.machine.platform].join('|')
}

/** `named` steps with their times, and "Other" for the rest of `total`. */
function steps(named: Array<[string, unknown]>, total: number | null): StepTime[] {
  const list = named.flatMap(([name, v]) => (num(v) == null ? [] : [{ name, ms: num(v)! }]))
  const rest = total == null ? 0 : total - list.reduce((t, x) => t + x.ms, 0)
  return rest > 0.05 ? [...list, { name: 'Other', ms: Math.round(rest * 1000) / 1000 }] : list
}

export function machine(): Machine {
  const model = cpus()[0]?.model?.trim()
  return {
    cpu: model && model !== 'unknown' ? model : `${arch()} CPU`,
    cores: availableParallelism(),
    platform: `${platform()} ${arch()}`,
    memory_gb: Math.round(totalmem() / 1e9),
  }
}

const g = globalThis as unknown as { __communityMeasurements?: Measurement[] }

function file(): string {
  return resolve(process.cwd(), String(useRuntimeConfig().measurementsFile))
}

/** Every record, read from the file once. A line that does not parse is skipped. */
export function measurements(): Measurement[] {
  if (g.__communityMeasurements) return g.__communityMeasurements
  const list: Measurement[] = []
  try {
    if (existsSync(file())) {
      for (const line of readFileSync(file(), 'utf8').split('\n')) {
        if (!line.trim()) continue
        try {
          list.push(JSON.parse(line) as Measurement)
        } catch {
          /* a torn line */
        }
      }
    }
  } catch (e) {
    console.warn(`[measurements] cannot read ${file()}: ${(e as Error).message}`)
  }
  g.__communityMeasurements = list
  return list
}

const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null)

/**
 * Records a verified presentation from its session trace: the prover's metrics (the last prove
 * step, and the device signature for mso_mdoc) and the verifier's. Nothing is recorded without a
 * prove step (a presentation made outside the mocked phone).
 */
export async function recordMeasurement(s: VpSessionRecord, format: SourceFormat, proofId: string, verify: Record<string, unknown> | undefined, hasAge: boolean) {
  const at = (step: string) => s.trace.filter((t) => t.step === step && t.data?.metrics).at(-1)?.data as Record<string, any> | undefined
  const prove = at('prove')
  if (!prove) return
  const proofSystem = findSystem(proofId)?.proof_system
  if (!proofSystem) return
  const pm = prove.metrics as Record<string, unknown>
  const sign = format === 'mso_mdoc' ? num((at('sign')?.metrics as Record<string, unknown> | undefined)?.sign_ms) : null
  const proveTotal = num(pm.total_ms)
  const total = proveTotal == null ? null : Math.round((proveTotal + (sign ?? 0)) * 1000) / 1000
  const v = verify ?? {}
  const proveSteps =
    format === 'mso_mdoc'
      ? steps([['Device signature', sign], ['Witness', pm.witness_ms], ['Proof', pm.prove_ms]], total)
      : steps([['Commitments and ecdsa-pop setup', pm.offline_ms], ['BBS proof', pm.bbs_ms], ['ecdsa-pop', pm.ecdsa_pop_ms], ['Pseudonym', pm.pseudonym_ms], ['Date range', pm.date_range_ms]], total)
  const verifySteps =
    format === 'mso_mdoc'
      ? steps([['Decode', v.decode_ms], ['Verify', v.verify_ms]], num(v.total_ms))
      : steps([['Parse', v.parse_ms], ['BBS proof', v.bbs_ms], ['ecdsa-pop', v.ecdsa_pop_ms], ['Pseudonym', v.pseudonym_ms], ['Date range', v.date_range_ms]], num(v.total_ms))
  const m: Measurement = {
    at: new Date().toISOString(),
    proof_system: proofSystem,
    format,
    proof_id: proofId,
    statement: hasAge ? 'pseudonym and age' : 'pseudonym',
    prove: {
      threads: num(pm.threads),
      total_ms: total,
      sign_ms: sign,
      witness_ms: num(pm.witness_ms),
      prove_ms: num(pm.prove_ms),
      proof_bytes: num(pm.proof_bytes),
      presentation_bytes: num(pm.presentation_bytes),
      heap_mb: num(pm.heap_mb),
      keys_mb: num(pm.keys_mb),
      witness_mb: num(pm.witness_mb),
      peak_memory_mb: num(pm.peak_memory_mb),
      steps: proveSteps,
      proof_parts: s.detail?.proofParts ?? null,
      presentation_parts: s.detail?.presentationParts ?? null,
    },
    verify: {
      threads: num(verify?.threads),
      total_ms: num(verify?.total_ms),
      verify_ms: num(verify?.verify_ms),
      heap_mb: num(verify?.heap_mb),
      keys_mb: num(verify?.keys_mb),
      peak_memory_mb: num(verify?.peak_memory_mb),
      steps: verifySteps,
    },
    machine: machine(),
    ...(s.detail && Object.keys(s.detail.profiles).length && { profiled: true }),
  }
  measurements().push(m)
  try {
    await mkdir(dirname(file()), { recursive: true })
    await appendFile(file(), `${JSON.stringify(m)}\n`)
  } catch (e) {
    console.warn(`[measurements] cannot write ${file()}: ${(e as Error).message}`)
  }
  await recordProfiles(s, m, rowKey(m))
}

/** Empties the file and the list, and the profiles. */
export async function clearMeasurements() {
  g.__communityMeasurements = []
  await mkdir(dirname(file()), { recursive: true })
  await writeFile(file(), '')
  await clearProfiles()
}

export interface Spread {
  median: number
  min: number
  max: number
}

function spread(values: Array<number | null>): Spread | null {
  const v = values.filter((x): x is number => x != null).sort((a, b) => a - b)
  if (!v.length) return null
  const mid = Math.floor(v.length / 2)
  const median = v.length % 2 ? v[mid]! : (v[mid - 1]! + v[mid]!) / 2
  return { median, min: v[0]!, max: v.at(-1)! }
}

export interface MeasurementRow {
  proof_system: string
  label: string
  statement: Measurement['statement']
  threads: number | null
  machine: Machine
  runs: number
  prove: Spread | null
  verify: Spread | null
  proof_bytes: Spread | null
  presentation_bytes: Spread | null
  /** The prover's and the verifier's own heap (the step's requirement). */
  prove_heap_mb: Spread | null
  verify_heap_mb: Spread | null
  /** The memory breakdown, medians: the loaded keys or circuits, the witness held, and the step's work. */
  memory: {
    prove: { keys_mb: number | null; witness_mb: number | null; work_mb: number | null }
    verify: { keys_mb: number | null; work_mb: number | null }
  }
  /** The server process's peak resident set (Linux only): Node and all addons. */
  peak_memory_mb: number | null
  last: string
  /** The row's key (GET /api/tech/profile?row=). */
  key: string
  /** Runs with Profiling on: left out of the figures when the row has others; the profiles kept. */
  profiled_runs: number
  /** The time by step, each the median over the runs. */
  steps: { prove: StepTime[]; verify: StepTime[] }
  /** The bytes by part, from the latest run that has them. */
  parts: { proof: SizePart[] | null; presentation: SizePart[] | null }
}

const median = (values: Array<number | null | undefined>) => spread(values.map((v) => v ?? null))?.median ?? null

/** The memory a proof needs, medians over the runs: the prover's loaded keys or circuits, the
 *  witness held into the prove step, and the rest of the prove step's heap; the verifier's keys or
 *  circuits and its step's heap. Prove total = keys + heap_mb; verify total = keys + heap_mb. */
function memoryOf(ms: Measurement[]): MeasurementRow['memory'] {
  const heap = median(ms.map((x) => x.prove.heap_mb))
  const witness = median(ms.map((x) => x.prove.witness_mb))
  return {
    prove: { keys_mb: median(ms.map((x) => x.prove.keys_mb)), witness_mb: witness, work_mb: heap == null ? null : Math.max(0, Math.round((heap - (witness ?? 0)) * 10) / 10) },
    verify: { keys_mb: median(ms.map((x) => x.verify.keys_mb)), work_mb: median(ms.map((x) => x.verify.heap_mb)) },
  }
}

/** Each step's median over the runs, in the order of the latest run. */
function stepsOf(lists: Array<StepTime[] | undefined>): StepTime[] {
  const names: string[] = []
  for (const l of [...lists].reverse()) for (const x of l ?? []) if (!names.includes(x.name)) names.push(x.name)
  const ordered = names.filter((n) => n !== 'Other').concat(names.includes('Other') ? ['Other'] : [])
  return ordered.map((name) => ({ name, ms: Math.round((median(lists.map((l) => l?.find((x) => x.name === name)?.ms)) ?? 0) * 1000) / 1000 }))
}

/** The records grouped by proof system, statement, prover threads and machine. */
export async function measurementSummary() {
  const list = measurements()
  const profiled = await profiledRuns()
  const groups = new Map<string, Measurement[]>()
  for (const m of list) {
    const key = rowKey(m)
    groups.set(key, [...(groups.get(key) ?? []), m])
  }
  const order = (id: string) => PROOF_SYSTEMS.findIndex((p) => p.id === id)
  const rows: MeasurementRow[] = [...groups.entries()].map(([key, all]) => {
    // Profiled runs only count when the row has nothing else.
    const plain = all.filter((x) => !x.profiled)
    const ms = plain.length ? plain : all
    const m = ms[0]!
    const latest = <T>(f: (x: Measurement) => T | null | undefined) => [...ms].reverse().map(f).find((x) => x != null) ?? null
    const peaks = ms.flatMap((x) => [x.prove.peak_memory_mb, x.verify.peak_memory_mb]).filter((x): x is number => x != null)
    return {
      proof_system: m.proof_system,
      label: PROOF_SYSTEMS.find((p) => p.id === m.proof_system)?.label ?? m.proof_system,
      statement: m.statement,
      threads: m.prove.threads,
      machine: m.machine,
      runs: ms.length,
      prove: spread(ms.map((x) => x.prove.total_ms)),
      verify: spread(ms.map((x) => x.verify.total_ms)),
      proof_bytes: spread(ms.map((x) => x.prove.proof_bytes)),
      presentation_bytes: spread(ms.map((x) => x.prove.presentation_bytes)),
      prove_heap_mb: spread(ms.map((x) => x.prove.heap_mb ?? null)),
      verify_heap_mb: spread(ms.map((x) => x.verify.heap_mb ?? null)),
      memory: memoryOf(ms),
      peak_memory_mb: peaks.length ? Math.max(...peaks) : null,
      last: all.at(-1)!.at,
      key,
      profiled_runs: profiled.get(key) ?? 0,
      steps: { prove: stepsOf(ms.map((x) => x.prove.steps)), verify: stepsOf(ms.map((x) => x.verify.steps)) },
      parts: { proof: latest((x) => x.prove.proof_parts), presentation: latest((x) => x.prove.presentation_parts) },
    }
  })
  rows.sort((a, b) => order(a.proof_system) - order(b.proof_system) || a.statement.localeCompare(b.statement) || (a.threads ?? 0) - (b.threads ?? 0))
  return { runs: list.length, file: String(useRuntimeConfig().measurementsFile), machine: machine(), rows }
}
