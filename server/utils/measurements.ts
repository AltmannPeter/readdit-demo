// The real numbers of /tech: one record per presentation that was proved through the mocked phone
// and verified, appended to a JSON-lines file (runtime config measurementsFile), so they survive
// restarts. /tech groups them by proof system, statement, threads and machine; its Clear button
// empties the file. A demo reset leaves them.
import { appendFile, mkdir, writeFile } from 'node:fs/promises'
import { existsSync, readFileSync } from 'node:fs'
import { availableParallelism, cpus, arch, platform, totalmem } from 'node:os'
import { dirname, resolve } from 'node:path'
import { PROOF_SYSTEMS, findCircuit, findScheme } from '#shared/registry/circuits'
import type { VpSessionRecord } from './store'

export interface Machine {
  cpu: string
  cores: number
  platform: string
  memory_gb: number
}

export interface Measurement {
  at: string
  proof_system: string
  format: 'circuit_zk' | 'mms_zk'
  proof_id: string
  /** What was proven: the pseudonym, or the pseudonym and an age range. */
  statement: 'pseudonym' | 'pseudonym and age'
  prove: {
    threads: number | null
    /** The phone's work for one presentation: device signature, witness and proof (circuit_zk), or the whole BBS presentation (mms_zk). */
    total_ms: number | null
    sign_ms: number | null
    witness_ms: number | null
    prove_ms: number | null
    proof_bytes: number | null
    presentation_bytes: number | null
    peak_memory_mb: number | null
  }
  verify: { threads: number | null; total_ms: number | null; verify_ms: number | null; peak_memory_mb: number | null }
  machine: Machine
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

const g = globalThis as unknown as { __readditMeasurements?: Measurement[] }

function file(): string {
  return resolve(process.cwd(), String(useRuntimeConfig().measurementsFile))
}

/** Every record, read from the file once. A line that does not parse is skipped. */
export function measurements(): Measurement[] {
  if (g.__readditMeasurements) return g.__readditMeasurements
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
  g.__readditMeasurements = list
  return list
}

const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null)

/**
 * Records a verified presentation from its session trace: the prover's metrics (the last prove
 * step, and the device signature for circuit_zk) and the verifier's. Nothing is recorded without a
 * prove step (a presentation made outside the mocked phone).
 */
export async function recordMeasurement(s: VpSessionRecord, format: 'circuit_zk' | 'mms_zk', proofId: string, verify: Record<string, unknown> | undefined, hasAge: boolean) {
  const at = (step: string) => s.trace.filter((t) => t.step === step && t.data?.metrics).at(-1)?.data as Record<string, any> | undefined
  const prove = at('prove')
  if (!prove) return
  const proofSystem = format === 'circuit_zk' ? findCircuit(proofId)?.proof_system : findScheme(proofId)?.proof_system
  if (!proofSystem) return
  const pm = prove.metrics as Record<string, unknown>
  const sign = format === 'circuit_zk' ? num((at('sign')?.metrics as Record<string, unknown> | undefined)?.sign_ms) : null
  const proveTotal = num(pm.total_ms)
  const m: Measurement = {
    at: new Date().toISOString(),
    proof_system: proofSystem,
    format,
    proof_id: proofId,
    statement: hasAge ? 'pseudonym and age' : 'pseudonym',
    prove: {
      threads: num(pm.threads),
      total_ms: proveTotal == null ? null : Math.round((proveTotal + (sign ?? 0)) * 1000) / 1000,
      sign_ms: sign,
      witness_ms: num(pm.witness_ms),
      prove_ms: num(pm.prove_ms),
      proof_bytes: num(pm.proof_bytes),
      presentation_bytes: num(pm.presentation_bytes),
      peak_memory_mb: num(pm.peak_memory_mb),
    },
    verify: {
      threads: num(verify?.threads),
      total_ms: num(verify?.total_ms),
      verify_ms: num(verify?.verify_ms),
      peak_memory_mb: num(verify?.peak_memory_mb),
    },
    machine: machine(),
  }
  measurements().push(m)
  try {
    await mkdir(dirname(file()), { recursive: true })
    await appendFile(file(), `${JSON.stringify(m)}\n`)
  } catch (e) {
    console.warn(`[measurements] cannot write ${file()}: ${(e as Error).message}`)
  }
}

/** Empties the file and the list. */
export async function clearMeasurements() {
  g.__readditMeasurements = []
  await mkdir(dirname(file()), { recursive: true })
  await writeFile(file(), '')
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
  peak_memory_mb: number | null
  last: string
}

/** The records grouped by proof system, statement, prover threads and machine. */
export function measurementSummary() {
  const list = measurements()
  const groups = new Map<string, Measurement[]>()
  for (const m of list) {
    const key = [m.proof_system, m.statement, m.prove.threads, m.machine.cpu, m.machine.cores, m.machine.platform].join('|')
    groups.set(key, [...(groups.get(key) ?? []), m])
  }
  const order = (id: string) => PROOF_SYSTEMS.findIndex((p) => p.id === id)
  const rows: MeasurementRow[] = [...groups.values()].map((ms) => {
    const m = ms[0]!
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
      peak_memory_mb: peaks.length ? Math.max(...peaks) : null,
      last: ms.at(-1)!.at,
    }
  })
  rows.sort((a, b) => order(a.proof_system) - order(b.proof_system) || a.statement.localeCompare(b.statement) || (a.threads ?? 0) - (b.threads ?? 0))
  return { runs: list.length, file: String(useRuntimeConfig().measurementsFile), machine: machine(), rows }
}
