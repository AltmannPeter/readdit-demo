// Timing and size model for the technical view and the offline simulation.
//
// Desktop figures are measurements on Apple M5 and AMD Ryzen 9, from:
//   NYM-AUTH.md               full nym_auth statement (age + pseudonym) on mdoc
//   vega-caching-analysis.md  per-phase figures for a 1920-byte MSO
// Phone figures are NOT measured: desktop x PHONE_FACTOR (1-5x), applied only to
// phases that run on the phone.

export const DESKTOP_MACHINES = 'Apple M5 and AMD Ryzen 9'
export const PHONE_FACTOR = { min: 1, max: 5 } as const
/** Mobile uplink assumed for sending the proof, Mbit/s. */
export const UPLINK_MBPS = { min: 5, max: 50 } as const

export type Where = 'circuit provider' | 'phone' | 'network' | 'Readdit server'
export type Range = readonly [number, number]

export interface Phase {
  id: 'setup' | 'precompute' | 'prove' | 'transfer' | 'verify'
  label: string
  where: Where
  frequency: string
  /** Desktop time in ms, or null when the system has no such phase. */
  desktopMs: Range | null
  detail?: string
  source: string
}

export interface SystemModel {
  key: 'longfellow' | 'vega'
  label: string
  proofSystem: string
  proofBytes: number
  phases: Phase[]
  notes: string[]
}

const NYM = 'NYM-AUTH.md'
const CACHE = 'vega-caching-analysis.md'

export const SYSTEMS: SystemModel[] = [
  {
    key: 'longfellow',
    label: 'Longfellow',
    proofSystem: 'longfellow-libzk-v1',
    proofBytes: 345_608,
    phases: [
      {
        id: 'setup',
        label: 'Setup',
        where: 'circuit provider',
        frequency: 'Once per circuit version',
        desktopMs: [5_500, 8_000],
        detail: 'Keys ~200 kB, published; the phone downloads them once',
        source: CACHE,
      },
      {
        id: 'precompute',
        label: 'Precompute',
        where: 'phone',
        frequency: 'Not used by Longfellow',
        desktopMs: null,
        source: CACHE,
      },
      {
        id: 'prove',
        label: 'Prove',
        where: 'phone',
        frequency: 'Every presentation',
        // Google Rust, load + witness + prove: 32 threads with caches (30.3+32.4+154)
        // to 1 thread without caches (219+92.0+277).
        desktopMs: [217, 588],
        detail: 'Load, witness and prove. Peak memory 94–158 MB',
        source: NYM,
      },
      {
        id: 'transfer',
        label: 'Send proof',
        where: 'network',
        frequency: 'Every presentation',
        desktopMs: null,
        detail: '345.6 kB',
        source: NYM,
      },
      {
        id: 'verify',
        label: 'Verify',
        where: 'Readdit server',
        frequency: 'Every presentation',
        // 32 threads with caches (28.7+82.6) to 1 thread without caches (224+130).
        desktopMs: [111, 354],
        detail: 'Load and verify',
        source: NYM,
      },
    ],
    notes: ['Longfellow has no per-attestation precompute: all work happens at proving time.'],
  },
  {
    key: 'vega',
    label: 'VegaMC',
    proofSystem: 'vega-v1',
    proofBytes: 96_079,
    phases: [
      {
        id: 'setup',
        label: 'Setup',
        where: 'circuit provider',
        frequency: 'Once per circuit version',
        desktopMs: [50, 210],
        detail: 'Keys ~470 kB, published; the phone downloads them once',
        source: CACHE,
      },
      {
        id: 'precompute',
        label: 'Precompute',
        where: 'phone',
        frequency: 'Once per attestation',
        desktopMs: [65, 400],
        detail: 'Hashes the attestation, checks the issuer signature. Stores ~100 MB',
        source: CACHE,
      },
      {
        id: 'prove',
        label: 'Prove',
        where: 'phone',
        frequency: 'Every presentation',
        desktopMs: [92, 237],
        detail: 'Peak memory ~550 MB',
        source: CACHE,
      },
      {
        id: 'transfer',
        label: 'Send proof',
        where: 'network',
        frequency: 'Every presentation',
        desktopMs: null,
        detail: '96.1 kB',
        source: NYM,
      },
      {
        id: 'verify',
        label: 'Verify',
        where: 'Readdit server',
        frequency: 'Every presentation',
        // Vega (macro): 32 threads (99.8+33.3) to 1 thread minimal storage (309+58.5).
        desktopMs: [133, 368],
        detail: 'Load and verify',
        source: NYM,
      },
    ],
    notes: [
      'Prove assumes setup and precompute are cached. The demo implementation measured 340–948 ms per presentation (NYM-AUTH.md), which may include them every time.',
      'Peak memory of ~550 MB matters on phones.',
    ],
  },
]

export function transferMs(bytes: number): Range {
  const bits = bytes * 8
  return [Math.round(bits / (UPLINK_MBPS.max * 1000)), Math.round(bits / (UPLINK_MBPS.min * 1000))]
}

/** Time for a phase on the phone setup: phone phases x factor, network from uplink, server unchanged. */
export function phaseRange(sys: SystemModel, p: Phase): Range | null {
  if (p.id === 'transfer') return transferMs(sys.proofBytes)
  if (!p.desktopMs) return null
  if (p.where === 'phone') return [p.desktopMs[0] * PHONE_FACTOR.min, p.desktopMs[1] * PHONE_FACTOR.max]
  return p.desktopMs
}

/** Per presentation: prove on the phone + send + verify. */
export function presentationRange(sys: SystemModel): Range {
  let lo = 0
  let hi = 0
  for (const p of sys.phases) {
    if (p.frequency !== 'Every presentation') continue
    const r = phaseRange(sys, p)
    if (r) {
      lo += r[0]
      hi += r[1]
    }
  }
  return [lo, hi]
}

export function systemForCircuit(circuitId?: string | null): SystemModel {
  return SYSTEMS.find((s) => circuitId?.includes(`:${s.key}:`)) ?? SYSTEMS[0]!
}

/**
 * Point values used by the offline simulation (Longfellow, Google Rust, 1 thread, with caches,
 * NYM-AUTH.md), scaled by the chosen phone factor for the phone-side steps.
 */
export function simulatedLongfellow(phoneFactor: number) {
  const f = phoneFactor
  return {
    prove: {
      load_ms: +(37.9 * f).toFixed(1),
      witness_ms: +(44.6 * f).toFixed(1),
      prove_ms: +(276 * f).toFixed(1),
      total_ms: +((37.9 + 44.6 + 276) * f).toFixed(1),
      peak_memory_mb: 94,
      proof_bytes: 345_608,
    },
    verify: { load_ms: 34.5, verify_ms: 131, total_ms: 165.5, proof_bytes: 345_608 },
  }
}
