// Timing and size model for the technical view's estimates.
//
// Desktop figures are measurements on Apple M5 and AMD Ryzen 9, from:
//   NYM-AUTH.md               full nym_auth statement (age + pseudonym) on mdoc
//   vega-caching-analysis.md  per-phase figures for a 1920-byte MSO
// BBS (mms_zk): bbs-cd-plugins' full-flow-bench (n = 20, 1 thread) on the 2-core Intel Xeon
// 2.8 GHz cloud VM the BBS backend was built on, 2026-10-19: ETSI BBS proof, ecdsa-pop (hashed,
// 96-bit limbs), date-range and pseudonym in one presentation.
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
  key: 'longfellow' | 'vega' | 'bbs'
  label: string
  proofSystem: string
  proofBytes: number
  phases: Phase[]
  notes: string[]
}

const NYM = 'NYM-AUTH.md'
const CACHE = 'vega-caching-analysis.md'
const BBS_BENCH = 'bbs-cd-plugins full-flow-bench'

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
  {
    key: 'bbs',
    label: 'BBS',
    proofSystem: 'bbs-cd-plugins-v0.1',
    proofBytes: 126_710,
    phases: [
      {
        id: 'setup',
        label: 'Setup',
        where: 'circuit provider',
        frequency: 'Once per circuit version',
        desktopMs: null,
        detail: 'No circuit: the issuer key and the schema are all a verifier needs',
        source: BBS_BENCH,
      },
      {
        id: 'precompute',
        label: 'Precompute',
        where: 'phone',
        frequency: 'Before each presentation',
        desktopMs: [8, 9],
        detail: 'BBS commitments and ecdsa-pop preparation, before the request arrives',
        source: BBS_BENCH,
      },
      {
        id: 'prove',
        label: 'Prove',
        where: 'phone',
        frequency: 'Every presentation',
        // Holder online: ProofGen 14.5, ecdsa-pop 135.8 (device signature 0.2), date-range 5.3, pseudonym 1.5.
        desktopMs: [152, 158],
        detail: 'ecdsa-pop 136 ms, BBS proof 14 ms, date-range 5 ms, pseudonym 1.5 ms',
        source: BBS_BENCH,
      },
      {
        id: 'transfer',
        label: 'Send proof',
        where: 'network',
        frequency: 'Every presentation',
        desktopMs: null,
        detail: '126.7 kB, of which ecdsa-pop 123.2 kB',
        source: BBS_BENCH,
      },
      {
        id: 'verify',
        label: 'Verify',
        where: 'Readdit server',
        frequency: 'Every presentation',
        // ProofVerify 10.4, ecdsa-pop 58.0, date-range 9.8, pseudonym 1.3, parse 1.6.
        desktopMs: [80, 82],
        detail: 'ecdsa-pop 58 ms, BBS proof 10 ms, date-range 10 ms',
        source: BBS_BENCH,
      },
    ],
    notes: [
      'Measured on a 2-core Intel Xeon cloud VM, not on the desktop machines above. Device binding (ecdsa-pop) takes most of the time and 97% of the size; without it a presentation is about 3.5 kB.',
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
