// The Benchmark's profile views: the sampled stacks (`entry;…;leaf` → samples, from
// native/nym-profile) grouped in several ways, each a tree whose leaves are functions. The groups
// come from function names, by rules per proof system written against the vendored libraries'
// code; whatever matches no rule lands in "Other", so a rule that no longer fits shows up there.
//
//   stages      the protocol's steps: the outermost frame that matches a stage rule, then the
//               stage's own parts (by priority: a commitment inside the witness counts as commitment)
//   field       the stages, then the field or curve the work is in (the frame nearest the leaf
//               that names one; for Longfellow GF(2^128) is the hash circuit and P-256 the signature circuit)
//   operations  what the CPU does: hashing, FFT, interpolation and Reed–Solomon, curve operations, field
//               arithmetic, memory; the frame nearest the leaf that names one
//   libraries   the library (crate) of the function that was running
//   functions   every function that was running when sampled, flat

export interface Group {
  name: string
  samples: number
  children: Group[]
}

export type View = 'stages' | 'field' | 'operations' | 'libraries' | 'functions'

interface Part {
  name: string
  match: RegExp
}
interface Stage extends Part {
  parts?: Part[]
}

/** Rust's own library and primitive types: they do work for the function that calls them. */
const STD = /^(core|alloc|std|__rustc)::|^(u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize|bool|char|str)::|^\[/

/** The steps the prover's stacks are rooted at (server/utils/profiles.ts). */
const STEP_ROOTS = ['Device signature', 'Witness', 'Proof', 'Verification']

const LONGFELLOW_PROVE: Stage[] = [
  {
    name: 'Ligero commitment',
    match: /LigeroProver::commit|ZkProver::commit/,
    parts: [
      { name: 'Merkle tree over the columns', match: /merkle|commitment::commit/i },
      { name: 'Witness rows, Reed–Solomon encoded', match: /layout_witness_rows/ },
      { name: 'Blinding and quadratic rows', match: /layout_blinding_rows|layout_quadratic_rows|random_row|random_subfield_row/ },
    ],
  },
  { name: 'Circuit evaluation', match: /eval::eval_circuit/ },
  {
    name: 'Sumcheck',
    match: /prove_core|runtime_sumcheck::prover/,
    parts: [
      { name: 'Binding the quadratic form', match: /HQuad::bind|bind_g|bind_h|dense::bind/ },
      { name: 'Round polynomials', match: /Poly::|eval_lagrange/ },
      { name: 'eq tables', match: /eq::/ },
      { name: 'Layer rounds', match: /prover::layer/ },
    ],
  },
  {
    name: 'Ligero proof',
    match: /LigeroProver::prove/,
    parts: [
      { name: 'Low-degree test', match: /low_degree_proof/ },
      { name: 'Linear test', match: /dot_proof/ },
      { name: 'Quadratic test', match: /quadratic_proof/ },
      { name: 'Opened columns', match: /gather_opened_columns|merkle/i },
    ],
  },
  { name: 'Writing the proof', match: /write_to_buf/ },
  { name: 'Transcript', match: /Transcript|runtime_random/ },
]

const LONGFELLOW_VERIFY: Stage[] = [
  { name: 'Reading the proof', match: /ZkProof::read|LigeroProof::read|::read$/ },
  { name: 'Public inputs', match: /hash_public|sig_public|set_mac_public/ },
  { name: 'Commitment into the transcript', match: /recv_commitment/ },
  {
    name: 'Ligero check',
    match: /LigeroVerifier::verify/,
    parts: [
      { name: 'Merkle check', match: /merkle_check/ },
      { name: 'Low-degree check', match: /low_degree_check/ },
      { name: 'Linear check', match: /dot_check/ },
      { name: 'Quadratic check', match: /quadratic_check/ },
      { name: 'Column interpolation', match: /interpolate_req_columns/ },
    ],
  },
  { name: 'Sumcheck check', match: /sumcheck/i },
]

/** Vega's parts, in priority order: the first that any frame of a stack matches. */
const VEGA_PARTS: Part[] = [
  { name: 'Opening (Hyrax, inner-product argument)', match: /HyraxPCS::prove|InnerProductArgument/ },
  { name: 'Folding (NIFS)', match: /NIFS|fold_witnesses|fold_instances/ },
  { name: 'Sumchecks', match: /[Ss]umcheck/ },
  { name: 'Commitments (multi-scalar multiplication)', match: /HyraxPCS::commit|commit_witness|msm/ },
  { name: 'Matrix–vector products', match: /multiply_vec|matrix_vector|evaluate_with_tables|evaluate_three_matrices/ },
  { name: 'Witness synthesis', match: /witness|SatisfyingAssignment|synthesize/i },
  { name: 'Conversions', match: /small_value|to_small|to_bytes/ },
]
const VEGA_PROVE: Stage[] = [
  { name: 'Preparation', match: /prep_prove|app::prepare/, parts: VEGA_PARTS },
  { name: 'Proving', match: /VegaMcZkSNARK::prove|app::prove/, parts: VEGA_PARTS },
]
const VEGA_VERIFY: Stage[] = [
  { name: 'Decoding', match: /deserialize/ },
  {
    name: 'Proof check',
    match: /VegaMcZkSNARK::verify|accept_pseudonym|app::verified/,
    parts: [
      { name: 'Opening check (Hyrax, inner-product argument)', match: /HyraxPCS::verify|InnerProductArgument/ },
      { name: 'Folding the commitments', match: /fold_commitments|fold_multiple|RelaxedR1CSInstance::fold|NIFS/ },
      { name: 'Matrix evaluation', match: /evaluate_with_tables|evaluate_three_matrices/ },
      { name: 'Sumchecks', match: /[Ss]umcheck/ },
      { name: 'Transcript', match: /Transcript|absorb/ },
      { name: 'eq tables', match: /EqPolynomial/ },
    ],
  },
]

const BBS_PROVE: Stage[] = [
  { name: 'Device key', match: /SigningKey/ },
  { name: 'ecdsa-pop setup', match: /cd_ecdsa_pop::prepare|hashed::prepare/ },
  { name: 'Commitments', match: /prepare_credential|committed_input/ },
  { name: 'ecdsa-pop proof', match: /EcdsaPopProver/ },
  { name: 'BBS proof', match: /bbs_proof|ProofGen/ },
  { name: 'Pseudonym', match: /PseudonymProver/ },
  { name: 'Date range', match: /DateRangeProver/ },
  { name: 'Parsing the envelope', match: /envelope::parse/ },
]
const BBS_VERIFY: Stage[] = [
  { name: 'ecdsa-pop check', match: /EcdsaPopVerifier/ },
  { name: 'BBS proof check', match: /ProofVerify|core_proof_verify/ },
  { name: 'Pseudonym check', match: /PseudonymVerifier/ },
  { name: 'Date range check', match: /DateRangeVerifier/ },
  { name: 'Parsing the envelope', match: /envelope::parse|octets_to_proof/ },
]

const RULES: Record<string, { prove: Stage[]; verify: Stage[] }> = {
  'longfellow-libzk-v1': { prove: LONGFELLOW_PROVE, verify: LONGFELLOW_VERIFY },
  'vega-v1': { prove: VEGA_PROVE, verify: VEGA_VERIFY },
  'bbs-cd-plugins-v0.1': { prove: BBS_PROVE, verify: BBS_VERIFY },
}

/** A stack's stage and part. */
function stageOf(frames: string[], stages: Stage[]): [string, string | null] {
  const root = STEP_ROOTS.includes(frames[0] ?? '') ? frames[0]! : null
  // Steps without stage rules of their own (device signature, witness) are a stage each.
  if (root && root !== 'Proof' && root !== 'Verification') return [root, null]
  let stage: Stage | undefined
  for (const f of frames) {
    stage = stages.find((s) => s.match.test(f))
    if (stage) break
  }
  if (!stage) return ['Other', null]
  if (!stage.parts) return [stage.name, null]
  const part = stage.parts.find((p) => frames.some((f) => p.match.test(f)))
  return [stage.name, part?.name ?? 'Rest']
}

const FIELDS: Array<[string, RegExp]> = [
  ['GF(2^128)', /gf2_128|Gf2_128|BinarySubfield|Lch14/i],
  ['Tom-256', /tom256|Tom256|cd_tom256/],
  ['T-256', /t256|T256/],
  ['P-256', /p256|P256|secp256r1/],
  ['BLS12-381', /bls12|blstrs/i],
]
/** Longfellow's prime-field code (generic fields, limbs) serves only its P-256 field. */
const LONGFELLOW_FIELDS: Array<[string, RegExp]> = [...FIELDS, ['P-256', /fp_generic|FpGeneric|runtime_algebra::limb/]]
/** The field or curve the work is in: the frame nearest the leaf that names one. */
function fieldOf(frames: string[], system: string): string {
  const fields = system === 'longfellow-libzk-v1' ? LONGFELLOW_FIELDS : FIELDS
  for (let i = frames.length - 1; i >= 0; i--) {
    const hit = fields.find(([, re]) => re.test(frames[i]!))
    if (hit) {
      if (system === 'longfellow-libzk-v1' && hit[0] === 'GF(2^128)') return 'GF(2^128), hash circuit'
      if (system === 'longfellow-libzk-v1' && hit[0] === 'P-256') return 'P-256, signature circuit'
      return hit[0]
    }
  }
  return 'No field named'
}

const OPERATIONS: Array<[string, RegExp]> = [
  ['Hashing', /sha2|sha256|Sha256|compress256|keccak|Keccak|blake|Digest|merkle/i],
  ['FFT, interpolation and Reed–Solomon', /fft|rfft|ReedSolomon|interpolat/i],
  ['Curve operations', /curve::|Projective|Affine|ProjectivePoint|msm|multiscalar|Wnaf|torsion|scalar_mul|vartime_mul/i],
]
/** The C library's copying, zeroing and allocation (memcpy, memset, malloc, free, …). */
const LIBC = /^(__)?(mem(cpy|move|set)|bzero|_platform_mem|(sys|_int_|__libc_)?(malloc|free|calloc|realloc)|madvise|munmap|mmap|__GI_)/
// The counting allocator's atomic counter (native/*/node/src/alloc.rs) counts as allocation.
const MEMORY = /core::sync::atomic|^(__)?(mem(cpy|move|set)|bzero)|malloc|_int_free|libc_free|realloc|calloc|sysmalloc|munmap|madvise|_platform_mem|ptr::write|ptr::copy|ptr::read|alloc::|memcpy|memmove|::clone$|to_vec|Vec::push|Vec::extend|extend_from_slice|copy_from_slice|__rustc::/
const ARITHMETIC = /^(u8|u16|u32|u64|u128|usize|i64|i128)::|core_arch|_mm_|clmul|black_box|field|Field|fp::|Fp|Fq|Fr|Gf2|gf2|limb|montgomery|::mac$|::adc$|::sbb$|reduce|::mul|::square|::add|::sub|::neg|invert|carrying|borrowing|widening|ct_eq|cmov|conditional_select|biginteger/
function operationOf(frames: string[]): string {
  const leaf = frames.at(-1) ?? ''
  if (MEMORY.test(leaf)) return 'Memory (allocation, copying)'
  for (let i = frames.length - 1; i >= 0; i--) {
    const hit = OPERATIONS.find(([, re]) => re.test(frames[i]!))
    if (hit) return hit[0]
  }
  return ARITHMETIC.test(leaf) ? 'Field and integer arithmetic' : 'Other'
}

/** The crate of the function that was running; Rust's own library counts for its caller, the C
 *  library for itself. */
function libraryOf(frames: string[]): string {
  if (LIBC.test(frames.at(-1) ?? '')) return 'C library (memcpy, malloc, …)'
  const own = [...frames].reverse().find((f) => !STD.test(f) && !STEP_ROOTS.includes(f))
  return (own ?? frames.at(-1) ?? 'unknown').split('::')[0] || 'unknown'
}

/** The function that was running, Rust's own library counted for its caller. */
function functionOf(frames: string[]): string {
  return [...frames].reverse().find((f) => !STD.test(f) && !STEP_ROOTS.includes(f)) ?? frames.at(-1) ?? 'unknown'
}

/** Adds `n` samples along `path`. */
function add(groups: Group[], path: string[], n: number) {
  let level = groups
  for (const name of path) {
    let g = level.find((x) => x.name === name)
    if (!g) level.push((g = { name, samples: 0, children: [] }))
    g.samples += n
    level = g.children
  }
}

function sorted(groups: Group[]): Group[] {
  return groups
    .sort((a, b) => (a.name === 'Other') !== (b.name === 'Other') ? (a.name === 'Other' ? 1 : -1) : b.samples - a.samples)
    .map((g) => ({ ...g, children: sorted(g.children) }))
}

/** Whether a proof system has stage rules. */
export const hasStages = (system: string) => system in RULES

/** The samples of one side (prove or verify) of a system, grouped by `view`. */
export function group(stacks: Record<string, number>, view: View, system: string, side: 'prove' | 'verify'): Group[] {
  const stages = RULES[system]?.[side] ?? []
  const out: Group[] = []
  for (const [stack, n] of Object.entries(stacks)) {
    let frames = stack.split(';')
    // The verifier's stacks have no step root: one step.
    if (side === 'verify' && !STEP_ROOTS.includes(frames[0]!)) frames = ['Verification', ...frames]
    if (side === 'prove' && !STEP_ROOTS.includes(frames[0]!)) frames = ['Proof', ...frames]
    const fn = functionOf(frames)
    if (view === 'stages' || view === 'field') {
      const [stage, part] = stageOf(frames, stages)
      const second = view === 'field' ? fieldOf(frames, system) : part
      add(out, second ? [stage, second, fn] : [stage, fn], n)
    } else if (view === 'operations') add(out, [operationOf(frames), fieldOf(frames, system), fn], n)
    else if (view === 'libraries') add(out, [libraryOf(frames), fn], n)
    else add(out, [fn], n)
  }
  return sorted(out)
}
