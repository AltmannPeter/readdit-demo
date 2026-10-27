// Runs the site's own code against the rulebook v0.5 test vectors
// (profiles/nym-auth-v0.5/test-vectors/nym_auth_mdoc, from the nym_auth rulebook repository):
// the commitments, the four pseudonym configurations (prf sha-256), the age_check operator of the
// v0.5 profile and the range bounds, and that the profile's mdoc encoding matches the fixture.
// The addons have their own tests on the same files (rulebook_vectors.rs in nym-vega,
// nym-longfellow and nym-bbs: the bounds, and the SessionTranscript and device message). The
// fixture itself is checked by the rulebook's verify_nym_auth_mdoc.py.
//
//   npm run vectors:check

import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { decode } from 'cbor-x'
import { createJiti } from 'jiti'

const root = fileURLToPath(new URL('../', import.meta.url))
const dir = `${root}profiles/nym-auth-v0.5/test-vectors/nym_auth_mdoc/`
const jiti = createJiti(import.meta.url)
const { ageOperator, parseRange, rangeBounds, rangeOf } = await jiti.import(`${root}shared/protocol/operators.ts`)
const { derivePseudonym } = await jiti.import(`${root}shared/utils/pseudonym.ts`)
const { findProfile } = await jiti.import(`${root}shared/profiles/index.ts`)

const results = []
const ok = (c, m) => {
  console.log(`${c ? 'PASS' : 'FAIL'} ${m}`)
  results.push(!!c)
}
const sha = (b) => createHash('sha256').update(b).digest('hex')
const bytes = (hex) => Buffer.from(hex, 'hex')

const profile = findProfile('nym-auth-v0.5')
const mdoc = profile.credential.encodings.mso_mdoc
const age = profile.functions.age_check

for (const variant of ['', '_zero_psc']) {
  const V = JSON.parse(readFileSync(`${dir}nym_auth_test_vectors${variant}.json`, 'utf8'))
  const p = `[${variant ? 'zero psc' : 'psc'}]`
  const h = V.holder_openings

  // The profile's mdoc encoding and the fixture's IssuerSigned.
  const issuerSigned = decode(readFileSync(`${dir}issuer_signed${variant}.cbor`))
  ok(sha(readFileSync(`${dir}issuer_signed${variant}.cbor`)) === sha(bytes(V.issuer_signed_cbor)), `${p} issuer_signed${variant}.cbor is the JSON's issuer_signed_cbor`)
  const namespaces = Object.keys(issuerSigned.nameSpaces)
  ok(namespaces.length === 1 && namespaces[0] === mdoc.doctype, `${p} namespace ${namespaces[0]} is the profile's doctype`)
  const ids = V.issuer_signed_items.map((i) => i.elementIdentifier)
  const required = mdoc.attributes.filter((a) => a.presence === 'required').map((a) => a.id)
  ok(JSON.stringify(ids) === JSON.stringify(required), `${p} data elements ${ids.join(', ')} are the profile's required attributes, in digestID order`)
  ok(V.issuer_signed_items.every((it, n) => it.digestID === n && sha(bytes(it.item_bytes_tag24)) === it.digest), `${p} item digests`)

  // Commitments.
  ok(sha(Buffer.concat([bytes(h.secret_seed), Buffer.from(h.birth_date, 'utf8')])) === V.commitments.bsc, `${p} bsc = SHA-256(secret_seed || birth_date), ${h.birth_date.length}-byte birth_date`)
  ok(V.commitments.psc === (h.private_seed ? sha(bytes(h.private_seed)) : '00'.repeat(32)), `${p} psc = ${h.private_seed ? 'SHA-256(private_seed)' : '32 zero bytes'}`)

  // Pseudonyms (shared/utils/pseudonym.ts).
  const inputs = V.expected.pseudonym_inputs
  for (const [config, want] of Object.entries(V.expected.pseudonyms_sha256)) {
    const seed = config.endsWith('-psc') ? h.private_seed : h.secret_seed
    if (seed == null) {
      ok(!/^[0-9a-f]{64}$/.test(String(want)), `${p} ${config}: no private_seed, the vectors expect no pseudonym`)
      continue
    }
    const got = await derivePseudonym({ config, seed: bytes(seed), verifierId: inputs.verifier_id, verifierContext: inputs.verifier_context, userValue: inputs.user_supplied_value })
    ok(got === want, `${p} pseudonym ${config}`)
  }

  // age_check: the v0.5 profile's operator reads { range } on D, the UTC date of proof_time.
  const a = V.expected.age_check
  ok(a.proof_time.slice(0, 10) === a.D, `${p} D is the UTC date of proof_time ${a.proof_time}`)
  const op = ageOperator(age.wire)
  for (const c of a.cases) {
    const r = op.read({ range: c.range }, a.D)
    const g = r.ok ? r.value : {}
    const holds = (g.ge == null || g.ge <= a.birth_date) && (g.le == null || a.birth_date <= g.le)
    ok(r.ok && (g.ge ?? null) === c.E && (g.le ?? null) === c.C && holds === c.holds, `${p} age_check ${c.range} on ${a.D}: E ${c.E}, C ${c.C}, ${c.holds ? 'holds' : 'does not hold'} for ${a.birth_date}`)
    const gate = op.gate({ range: c.range })
    ok(gate && JSON.stringify(op.build(gate, a.D)) === JSON.stringify({ range: c.range }), `${p} the site writes ${c.range} as { range: "${c.range}" }`)
  }
  for (const c of V.expected.range_conversion) {
    const g = parseRange(c.range)
    const b = g.ok ? rangeBounds(g.value, c.D) : {}
    ok(g.ok && rangeOf(g.value) === c.range && (b.ge ?? null) === c.E && (b.le ?? null) === c.C, `${p} range ${c.range} on ${c.D}: E ${c.E}, C ${c.C}`)
  }
}

const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} checks passed`)
process.exit(passed === results.length ? 0 : 1)
