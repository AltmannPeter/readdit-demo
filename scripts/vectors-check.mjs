// Runs the site's own code against the rulebook v0.5 test vectors
// (profiles/nym-auth-v0.5/test-vectors/nym_auth_mdoc, from the nym_auth rulebook repository):
// the commitments, the four pseudonym configurations (prf sha-256), the age_check operator of the
// v0.5 profile and the range bounds, and that the profile's mdoc encoding matches the fixture.
// Then the same against the v0.6 profile's provisional vectors
// (profiles/nym-auth-v0.6/test-vectors/nym_auth_mdoc_decoy, the circuit package's: the v0.5
// vectors' keys, openings and sessions, the credential in the decoy-digest layout), where the
// fixture is read with shared/utils/mdoc.ts (bsc and psc from the MSO's valueDigests).
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
const jiti = createJiti(import.meta.url)
const { ageOperator, parseRange, rangeBounds, rangeOf } = await jiti.import(`${root}shared/protocol/operators.ts`)
const { derivePseudonym } = await jiti.import(`${root}shared/utils/pseudonym.ts`)
const { findProfile } = await jiti.import(`${root}shared/profiles/index.ts`)
const { readIssuerSigned, toBase64url } = await jiti.import(`${root}shared/utils/mdoc.ts`)

const results = []
const ok = (c, m) => {
  console.log(`${c ? 'PASS' : 'FAIL'} ${m}`)
  results.push(!!c)
}
const sha = (b) => createHash('sha256').update(b).digest('hex')
const bytes = (hex) => Buffer.from(hex, 'hex')

for (const version of ['0.5', '0.6']) {
  const profile = findProfile(`nym-auth-v${version}`)
  const mdoc = profile.credential.encodings.mso_mdoc
  const age = profile.functions.age_check
  const dir = `${root}profiles/nym-auth-v${version}/test-vectors/${version === '0.5' ? 'nym_auth_mdoc' : 'nym_auth_mdoc_decoy'}/`
  console.log(`\n== v${version}: ${dir.slice(root.length)}`)

  for (const variant of ['', '_zero_psc']) {
    const V = JSON.parse(readFileSync(`${dir}${version === '0.5' ? 'nym_auth' : 'decoy'}_test_vectors${variant}.json`, 'utf8'))
    const p = `[v${version}, ${variant ? 'zero psc' : 'psc'}]`
    const h = V.holder_openings
    const required = mdoc.attributes.filter((a) => a.presence === 'required').map((a) => a.id)

    if (version === '0.6') {
      // The decoy-digest layout, read by the site's own reader: no nameSpaces, bsc and psc as the
      // MSO's valueDigests 0 and 1, which are the profile's required attributes in that order.
      const v = readIssuerSigned(toBase64url(bytes(V.issuer_signed_cbor)))
      ok(v.layout === 'decoy' && v.items.length === 0 && v.birthDate === null, `${p} readIssuerSigned: the decoy-digest layout, no items, no birth_date`)
      ok(v.docType === mdoc.doctype, `${p} docType ${v.docType} is the profile's doctype`)
      ok(JSON.stringify(required) === JSON.stringify(['bsc', 'psc']), `${p} the profile's required attributes are bsc, psc (valueDigests 0, 1)`)
      ok(Buffer.from(v.bsc).toString('hex') === V.decoy.bsc && Buffer.from(v.psc).toString('hex') === V.decoy.psc, `${p} bsc and psc from the valueDigests are the vectors'`)
      ok(v.validity.validFrom === V.decoy.valid_from && v.validity.validUntil === V.decoy.valid_until, `${p} validity ${v.validity.validFrom} to ${v.validity.validUntil}`)
      ok(sha(bytes(V.decoy.sig_structure)) === V.decoy.e && bytes(V.decoy.sig_structure).length === 423, `${p} e = SHA-256(Sig_structure), 423 bytes`)
      V.commitments = { bsc: V.decoy.bsc, psc: V.decoy.psc }
    } else {
      // The profile's mdoc encoding and the fixture's IssuerSigned.
      const issuerSigned = decode(readFileSync(`${dir}issuer_signed${variant}.cbor`))
      ok(sha(readFileSync(`${dir}issuer_signed${variant}.cbor`)) === sha(bytes(V.issuer_signed_cbor)), `${p} issuer_signed${variant}.cbor is the JSON's issuer_signed_cbor`)
      const namespaces = Object.keys(issuerSigned.nameSpaces)
      ok(namespaces.length === 1 && namespaces[0] === mdoc.doctype, `${p} namespace ${namespaces[0]} is the profile's doctype`)
      const ids = V.issuer_signed_items.map((i) => i.elementIdentifier)
      ok(JSON.stringify(ids) === JSON.stringify(required), `${p} data elements ${ids.join(', ')} are the profile's required attributes, in digestID order`)
      ok(V.issuer_signed_items.every((it, n) => it.digestID === n && sha(bytes(it.item_bytes_tag24)) === it.digest), `${p} item digests`)
    }

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
}

const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} checks passed`)
process.exit(passed === results.length ? 0 : 1)
