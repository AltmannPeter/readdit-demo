// direct_post.cwt (zkp_req.md §6.2) without a server: shared/utils/cwt.ts against messages an
// independent COSE library made (scripts/fixtures/cwt-pycose.json, pycose), a round trip in each
// content algorithm, the presentation spliced in as its CBOR bytes and back byte for byte, the
// refusals, and the size against direct_post.jwt. Exits 1 on a failed check.
//
//   npm run cwt:check
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createJiti } from 'jiti'
import { CompactEncrypt, importJWK } from 'jose'
import { encode as cborEncode } from 'cbor-x'

const root = fileURLToPath(new URL('../', import.meta.url))
const jiti = createJiti(import.meta.url)
const cwt = await jiti.import(`${root}shared/utils/cwt.ts`)
const { encryptCwt, decryptCwt, encodeAuthorizationResponse, decodeAuthorizationResponse, kdfContext, COSE_A128GCM, COSE_A192GCM, COSE_A256GCM } = cwt
const fixture = JSON.parse(readFileSync(join(root, 'scripts/fixtures/cwt-pycose.json'), 'utf8'))

let failed = 0
function check(what, ok, detail) {
  if (!ok) failed++
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${what}${detail != null && detail !== '' ? `  (${detail})` : ''}`)
}
const eq = (what, a, b) => check(what, a === b, a === b ? '' : `got ${a}, expected ${b}`)
const hex = (b) => Buffer.from(b).toString('hex')
const fromHex = (h) => new Uint8Array(Buffer.from(h, 'hex'))
const b64url = (b) => Buffer.from(b).toString('base64url')
async function refused(what, f) {
  try {
    await f()
    check(`refused: ${what}`, false, 'accepted')
  } catch (e) {
    check(`refused: ${what}`, true, e.message)
  }
}
const { subtle } = globalThis.crypto
const importPrivate = (jwk) => subtle.importKey('jwk', { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d }, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])
/** A session key as server/utils/store.ts makes it: the public JWK in the request, the private key kept. */
async function sessionKey(kid = 'k1') {
  const pair = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
  const { kty, crv, x, y } = await subtle.exportKey('jwk', pair.publicKey)
  return { privateKey: pair.privateKey, jwk: { kty, crv, x, y, kid, use: 'enc', alg: 'ECDH-ES' } }
}

console.log('== the COSE_KDF_Context')
eq('A128GCM', hex(kdfContext(COSE_A128GCM)), '840183f6f6f683f6f6f682188044a1013818')
eq('A256GCM', hex(kdfContext(COSE_A256GCM)), '840383f6f6f683f6f6f68219010044a1013818')

console.log('\n== messages pycose made')
const fixtureKey = await importPrivate(fixture.private_jwk)
for (const m of fixture.messages) {
  const { plaintext, header } = await decryptCwt(fromHex(m.cwt), fixtureKey)
  eq(`${m.enc}: the plaintext`, hex(plaintext), m.plaintext)
  eq(`${m.enc}: the header`, `${header.alg} ${header.enc}`, `ECDH-ES+HKDF-256 ${m.enc}`)
  const d = decodeAuthorizationResponse(plaintext)
  check(`${m.enc}: an Authorization Response with a vp_token`, d.vp_token && typeof d.vp_token === 'object', JSON.stringify(Object.keys(d.vp_token ?? {})))
}

console.log('\n== round trip')
const presentation = cborEncode({ system_id: 'urn:circuits:sha256:00', pseudonym: new Uint8Array(32).fill(7), proof: new Uint8Array(4096).map((_, i) => i & 0xff) })
const pres64 = b64url(presentation)
const body = { state: 's-123', vp_token: { nym_attestation: [pres64] } }
for (const [name, alg] of [['A128GCM', COSE_A128GCM], ['A192GCM', COSE_A192GCM], ['A256GCM', COSE_A256GCM]]) {
  const k = await sessionKey()
  const { bytes, header } = await encryptCwt(encodeAuthorizationResponse(body), k.jwk, alg)
  const out = await decryptCwt(bytes, k.privateKey, 'k1')
  const d = decodeAuthorizationResponse(out.plaintext)
  eq(`${name}: state`, d.state, 's-123')
  eq(`${name}: the presentation back byte for byte`, d.vp_token?.nym_attestation?.[0], pres64)
  eq(`${name}: header`, `${header.alg} ${header.enc} ${header.kid}`, `ECDH-ES+HKDF-256 ${name} k1`)
  eq(`${name}: tag 96, an array of 4`, hex(bytes.subarray(0, 3)), 'd86084')
}
{
  const plain = encodeAuthorizationResponse(body)
  const at = Buffer.from(plain).indexOf(Buffer.from(presentation))
  check('the presentation is spliced in as its CBOR bytes, not as text', at > 0, `at byte ${at}`)
  const text = decodeAuthorizationResponse(encodeAuthorizationResponse({ state: 's', vp_token: { q: ['not-cbor'] } }))
  eq('a presentation that is not base64url of one CBOR map stays text', text.vp_token?.q?.[0], 'not-cbor')
  const extra = b64url(Buffer.concat([presentation, Buffer.from([0x01])]))
  eq('one with trailing bytes stays text', decodeAuthorizationResponse(encodeAuthorizationResponse({ state: 's', vp_token: { q: [extra] } })).vp_token?.q?.[0], extra)
  const err = decodeAuthorizationResponse(encodeAuthorizationResponse({ state: 's', error: 'access_denied' }))
  eq('an error response', `${err.error} ${err.state} ${err.vp_token}`, 'access_denied s undefined')
}

console.log('\n== refusals')
{
  const k = await sessionKey()
  const good = (await encryptCwt(encodeAuthorizationResponse(body), k.jwk)).bytes
  const changed = (f) => {
    const b = Uint8Array.from(good)
    f(b)
    return b
  }
  await refused('another tag', () => decryptCwt(changed((b) => (b[1] = 0x61)), k.privateKey))
  await refused('a flipped ciphertext byte', () => decryptCwt(changed((b) => (b[b.length >> 1] ^= 1)), k.privateKey))
  await refused('a trailing byte', () => decryptCwt(Uint8Array.from([...good, 0]), k.privateKey))
  await refused('truncated', () => decryptCwt(good.subarray(0, good.length - 1), k.privateKey))
  await refused('another kid', () => decryptCwt(good, k.privateKey, 'k2'))
  await refused("another session's key", async () => decryptCwt(good, (await sessionKey()).privateKey))
  // Bytes 3-6 are the body's protected header, 43 a1 01 01; byte 6 is the content algorithm.
  await refused('content algorithm 4', () => decryptCwt(changed((b) => (b[6] = 0x04)), k.privateKey))
  await refused('content algorithm A256GCM in place of A128GCM (the key length and the AAD change)', () => decryptCwt(changed((b) => (b[6] = 0x03)), k.privateKey))
  await refused('not CBOR', () => decryptCwt(new TextEncoder().encode('eyJhbGciOiJFQ0RILUVTIn0..'), k.privateKey))
  await refused('a map that is not an Authorization Response', async () => decodeAuthorizationResponse(Uint8Array.of(0x81, 0x01)))
}

console.log('\n== size against direct_post.jwt (a 323 KB proof, as Longfellow v0.5)')
{
  const big = b64url(cborEncode({ system_id: 'urn:circuits:sha256:00', pseudonym: new Uint8Array(32), proof: new Uint8Array(323_000).map((_, i) => (i * 31) & 0xff) }))
  const k = await sessionKey()
  const body = { state: 's-123', vp_token: { nym_attestation: [big] } }
  const c = (await encryptCwt(encodeAuthorizationResponse(body), k.jwk)).bytes.length
  const jwe = await new CompactEncrypt(Buffer.from(JSON.stringify(body))).setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128GCM', kid: 'k1' }).encrypt(await importJWK(k.jwk, 'ECDH-ES'))
  const form = new URLSearchParams({ response: jwe }).toString().length
  const raw = Buffer.from(big, 'base64url').length
  console.log(`  presentation ${raw} B; COSE_Encrypt ${c} B (+${c - raw}); JWE ${jwe.length} B, form-encoded ${form} B (${(form / raw).toFixed(2)}×)`)
  check('the COSE_Encrypt adds under 300 bytes to the presentation', c - raw < 300)
  check('the COSE_Encrypt is under 60 % of the JWE', c < 0.6 * jwe.length)
}

console.log(failed ? `\n${failed} failed` : '\nall passed')
process.exit(failed ? 1 : 0)
