// Response Mode direct_post.cwt (zkp_req.md §6.2, sirosfoundation/nym_auth_rulebook PR #12): the
// Authorization Response as CBOR (§6.1, each ZkpPresentation the CBOR map itself), encrypted in a
// COSE_Encrypt (RFC 9052 §5.1, tag 96, no signature) and posted to response_uri as the HTTP body,
// Content-Type application/cwt.
//
//   96([ h'a10101' ({1: 1}: A128GCM), {5: iv}, ciphertext ‖ tag,
//        [[ h'a1013818' ({1: -25}: ECDH-ES + HKDF-256), {-1: ephemeral COSE_Key, 4: kid}, h'' ]] ])
//
// Key agreement: ECDH-ES + HKDF-256 (RFC 9053 §6.3.1), direct: the HKDF output is the content
// key. COSE_KDF_Context (RFC 9053 §5.2): AlgorithmID = the content algorithm, PartyU and PartyV
// with nil identities, SuppPubInfo [key bits, the recipient's protected header]. No HKDF salt.
// The content's AAD is the Enc_structure ["Encrypt", protected, h''] (empty external AAD).
//
// WebCrypto only (ECDH, HKDF, AES-GCM), so the same code runs in the server and in the browser's
// demo wallet. The CBOR around the presentations is written and read here byte for byte: a
// presentation is spliced in and sliced out as the prover encoded it, never decoded and
// re-encoded.
import type { AuthorizationResponse, EncryptionJwk } from '../types/oid4vp'

export const CWT_RESPONSE_MODE = 'direct_post.cwt'
export const CWT_CONTENT_TYPE = 'application/cwt'
/** COSE algorithms (RFC 9053): content A128GCM, A192GCM, A256GCM; recipient ECDH-ES + HKDF-256. */
export const COSE_A128GCM = 1
export const COSE_A192GCM = 2
export const COSE_A256GCM = 3
export const COSE_ECDH_ES_HKDF_256 = -25
const KEY_BITS: Record<number, number> = { [COSE_A128GCM]: 128, [COSE_A192GCM]: 192, [COSE_A256GCM]: 256 }
/** COSE_Encrypt's tag (RFC 9052 §2). */
export const COSE_ENCRYPT_TAG = 96

// ---- bytes ----

const enc = new TextEncoder()
const dec = new TextDecoder('utf-8', { fatal: true })

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const p of parts) {
    out.set(p, at)
    at += p.length
  }
  return out
}

function b64urlToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)
  const bin = atob(b64)
  return Uint8Array.from(bin, (c) => c.charCodeAt(0))
}

function bytesToB64url(b: Uint8Array): string {
  let bin = ''
  for (let i = 0; i < b.length; i += 0x8000) bin += String.fromCharCode(...b.subarray(i, i + 0x8000))
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// ---- a minimal CBOR writer and reader (RFC 8949), for what this mode carries ----

function head(major: number, n: number): Uint8Array {
  const m = major << 5
  if (n < 24) return Uint8Array.of(m | n)
  if (n < 0x100) return Uint8Array.of(m | 24, n)
  if (n < 0x10000) return Uint8Array.of(m | 25, n >> 8, n & 0xff)
  if (n < 0x100000000) return Uint8Array.of(m | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff)
  throw new Error('CBOR: length too large')
}
const int = (v: number) => (v >= 0 ? head(0, v) : head(1, -1 - v))
const bstr = (b: Uint8Array) => concat([head(2, b.length), b])
const tstr = (s: string) => {
  const b = enc.encode(s)
  return concat([head(3, b.length), b])
}
const arr = (items: Uint8Array[]) => concat([head(4, items.length), ...items])
const map = (entries: Array<[Uint8Array, Uint8Array]>) => concat([head(5, entries.length), ...entries.flat()])
const NIL = Uint8Array.of(0xf6)

interface Head {
  major: number
  /** The argument: a length, a value, or a tag number. Undefined for indefinite lengths. */
  n?: number
  /** Simple values and floats (major 7): the additional information. */
  info: number
  /** Where the item's content starts. */
  at: number
}

function readHead(b: Uint8Array, at: number): Head {
  if (at >= b.length) throw new Error('CBOR: truncated')
  const ib = b[at]!
  const major = ib >> 5
  const info = ib & 0x1f
  const need = (k: number) => {
    if (at + 1 + k > b.length) throw new Error('CBOR: truncated')
  }
  if (info < 24) return { major, n: info, info, at: at + 1 }
  if (info === 24) {
    need(1)
    return { major, n: b[at + 1], info, at: at + 2 }
  }
  if (info === 25) {
    need(2)
    return { major, n: (b[at + 1]! << 8) | b[at + 2]!, info, at: at + 3 }
  }
  if (info === 26) {
    need(4)
    return { major, n: ((b[at + 1]! << 24) >>> 0) + (b[at + 2]! << 16) + (b[at + 3]! << 8) + b[at + 4]!, info, at: at + 5 }
  }
  if (info === 27) {
    need(8)
    const hi = ((b[at + 1]! << 24) >>> 0) + (b[at + 2]! << 16) + (b[at + 3]! << 8) + b[at + 4]!
    const lo = ((b[at + 5]! << 24) >>> 0) + (b[at + 6]! << 16) + (b[at + 7]! << 8) + b[at + 8]!
    const n = hi * 2 ** 32 + lo
    if (!Number.isSafeInteger(n)) throw new Error('CBOR: integer too large')
    return { major, n, info, at: at + 9 }
  }
  if (info === 31 && major >= 2 && major <= 5) return { major, info, at: at + 1 }
  if (info === 31 && major === 7) throw new Error('CBOR: unexpected break')
  throw new Error('CBOR: reserved additional information')
}

/** The offset just past the item that starts at `at` (any item, definite or indefinite length). */
function skip(b: Uint8Array, at: number, depth = 0): number {
  if (depth > 64) throw new Error('CBOR: nested too deep')
  const h = readHead(b, at)
  const untilBreak = (step: (p: number) => number) => {
    let p = h.at
    for (;;) {
      if (p >= b.length) throw new Error('CBOR: truncated')
      if (b[p] === 0xff) return p + 1
      p = step(p)
    }
  }
  switch (h.major) {
    case 0:
    case 1:
      return h.at
    case 2:
    case 3:
      if (h.n === undefined) return untilBreak((p) => skip(b, p, depth + 1))
      if (h.at + h.n > b.length) throw new Error('CBOR: truncated')
      return h.at + h.n
    case 4: {
      if (h.n === undefined) return untilBreak((p) => skip(b, p, depth + 1))
      let p = h.at
      for (let i = 0; i < h.n; i++) p = skip(b, p, depth + 1)
      return p
    }
    case 5: {
      if (h.n === undefined) return untilBreak((p) => skip(b, skip(b, p, depth + 1), depth + 1))
      let p = h.at
      for (let i = 0; i < h.n; i++) p = skip(b, skip(b, p, depth + 1), depth + 1)
      return p
    }
    case 6:
      return skip(b, h.at, depth + 1)
    default:
      return h.at
  }
}

/** A definite-length text string at `at`, and where it ends; null when the item is not one. */
function readText(b: Uint8Array, at: number): { value: string; end: number } | null {
  const h = readHead(b, at)
  if (h.major !== 3 || h.n === undefined) return null
  if (h.at + h.n > b.length) throw new Error('CBOR: truncated')
  return { value: dec.decode(b.subarray(h.at, h.at + h.n)), end: h.at + h.n }
}

/** A definite-length byte string at `at`. */
function readBytes(b: Uint8Array, at: number): { value: Uint8Array; end: number } {
  const h = readHead(b, at)
  if (h.major !== 2 || h.n === undefined) throw new Error('CBOR: expected a byte string')
  if (h.at + h.n > b.length) throw new Error('CBOR: truncated')
  return { value: b.subarray(h.at, h.at + h.n), end: h.at + h.n }
}

/** A definite-length map with integer keys whose values are read by `value`. */
function readIntMap<T>(b: Uint8Array, at: number, value: (key: number, at: number) => { value: T; end: number }): { value: Map<number, T>; end: number } {
  const h = readHead(b, at)
  if (h.major !== 5 || h.n === undefined) throw new Error('COSE: expected a header map')
  const out = new Map<number, T>()
  let p = h.at
  for (let i = 0; i < h.n; i++) {
    const k = readHead(b, p)
    if ((k.major !== 0 && k.major !== 1) || k.n === undefined) throw new Error('COSE: header labels must be integers')
    const key = k.major === 0 ? k.n : -1 - k.n
    if (out.has(key)) throw new Error('COSE: duplicate header label')
    const v = value(key, k.at)
    out.set(key, v.value)
    p = v.end
  }
  return { value: out, end: p }
}

/** An integer item at `at`. */
function readInt(b: Uint8Array, at: number): { value: number; end: number } {
  const h = readHead(b, at)
  if ((h.major !== 0 && h.major !== 1) || h.n === undefined) throw new Error('CBOR: expected an integer')
  return { value: h.major === 0 ? h.n : -1 - h.n, end: h.at }
}

/** Any item at `at`, kept as its bytes. */
const raw = (b: Uint8Array, at: number) => {
  const end = skip(b, at)
  return { value: b.subarray(at, end), end }
}

// ---- the Authorization Response (zkp_req.md §6.1) ----

/** A presentation for the CBOR response: the ZkpPresentation map itself when the base64url string
 *  holds exactly one CBOR map, else the string as tstr (`Presentation = ZkpPresentation / tstr`). */
function presentationItem(p: string): Uint8Array {
  try {
    const bytes = b64urlToBytes(p)
    if (bytes.length && bytes[0]! >> 5 === 5 && skip(bytes, 0) === bytes.length) return bytes
  } catch {
    /* not base64url CBOR: sent as text */
  }
  return tstr(p)
}

/**
 * The Authorization Response as CBOR (§6.1): `{"vp_token": {query: [presentation…]}, "state": …}`
 * or `{"error": …, "state": …}`. Presentations come as the provers return them (base64url of the
 * ZkpPresentation's CBOR) and are spliced in as their CBOR bytes.
 */
export function encodeAuthorizationResponse(body: AuthorizationResponse | { state: string; vp_token: unknown } | { state: string; error: string }): Uint8Array {
  const entries: Array<[Uint8Array, Uint8Array]> = []
  if ('error' in body) {
    entries.push([tstr('error'), tstr(String(body.error))])
  } else {
    const token = body.vp_token
    const item =
      token && typeof token === 'object' && !Array.isArray(token)
        ? map(
            Object.entries(token as Record<string, unknown>).map(([q, list]) => [
              tstr(q),
              Array.isArray(list) ? arr(list.map((p) => (typeof p === 'string' ? presentationItem(p) : NIL))) : NIL,
            ]),
          )
        : typeof token === 'string'
          ? tstr(token)
          : NIL
    entries.push([tstr('vp_token'), item])
  }
  if (typeof body.state === 'string') entries.push([tstr('state'), tstr(body.state)])
  return map(entries)
}

/** A decoded CBOR Authorization Response, in the shape the JSON modes give: each presentation as
 *  base64url of its CBOR bytes (exactly as sent), or the text a tstr presentation held. Values
 *  that are not of the expected type are kept as `null` so the caller refuses them with its own
 *  rules (`vp_token`). */
export interface DecodedResponse {
  state?: string
  error?: string
  vp_token?: Record<string, Array<string | null>> | null
  /** Map keys other than vp_token, state and error, ignored as OpenID4VP says. */
  ignored: string[]
}

export function decodeAuthorizationResponse(b: Uint8Array): DecodedResponse {
  const h = readHead(b, 0)
  if (h.major !== 5 || h.n === undefined) throw new Error('the Authorization Response is not a CBOR map')
  const out: DecodedResponse = { ignored: [] }
  let p = h.at
  for (let i = 0; i < h.n; i++) {
    const k = readText(b, p)
    if (!k) throw new Error('the Authorization Response has a key that is not text')
    p = k.end
    if (k.value === 'state' || k.value === 'error') {
      const v = readText(b, p)
      if (v) out[k.value] = v.value
      p = skip(b, p)
    } else if (k.value === 'vp_token') {
      const t = readHead(b, p)
      if (t.major === 5 && t.n !== undefined) {
        const token: Record<string, Array<string | null>> = {}
        let q = t.at
        for (let j = 0; j < t.n; j++) {
          const id = readText(b, q)
          if (!id) throw new Error('vp_token has a key that is not text')
          q = id.end
          const l = readHead(b, q)
          const list: Array<string | null> = []
          if (l.major === 4 && l.n !== undefined) {
            let r = l.at
            for (let m = 0; m < l.n; m++) {
              const e = readHead(b, r)
              const end = skip(b, r)
              if (e.major === 5) list.push(bytesToB64url(b.subarray(r, end)))
              else if (e.major === 3) list.push(readText(b, r)?.value ?? null)
              else list.push(null)
              r = end
            }
            q = r
          } else {
            q = skip(b, q)
          }
          token[id.value] = list
        }
        out.vp_token = token
        p = q
      } else {
        out.vp_token = null
        p = skip(b, p)
      }
    } else {
      out.ignored.push(k.value)
      p = skip(b, p)
    }
  }
  if (p !== b.length) throw new Error('trailing bytes after the Authorization Response')
  return out
}

// ---- COSE_Encrypt with ECDH-ES + HKDF-256 ----

const subtle = () => globalThis.crypto.subtle

/** The recipient's protected header, {1: -25}, as encoded bytes: in the message and in the KDF context. */
const RECIPIENT_PROTECTED = map([[int(1), int(COSE_ECDH_ES_HKDF_256)]])

/** COSE_KDF_Context (RFC 9053 §5.2) for direct key agreement to content algorithm `contentAlg`. */
export function kdfContext(contentAlg: number, recipientProtected: Uint8Array = RECIPIENT_PROTECTED): Uint8Array {
  const party = arr([NIL, NIL, NIL])
  return arr([int(contentAlg), party, party, arr([int(KEY_BITS[contentAlg]!), bstr(recipientProtected)])])
}

/** The Enc_structure (RFC 9052 §5.3) the content is authenticated with: empty external AAD. */
const encStructure = (protectedBytes: Uint8Array) => arr([tstr('Encrypt'), bstr(protectedBytes), bstr(new Uint8Array(0))])

async function contentKey(shared: ArrayBuffer, contentAlg: number, recipientProtected: Uint8Array): Promise<CryptoKey> {
  const ikm = await subtle().importKey('raw', shared, 'HKDF', false, ['deriveKey'])
  return subtle().deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: kdfContext(contentAlg, recipientProtected) as BufferSource },
    ikm,
    { name: 'AES-GCM', length: KEY_BITS[contentAlg]! },
    false,
    ['encrypt', 'decrypt'],
  )
}

/** What the technical views show of an encrypted response. */
export interface CwtHeader {
  alg: 'ECDH-ES+HKDF-256'
  enc: 'A128GCM' | 'A192GCM' | 'A256GCM'
  kid?: string
}
const ENC_NAMES: Record<number, CwtHeader['enc']> = { [COSE_A128GCM]: 'A128GCM', [COSE_A192GCM]: 'A192GCM', [COSE_A256GCM]: 'A256GCM' }
/** The COSE content algorithm for an OpenID4VP `enc` value. */
export function coseEncOf(name: string): number | undefined {
  const hit = Object.entries(ENC_NAMES).find(([, n]) => n === name)
  return hit ? Number(hit[0]) : undefined
}

/**
 * Encrypts `plaintext` to the verifier's P-256 key `jwk` (its `kid`, if any, goes under label 4):
 * the COSE_Encrypt of §6.2, tag 96, with a fresh ephemeral key and IV.
 */
export async function encryptCwt(plaintext: Uint8Array, jwk: EncryptionJwk, contentAlg = COSE_A128GCM): Promise<{ bytes: Uint8Array; header: CwtHeader }> {
  if (!KEY_BITS[contentAlg]) throw new Error(`unsupported content algorithm ${contentAlg}`)
  const recipient = await subtle().importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true }, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
  const eph = (await subtle().generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])) as CryptoKeyPair
  const shared = await subtle().deriveBits({ name: 'ECDH', public: recipient }, eph.privateKey, 256)
  const point = new Uint8Array(await subtle().exportKey('raw', eph.publicKey))
  const coseKey = map([
    [int(1), int(2)],
    [int(-1), int(1)],
    [int(-2), bstr(point.subarray(1, 33))],
    [int(-3), bstr(point.subarray(33, 65))],
  ])
  const recipientHeader: Array<[Uint8Array, Uint8Array]> = [[int(-1), coseKey]]
  if (jwk.kid) recipientHeader.push([int(4), bstr(enc.encode(jwk.kid))])
  const protectedBytes = map([[int(1), int(contentAlg)]])
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12))
  const key = await contentKey(shared, contentAlg, RECIPIENT_PROTECTED)
  const ciphertext = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: encStructure(protectedBytes) as BufferSource, tagLength: 128 }, key, plaintext as BufferSource))
  const message = arr([bstr(protectedBytes), map([[int(5), bstr(iv)]]), bstr(ciphertext), arr([arr([bstr(RECIPIENT_PROTECTED), map(recipientHeader), bstr(new Uint8Array(0))])])])
  return { bytes: concat([head(6, COSE_ENCRYPT_TAG), message]), header: { alg: 'ECDH-ES+HKDF-256', enc: ENC_NAMES[contentAlg]!, ...(jwk.kid && { kid: jwk.kid }) } }
}

/**
 * Decrypts a §6.2 COSE_Encrypt with the verifier's private ECDH P-256 key. Refuses anything else:
 * another tag, a content algorithm other than A128/192/256GCM, more or fewer than one recipient, a
 * recipient algorithm other than ECDH-ES + HKDF-256, a `kid` other than `expectKid` (when the
 * message names one), a point not on P-256, a failed tag check, trailing bytes.
 */
export async function decryptCwt(bytes: Uint8Array, privateKey: CryptoKey, expectKid?: string): Promise<{ plaintext: Uint8Array; header: CwtHeader }> {
  let p = 0
  const tag = readHead(bytes, 0)
  if (tag.major !== 6 || tag.n !== COSE_ENCRYPT_TAG) throw new Error('not a COSE_Encrypt (tag 96)')
  p = tag.at
  const top = readHead(bytes, p)
  if (top.major !== 4 || top.n !== 4) throw new Error('COSE_Encrypt is not an array of 4')
  p = top.at
  const prot = readBytes(bytes, p)
  p = prot.end
  const protectedHeader = prot.value.length ? readIntMap(prot.value, 0, (_k, at) => raw(prot.value, at)).value : new Map<number, Uint8Array>()
  const algItem = protectedHeader.get(1)
  const contentAlg = algItem ? readInt(algItem, 0).value : undefined
  if (contentAlg === undefined || !KEY_BITS[contentAlg]) throw new Error(`content algorithm ${String(contentAlg)} is not A128GCM, A192GCM or A256GCM`)
  const unprot = readIntMap(bytes, p, (_k, at) => raw(bytes, at))
  p = unprot.end
  const ivItem = unprot.value.get(5)
  const iv = ivItem ? readBytes(ivItem, 0).value : undefined
  if (!iv || iv.length !== 12) throw new Error('no 12-byte IV (label 5)')
  const ct = readBytes(bytes, p)
  p = ct.end
  const recipients = readHead(bytes, p)
  if (recipients.major !== 4 || recipients.n !== 1) throw new Error('not exactly one recipient')
  p = recipients.at
  const rec = readHead(bytes, p)
  if (rec.major !== 4 || rec.n !== 3) throw new Error('the recipient is not an array of 3')
  p = rec.at
  const rprot = readBytes(bytes, p)
  p = rprot.end
  const rAlgItem = rprot.value.length ? readIntMap(rprot.value, 0, (_k, at) => raw(rprot.value, at)).value.get(1) : undefined
  if (!rAlgItem || readInt(rAlgItem, 0).value !== COSE_ECDH_ES_HKDF_256) throw new Error('the recipient algorithm is not ECDH-ES + HKDF-256 (-25)')
  const runprot = readIntMap(bytes, p, (_k, at) => raw(bytes, at))
  p = runprot.end
  const rct = readBytes(bytes, p)
  p = rct.end
  if (rct.value.length) throw new Error('the recipient carries a ciphertext; direct key agreement has none')
  if (p !== bytes.length) throw new Error('trailing bytes after the COSE_Encrypt')
  const kidItem = runprot.value.get(4)
  const kid = kidItem ? dec.decode(readBytes(kidItem, 0).value) : undefined
  if (kid !== undefined && expectKid !== undefined && kid !== expectKid) throw new Error('kid is not the session key')
  const epkItem = runprot.value.get(-1)
  if (!epkItem) throw new Error('no ephemeral key (label -1)')
  const epk = readIntMap<Uint8Array | number>(epkItem, 0, (k, at) => (k === -2 || k === -3 ? readBytes(epkItem, at) : readInt(epkItem, at))).value
  if (epk.get(1) !== 2 || epk.get(-1) !== 1) throw new Error('the ephemeral key is not EC2 P-256')
  const x = epk.get(-2) as Uint8Array | undefined
  const y = epk.get(-3) as Uint8Array | undefined
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) throw new Error('the ephemeral key has no 32-byte x and y')
  // importKey refuses a point that is not on the curve.
  const ephemeral = await subtle().importKey('raw', concat([Uint8Array.of(4), x, y]) as BufferSource, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
  const shared = await subtle().deriveBits({ name: 'ECDH', public: ephemeral }, privateKey, 256)
  const key = await contentKey(shared, contentAlg, rprot.value)
  const plaintext = new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv: iv as BufferSource, additionalData: encStructure(prot.value) as BufferSource, tagLength: 128 }, key, ct.value as BufferSource))
  return { plaintext, header: { alg: 'ECDH-ES+HKDF-256', enc: ENC_NAMES[contentAlg]!, ...(kid !== undefined && { kid }) } }
}
