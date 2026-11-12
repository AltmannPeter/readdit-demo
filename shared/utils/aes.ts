// AES-128 (FIPS 197) of single 16-byte blocks, with WebCrypto: rulebook v0.7's commitments
// (`bsc`, `psc`) and its pseudonym with `prf` `aes-128`. WebCrypto has no ECB, so each block is
// AES-CBC with a zero IV, of which the first 16 bytes are the block's encryption.

import { concatBytes } from './bytes'

/** AES-128 of one 16-byte block under a 16-byte key. */
export async function aes128(key: Uint8Array, block: Uint8Array): Promise<Uint8Array> {
  if (key.length !== 16 || block.length !== 16) throw new Error('aes128: a 16-byte key and a 16-byte block')
  const k = await crypto.subtle.importKey('raw', key as BufferSource, { name: 'AES-CBC' }, false, ['encrypt'])
  const out = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, k, block as BufferSource))
  return out.slice(0, 16)
}

/** The v0.7 commitment of `key`: AES-128 of `tag ‖ 01 ‖ first` ‖ AES-128 of `tag ‖ 02 ‖ 0^10`. */
async function commit(key: Uint8Array, tag: string, first: Uint8Array): Promise<Uint8Array> {
  const t = new TextEncoder().encode(tag)
  if (t.length !== 5 || first.length !== 10) throw new Error('commitment: a 5-byte tag and 10 bytes')
  return concatBytes(await aes128(key, concatBytes(t, Uint8Array.of(1), first)), await aes128(key, concatBytes(t, Uint8Array.of(2), new Uint8Array(10))))
}

/** Rulebook v0.7's bsc = AES-128(secret_seed, "nym/b" ‖ 01 ‖ birth_date) ‖ AES-128(secret_seed, "nym/b" ‖ 02 ‖ 0^10). */
export function bscV07(secretSeed: Uint8Array, birthDate: string): Promise<Uint8Array> {
  return commit(secretSeed, 'nym/b', new TextEncoder().encode(birthDate))
}

/** Rulebook v0.7's psc = AES-128(private_seed, "nym/p" ‖ 01 ‖ 0^10) ‖ AES-128(private_seed, "nym/p" ‖ 02 ‖ 0^10). */
export function pscV07(privateSeed: Uint8Array): Promise<Uint8Array> {
  return commit(privateSeed, 'nym/p', new Uint8Array(10))
}
