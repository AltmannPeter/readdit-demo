import type { PseudonymConfig } from '../types/oid4vp'
import { concatBytes, sha256, toHex, utf8 } from './bytes'
import { aes128 } from './aes'

const ZERO32 = new Uint8Array(32)

export interface PseudonymInputs {
  config: PseudonymConfig
  /** Opening of `ssc` (secret_seed) or `psc` (private_seed), 16 bytes. */
  seed: Uint8Array
  /** e.g. "x509_san_dns:community.example" */
  verifierId?: string
  verifierContext?: string
  /** Only for user-managed-pseudonym-xsite-ssc. */
  userValue?: string
}

/** verifier_input as defined per configuration (rulebook v0.4, "Configurations", prf sha-256). */
export async function verifierInput(i: Omit<PseudonymInputs, 'seed'>): Promise<Uint8Array> {
  switch (i.config) {
    case 'known-offender-matching-ssc':
    case 'known-offender-matching-psc':
      return sha256(utf8(required(i.verifierId, 'verifierId')))
    case 'account-recovery-ssc':
      return sha256(
        concatBytes(
          await sha256(utf8(required(i.verifierId, 'verifierId'))),
          await sha256(utf8(required(i.verifierContext, 'verifierContext'))),
        ),
      )
    case 'user-managed-pseudonym-xsite-ssc':
      return ZERO32
  }
}

export async function proverInput(i: Pick<PseudonymInputs, 'config' | 'userValue'>): Promise<Uint8Array> {
  if (i.config === 'user-managed-pseudonym-xsite-ssc') return sha256(utf8(required(i.userValue, 'userValue')))
  return ZERO32
}

/** pseudonym = SHA-256(DST || seed || prover_input || verifier_input), DST = "nym_auth/v1/<config>". Hex. */
export async function derivePseudonym(i: PseudonymInputs): Promise<string> {
  const dst = utf8(`nym_auth/v1/${i.config}`)
  const out = await sha256(concatBytes(dst, i.seed, await proverInput(i), await verifierInput(i)))
  return toHex(out)
}

/** prf aes-128 (rulebook v0.7): H = SHA-256("nym_auth/v1/aes-128/" ‖ config ‖ prover_input ‖
 *  verifier_input), which the verifier computes itself. Defined for the configurations whose
 *  prover_input is public (not user-managed-pseudonym-xsite-ssc). */
export async function nymBlock(i: Omit<PseudonymInputs, 'seed'>): Promise<Uint8Array> {
  if (i.config === 'user-managed-pseudonym-xsite-ssc') throw new Error('pseudonym: prf aes-128 is not defined for user-managed-pseudonym-xsite-ssc')
  return sha256(concatBytes(utf8(`nym_auth/v1/aes-128/${i.config}`), await proverInput(i), await verifierInput(i)))
}

/** prf aes-128: pseudonym = AES-128(seed, H[0..16]) ‖ AES-128(seed, H[16..32]). Hex. */
export async function derivePseudonymAes128(i: PseudonymInputs): Promise<string> {
  const h = await nymBlock(i)
  return toHex(concatBytes(await aes128(i.seed, h.slice(0, 16)), await aes128(i.seed, h.slice(16))))
}

function required<T>(v: T | undefined, name: string): T {
  if (v == null) throw new Error(`pseudonym: missing ${name}`)
  return v
}
