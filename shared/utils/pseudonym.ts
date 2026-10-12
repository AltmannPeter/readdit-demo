import type { PseudonymConfig } from '../types/oid4vp'
import { concatBytes, sha256, toHex, utf8 } from './bytes'

const ZERO32 = new Uint8Array(32)

export interface PseudonymInputs {
  config: PseudonymConfig
  /** Opening of `ssc` (secret_seed) or `psc` (private_seed), 16 bytes. */
  seed: Uint8Array
  /** e.g. "x509_san_dns:readdit.example" */
  verifierId?: string
  verifierContext?: string
  /** Only for user-managed-pseudonym-xsite-ssc. */
  userValue?: string
}

/** verifier_input as defined per configuration (rulebook, pseudonym-v1-sha256). */
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

function required<T>(v: T | undefined, name: string): T {
  if (v == null) throw new Error(`pseudonym: missing ${name}`)
  return v
}
