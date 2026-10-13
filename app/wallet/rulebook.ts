// What the nym_auth rulebook (v0.2, "Configurations") states about each pseudonym configuration.
// The consent screen phrases these properties for the request at hand; it claims nothing else.

import type { PseudonymConfig } from '#shared/types/oid4vp'

export interface ConfigProperties {
  /** "The pseudonym value is distinct per verifier_id" (and per verifier_context for account recovery). */
  distinctPerVerifier: boolean
  /** "The same pseudonym value can be presented to different verifiers." */
  sameAcrossVerifiers: boolean
  /** "The pseudonym can be remapped to an identity by the issuer, who knows the secret_seed value." */
  issuerCanLink: boolean
  /** "It supports known offender matching." */
  knownOffenderMatching: boolean
  /** The seed the pseudonym is derived from. */
  seed: 'secret_seed' | 'private_seed'
}

export const CONFIG_PROPERTIES: Record<PseudonymConfig, ConfigProperties> = {
  'known-offender-matching-ssc': { distinctPerVerifier: true, sameAcrossVerifiers: false, issuerCanLink: true, knownOffenderMatching: true, seed: 'secret_seed' },
  // "Remapping the pseudonym to an identity is as hard as brute forcing the private_seed, which is intractable."
  'known-offender-matching-psc': { distinctPerVerifier: true, sameAcrossVerifiers: false, issuerCanLink: false, knownOffenderMatching: true, seed: 'private_seed' },
  'account-recovery-ssc': { distinctPerVerifier: true, sameAcrossVerifiers: false, issuerCanLink: true, knownOffenderMatching: true, seed: 'secret_seed' },
  // "Does not offer sybil resistance. Does not support known offender matching."
  'user-managed-pseudonym-xsite-ssc': { distinctPerVerifier: false, sameAcrossVerifiers: true, issuerCanLink: false, knownOffenderMatching: false, seed: 'secret_seed' },
}
