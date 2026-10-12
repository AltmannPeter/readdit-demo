// Credential data as the prover service reports it (GET /api/wallet/credential).
// The wallet screens only read it; secrets (seed, device key) stay in the service.

export interface CredentialView {
  docType: string
  namespace: string
  title: string
  encoding: string
  compactProfile: boolean
  issuer: { name: string; country?: string; documentSigner: string }
  validity: { signed: string; validFrom: string; validUntil: string }
  attributes: { birth_date: string; ssc: string; psc: string | null }
  mso: { digestAlgorithm: string; signatureAlgorithm: string }
  deviceKey: { kty: string; crv: string; jwkThumbprint: string; protection?: string }
}

export interface DisplayCredential {
  title: string
  issuer: string
  subtitle: string
}

/** Static card shown next to nym_auth so the wallet looks lived-in. Not used in any flow. */
export const pidCard: DisplayCredential = { title: 'Personal ID', issuer: 'Demo Issuer', subtitle: 'Identity' }

export function nymCard(c: CredentialView | null): DisplayCredential {
  return { title: c?.title ?? 'Age and pseudonym', issuer: c?.issuer.name ?? '', subtitle: 'Pseudonyms and age checks' }
}
