import { readFile } from 'node:fs/promises'
import { CompactSign, importPKCS8 } from 'jose'

// Signs Request Objects (JWS, ES256, x5c). The leaf certificate's dNSName SAN must equal
// the client_id host (x509_san_dns). Without configured PEM files a self-signed P-256
// certificate is generated at start; fine for the mocked wallet, not for a real one.

const ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const

interface Signer {
  key: CryptoKey
  x5c: string[]
  subject: string
  selfSigned: boolean
}

const g = globalThis as unknown as { __readditSigner?: Promise<Signer> }

async function load(): Promise<Signer> {
  // @peculiar/x509 needs the Reflect metadata polyfill loaded first.
  await import('reflect-metadata')
  const x509 = await import('@peculiar/x509')
  const cfg = useRuntimeConfig()
  const host = String(cfg.public.siteHost)
  if (cfg.requestSigningKey && cfg.requestSigningCert) {
    const key = (await importPKCS8(await readFile(String(cfg.requestSigningKey), 'utf8'), 'ES256')) as CryptoKey
    const pem = await readFile(String(cfg.requestSigningCert), 'utf8')
    const certs = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) ?? []
    const parsed = certs.map((c) => new x509.X509Certificate(c))
    return {
      key,
      x5c: parsed.map((c) => Buffer.from(c.rawData).toString('base64')),
      subject: parsed[0]?.subject ?? '',
      selfSigned: false,
    }
  }
  const keys = await crypto.subtle.generateKey(ALG, true, ['sign', 'verify'])
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: Date.now().toString(16),
    name: `CN=${host}, O=${cfg.public.siteName}`,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 365 * 86_400_000),
    signingAlgorithm: ALG,
    keys,
    extensions: [new x509.SubjectAlternativeNameExtension([{ type: 'dns', value: host }])],
  })
  return { key: keys.privateKey, x5c: [Buffer.from(cert.rawData).toString('base64')], subject: cert.subject, selfSigned: true }
}

export function requestSigner(): Promise<Signer> {
  g.__readditSigner ??= load()
  return g.__readditSigner
}

export async function signRequestObject(payload: object): Promise<string> {
  const s = await requestSigner()
  return new CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: 'ES256', typ: 'oauth-authz-req+jwt', x5c: s.x5c })
    .sign(s.key)
}
