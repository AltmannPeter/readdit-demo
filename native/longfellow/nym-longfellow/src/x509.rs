//! The Document Signer certificate of `issuer_key_set` (rulebook, "Presentation encoding": DER
//! certificates, each validated against the verifier's trust anchors).
//!
//! The demo's trust anchor is the demo issuer's self-signed Document Signer. A certificate is
//! valid when it is byte-for-byte a trust anchor, its self-signature verifies under its key
//! (ECDSA with SHA-256), and the verifier's time lies in its validity period. The same rules as
//! `native/vega` (nym-vega `x509`).

use der::{Decode, Encode};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{DerSignature, VerifyingKey};
use x509_cert::Certificate;

/// A P-256 public key: x and y, big-endian.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
  pub x: [u8; 32],
  pub y: [u8; 32],
}

/// id-ecPublicKey and prime256v1 (RFC 5480), ecdsa-with-SHA256 (RFC 5758).
const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const PRIME256V1: &str = "1.2.840.10045.3.1.7";
const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";

/// A parsed Document Signer certificate.
#[derive(Clone, Debug)]
pub struct DocumentSigner {
  pub der: Vec<u8>,
  pub subject: String,
  pub issuer: String,
  /// The P-256 key, the signature circuit's issuer key Q.
  pub key: PublicKey,
  pub not_before: i64,
  pub not_after: i64,
  /// The certificate's own signature verifies under its key.
  pub self_signed: bool,
}

/// Parses a DER certificate whose key is a P-256 key.
pub fn parse(der: &[u8]) -> Result<DocumentSigner, String> {
  let cert = Certificate::from_der(der).map_err(|e| format!("not a DER certificate: {e}"))?;
  let tbs = &cert.tbs_certificate;
  let spki = &tbs.subject_public_key_info;
  if spki.algorithm.oid.to_string() != EC_PUBLIC_KEY {
    return Err("the certificate's key is not an EC key".into());
  }
  let curve = spki.algorithm.parameters.as_ref().and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok());
  if curve.map(|c| c.to_string()) != Some(PRIME256V1.to_string()) {
    return Err("the certificate's key is not on P-256".into());
  }
  let point = spki.subject_public_key.as_bytes().ok_or("the key's bit string has unused bits")?;
  if point.len() != 65 || point[0] != 0x04 {
    return Err("the key is not an uncompressed P-256 point".into());
  }
  let verifying = VerifyingKey::from_sec1_bytes(point).map_err(|e| format!("the key is not a P-256 point: {e}"))?;
  let key = PublicKey { x: point[1..33].try_into().map_err(|_| "x")?, y: point[33..].try_into().map_err(|_| "y")? };

  let self_signed = cert.signature_algorithm.oid.to_string() == ECDSA_SHA256 && tbs.issuer == tbs.subject && {
    let tbs_der = tbs.to_der().map_err(|e| e.to_string())?;
    let sig = cert.signature.as_bytes().ok_or("the signature's bit string has unused bits")?;
    DerSignature::try_from(sig).is_ok_and(|s| verifying.verify(&tbs_der, &s).is_ok())
  };
  let unix = |t: &x509_cert::time::Time| i64::try_from(t.to_unix_duration().as_secs()).map_err(|e| e.to_string());
  Ok(DocumentSigner {
    der: der.to_vec(),
    subject: tbs.subject.to_string(),
    issuer: tbs.issuer.to_string(),
    key,
    not_before: unix(&tbs.validity.not_before)?,
    not_after: unix(&tbs.validity.not_after)?,
    self_signed,
  })
}

/// PEM certificates (`-----BEGIN CERTIFICATE-----`) in a file's text, as DER.
pub fn pem_certificates(text: &str) -> Result<Vec<Vec<u8>>, String> {
  const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
  const END: &str = "-----END CERTIFICATE-----";
  let mut out = Vec::new();
  let mut rest = text;
  while let Some(start) = rest.find(BEGIN) {
    let after = &rest[start + BEGIN.len()..];
    let end = after.find(END).ok_or("a PEM certificate without its END line")?;
    let body: String = after[..end].chars().filter(|c| !c.is_whitespace()).collect();
    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD.decode(body).map_err(|e| format!("PEM body: {e}"))?;
    out.push(der);
    rest = &after[end + END.len()..];
  }
  if out.is_empty() {
    return Err("no PEM certificate".into());
  }
  Ok(out)
}

/// The verifier's trust anchors.
#[derive(Clone, Debug)]
pub struct TrustAnchors(pub Vec<DocumentSigner>);

impl TrustAnchors {
  /// Anchors from PEM text; each must be a self-signed P-256 Document Signer.
  pub fn from_pem(text: &str) -> Result<Self, String> {
    let anchors = pem_certificates(text)?.iter().map(|der| parse(der)).collect::<Result<Vec<_>, _>>()?;
    if let Some(a) = anchors.iter().find(|a| !a.self_signed) {
      return Err(format!("trust anchor {} is not self-signed with ECDSA-SHA256", a.subject));
    }
    Ok(TrustAnchors(anchors))
  }

  /// Validates a Document Signer certificate at `now`: it is a trust anchor and valid then.
  pub fn validate(&self, der: &[u8], now: i64) -> Result<DocumentSigner, String> {
    let anchor = self.0.iter().find(|a| a.der == der).ok_or("the Document Signer certificate is not a trust anchor")?;
    if now < anchor.not_before || now > anchor.not_after {
      return Err(format!("the Document Signer certificate {} is not valid now", anchor.subject));
    }
    Ok(anchor.clone())
  }
}
