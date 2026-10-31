//! nym-issuer: issues the Community demo's `eu.europa.ec.eudi.nym_auth.1` mdocs under the issuance
//! profile of nym-auth-circuits SPEC.md §2.1, with fresh keys:
//!
//! - a demo issuer key (P-256) and its self-signed Document Signer certificate, which the
//!   verifier trusts (`--trust-out`, PEM); every holder's credential is signed with it;
//! - for each holder (`--holder`, repeated): a device key pair (P-256), bound in the MSO; a random
//!   16-byte secret_seed, with `ssc` = SHA-256(secret_seed); the items `birth_date`
//!   (`1004("YYYY-MM-DD")`) and `ssc` (bstr 32), 16-byte random salts, digestIDs 0 and 1, the
//!   protected header exactly `{1: -7}`, `x5chain` in the unprotected header, and the MSO with
//!   exactly version, digestAlgorithm, valueDigests, deviceKeyInfo, docType and validityInfo
//!   (signed, validFrom, validUntil as 20-character tdates).
//!
//! The demo has no true holder binding: the wallet file (`--wallet-out`) holds each holder's
//! credential, device private key and seed, and the page's mocked wallet carries them. The issuer's
//! private key is not written anywhere; to re-issue, run the tool again, which replaces both files.
//!
//! With `--v05`, each holder also gets a rulebook v0.5 mdoc (`docs/nym_auth_rulebook-v0.5.md`,
//! compact profile), signed by the same Document Signer over the same device key, seed and
//! validity: the items `bsc` = SHA-256(secret_seed ‖ birth_date) (digestID 0) and `psc` =
//! SHA-256(private_seed) (digestID 1), each a 32-byte bstr with a 16-byte random, the MSO members
//! in the profile's order (version, digestAlgorithm, docType, valueDigests, deviceKeyInfo,
//! validityInfo), and a fresh 16-byte private_seed per holder (kept by `--keep` when the earlier
//! file has one). The wallet file holds it under the holder's `v05`, with `birth_date` (10 ASCII
//! bytes, which open `bsc` with the seed) and `private_seed`. Each v0.5 credential is checked
//! against the layout the v0.5 Longfellow circuits read (Peter's nym-auth-longfellow-v1 package,
//! INTEGRATION.md §5): Sig_structure 423 B (376 to 439), bsc item 108 B (56 to 119), and each
//! byte pattern exactly once.
//!
//! With `--v06`, each holder also gets a rulebook v0.6 mdoc in the decoy-digest layout (Peter's
//! nym-auth-longfellow-decoy-v1 package, INTEGRATION.md §5): the MSO's valueDigests hold `bsc` (0)
//! and `psc` (1) themselves, there are no IssuerSignedItems and no `nameSpaces`, and the MSO is the
//! fixed 398-byte form. It is written byte by byte, not with the CBOR writer, with the same seed,
//! birth_date, private_seed, device key, validity and Document Signer as the holder's v0.5 one, and
//! checked before writing: MSO 398 B, Sig_structure 423 B, three 20-character tdates, and every byte
//! outside the seven private fields equal to the circuits' template (`v06_template.hex`, a copy of
//! `nym_auth_zk_decoy::mdoc::TEMPLATE`; native/longfellow's tests check the copy). The wallet file
//! holds it under the holder's `v06` as `{ credential, birth_date, private_seed }`.
//!
//! Before writing, the tool checks the profile's lengths for each credential (Sig_structure 423 B,
//! birth_date item 95 B, ssc item 108 B), prints them, and takes each credential apart again as the
//! prover does.
//!
//! ```text
//! nym-issuer --holder YYYY-MM-DD[:DAYS] [--holder ...] --wallet-out <file.json> --trust-out <file.pem>
//!            [--valid-from YYYY-MM-DD] [--days N | --valid-until YYYY-MM-DDThh:mm:ssZ] [--keep <file.json>] [--v05] [--v06]
//! ```
//! Each holder's validity runs from `--valid-from` (default: yesterday, UTC) 00:00:00Z for DAYS days
//! (default `--days`, 366), or to `--valid-until` for every holder; `9999-12-31T23:59:59Z` is the
//! farthest a tdate holds, for a credential that does not expire. The certificate runs one year
//! longer than the longest validity, and to 9999-12-31T23:59:59Z at most (RFC 5280 §4.1.2.5: no
//! well-defined expiration). `--keep` reuses each holder's device key and secret_seed from an
//! earlier wallet file, in order, so that the seed commitments, and so the pseudonyms, stay the
//! same; only the issuer, the signatures and the dates change. `--birth-date` is accepted for
//! `--holder`.

use std::process::ExitCode;

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::EncodePrivateKey;
use rand_core::{OsRng, RngCore};
use serde_json::json;
use vega_age::fixtures::cbor::{Value, int, record, tag, text};
use vega_age::fixtures::mdoc::{full_date, item_bytes};
use vega_age::presentation::{Date, Time};
use vega_age::table::sha256;

use nym_vega::circuit::{BIRTH_DATE, DOC_TYPE, SSC};
use nym_vega::{b64url, dates, mdoc, x509};

/// SPEC.md §2.1, "Lengths that follow".
const SIG_STRUCTURE_BYTES: usize = 423;
const BIRTH_DATE_ITEM_BYTES: usize = 95;
const SSC_ITEM_BYTES: usize = 108;

struct Holder {
  birth_date: Date,
  /// Days of validity; `--days` when not given.
  days: Option<i64>,
}

struct Args {
  holders: Vec<Holder>,
  wallet_out: String,
  trust_out: String,
  valid_from: Date,
  days: i64,
  valid_until: Option<Time>,
  keep: Option<String>,
  /// Also issue each holder's rulebook v0.5 mdoc.
  v05: bool,
  /// Also issue each holder's rulebook v0.6 mdoc (the decoy-digest layout).
  v06: bool,
}

fn holder(value: &str) -> Result<Holder, String> {
  let (date, days) = match value.split_once(':') {
    Some((d, n)) => (d, Some(n.parse::<i64>().map_err(|_| format!("--holder {value}: not a number of days"))?)),
    None => (value, None),
  };
  Ok(Holder { birth_date: dates::date(date)?, days })
}

fn args() -> Result<Args, String> {
  let mut it = std::env::args().skip(1);
  let (mut holders, mut wallet_out, mut trust_out, mut valid_from, mut days) = (Vec::new(), None, None, None, 366);
  let (mut valid_until, mut keep, mut v05, mut v06) = (None, None, false, false);
  while let Some(flag) = it.next() {
    if flag == "--v05" {
      v05 = true;
      continue;
    }
    if flag == "--v06" {
      v06 = true;
      continue;
    }
    let value = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
    match flag.as_str() {
      "--holder" | "--birth-date" => holders.push(holder(&value)?),
      "--wallet-out" => wallet_out = Some(value),
      "--trust-out" => trust_out = Some(value),
      "--valid-from" => valid_from = Some(dates::date(&value)?),
      "--days" => days = value.parse().map_err(|_| format!("--days: not a number: {value}"))?,
      "--valid-until" => valid_until = Some(dates::date_time(&value)?),
      "--keep" => keep = Some(value),
      other => return Err(format!("unknown option {other}")),
    }
  }
  if holders.is_empty() {
    return Err("at least one --holder is required".into());
  }
  if days < 2 || holders.iter().any(|h| h.days.is_some_and(|d| d < 2)) {
    return Err("a validity must be at least 2 days".into());
  }
  let yesterday = dates::from_unix(dates::unix(&dates::now()?)? - 86_400)?.date;
  Ok(Args {
    holders,
    wallet_out: wallet_out.ok_or("--wallet-out is required")?,
    trust_out: trust_out.ok_or("--trust-out is required")?,
    valid_from: valid_from.unwrap_or(yesterday),
    days,
    valid_until,
    keep,
    v05,
    v06,
  })
}

fn midnight(date: Date) -> Time {
  Time { date, hour: 0, minute: 0, second: 0 }
}

fn random<const N: usize>() -> [u8; N] {
  let mut out = [0u8; N];
  OsRng.fill_bytes(&mut out);
  out
}

fn offset(t: &Time) -> Result<time::OffsetDateTime, String> {
  time::OffsetDateTime::from_unix_timestamp(dates::unix(t)?).map_err(|e| e.to_string())
}

/// The self-signed Document Signer certificate of `issuer`: keyUsage digitalSignature and the
/// extended key usage mdlDS (1.0.18013.5.1.2) of ISO/IEC 18013-5.
fn document_signer(issuer: &SigningKey, not_before: &Time, not_after: &Time) -> Result<rcgen::Certificate, String> {
  let pkcs8 = issuer.to_pkcs8_der().map_err(|e| e.to_string())?;
  let key_pair = rcgen::KeyPair::try_from(pkcs8.as_bytes()).map_err(|e| e.to_string())?;
  let mut params = rcgen::CertificateParams::default();
  let mut name = rcgen::DistinguishedName::new();
  name.push(rcgen::DnType::CommonName, "Demo Document Signer");
  name.push(rcgen::DnType::OrganizationName, "Demo Issuer");
  name.push(rcgen::DnType::CountryName, "SE");
  params.distinguished_name = name;
  params.not_before = offset(not_before)?;
  params.not_after = offset(not_after)?;
  params.serial_number = Some(rcgen::SerialNumber::from(random::<16>().to_vec()));
  params.is_ca = rcgen::IsCa::ExplicitNoCa;
  params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
  params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::Other(vec![1, 0, 18013, 5, 1, 2])];
  params.self_signed(&key_pair).map_err(|e| e.to_string())
}

/// A holder's device key and secret_seed from an earlier wallet file, checked to be consistent.
fn kept(holder: &serde_json::Value, k: usize) -> Result<(SigningKey, [u8; 16]), String> {
  let field = |path: &[&str]| -> Result<String, String> {
    let mut v = holder;
    for p in path {
      v = v.get(p).ok_or_else(|| format!("--keep: holder {}: no {}", k + 1, path.join(".")))?;
    }
    v.as_str().map(str::to_string).ok_or_else(|| format!("--keep: holder {}: {} is not text", k + 1, path.join(".")))
  };
  let d: [u8; 32] = nym_vega::unb64url("device_key.d", &field(&["device_key", "d"])?)?
    .try_into()
    .map_err(|_| format!("--keep: holder {}: device_key.d is not 32 bytes", k + 1))?;
  let device = SigningKey::from_bytes(&d.into()).map_err(|e| format!("--keep: holder {}: device_key.d: {e}", k + 1))?;
  let point = device.verifying_key().to_encoded_point(false);
  if b64url(point.x().ok_or("x")?) != field(&["device_key", "x"])? || b64url(point.y().ok_or("y")?) != field(&["device_key", "y"])? {
    return Err(format!("--keep: holder {}: device_key.x and y are not the public key of d", k + 1));
  }
  let seed = nym_vega::unhex::<16>("secret_seed", &field(&["secret_seed"])?)?;
  Ok((device, seed))
}

/// The private_seed of an earlier wallet file's holder: its v0.5 credential's, else its v0.6
/// credential's (both hold the same one), if it has either.
fn kept_private_seed(p: &serde_json::Value, k: usize) -> Result<Option<[u8; 16]>, String> {
  for v in ["v05", "v06"] {
    if let Some(s) = p.get(v).and_then(|c| c.get("private_seed")).and_then(|s| s.as_str()) {
      return nym_vega::unhex::<16>(&format!("--keep: holder {}: {v}.private_seed", k + 1), s).map(Some);
    }
  }
  Ok(None)
}

/// One holder's credential, device key and seed, signed by `issuer` with the Document Signer `ds`;
/// checked against the profile's lengths and read back as the prover reads it. `keep` reuses a
/// device key and seed; without it both are fresh.
fn issue(issuer: &SigningKey, ds: &[u8], birth_date: &Date, valid_from: &Time, valid_until: &Time, device: &SigningKey, seed: [u8; 16]) -> Result<serde_json::Value, String> {
  let device_point = device.verifying_key().to_encoded_point(false);
  let (dx, dy) = (device_point.x().ok_or("device x")?, device_point.y().ok_or("device y")?);
  let ssc = sha256(&seed);

  let birth_item = item_bytes(0, &random::<16>(), BIRTH_DATE, full_date(birth_date));
  let ssc_item = item_bytes(1, &random::<16>(), SSC, Value::Bytes(ssc.to_vec()));
  let cose_key = Value::Map(vec![
    (int(1), int(2)),
    (int(-1), int(1)),
    (int(-2), Value::Bytes(dx.to_vec())),
    (int(-3), Value::Bytes(dy.to_vec())),
  ]);
  let digests = Value::Map(vec![
    (Value::Unsigned(0), Value::Bytes(sha256(&birth_item).to_vec())),
    (Value::Unsigned(1), Value::Bytes(sha256(&ssc_item).to_vec())),
  ]);
  let mso = record(vec![
    ("version", text("1.0")),
    ("digestAlgorithm", text("SHA-256")),
    ("valueDigests", Value::Map(vec![(text(DOC_TYPE), digests)])),
    ("deviceKeyInfo", record(vec![("deviceKey", cose_key)])),
    ("docType", text(DOC_TYPE)),
    (
      "validityInfo",
      record(vec![
        ("signed", tag(0, text(&valid_from.text()))),
        ("validFrom", tag(0, text(&valid_from.text()))),
        ("validUntil", tag(0, text(&valid_until.text()))),
      ]),
    ),
  ]);
  let payload = tag(24, Value::Bytes(mso.encode())).encode();
  let protected = Value::Map(vec![(int(1), int(-7))]).encode();
  let sig_structure = Value::Array(vec![
    text("Signature1"),
    Value::Bytes(protected.clone()),
    Value::Bytes(Vec::new()),
    Value::Bytes(payload.clone()),
  ])
  .encode();
  let signature: Signature = issuer.sign(&sig_structure);
  let issuer_auth = Value::Array(vec![
    Value::Bytes(protected),
    Value::Map(vec![(int(33), Value::Bytes(ds.to_vec()))]),
    Value::Bytes(payload),
    Value::Bytes(signature.to_bytes().to_vec()),
  ]);
  let issuer_signed = record(vec![
    ("nameSpaces", Value::Map(vec![(text(DOC_TYPE), Value::Array(vec![Value::Encoded(birth_item.clone()), Value::Encoded(ssc_item.clone())]))])),
    ("issuerAuth", issuer_auth),
  ])
  .encode();

  // The profile's lengths.
  let lengths = [
    ("Sig_structure", sig_structure.len(), SIG_STRUCTURE_BYTES),
    ("birth_date item", birth_item.len(), BIRTH_DATE_ITEM_BYTES),
    ("ssc item", ssc_item.len(), SSC_ITEM_BYTES),
  ];
  for (what, got, want) in lengths {
    println!("  {what}: {got} B (profile: {want} B)");
    if got != want {
      return Err(format!("{what} is {got} bytes, the profile's is {want}: not written"));
    }
  }

  // Take it apart again, as the prover does.
  let encoded = b64url(&issuer_signed);
  let m = mdoc::parse(&encoded)?;
  let signer = x509::parse(&m.document_signer)?;
  if m.sig_structure != sig_structure || m.birth_date()? != *birth_date || m.ssc()? != ssc || !m.digests_listed() {
    return Err("the issued credential does not read back".into());
  }
  if m.device_key.x[..] != dx[..] || m.device_key.y[..] != dy[..] || !signer.self_signed {
    return Err("the device key or the Document Signer does not read back".into());
  }
  println!("  IssuerSigned: {} B; validity {} to {}; ssc {}", issuer_signed.len(), valid_from.text(), valid_until.text(), nym_vega::hex(&ssc));

  Ok(json!({
    "credential": { "format": "mso_mdoc", "doctype": DOC_TYPE, "issuer_signed": encoded },
    "device_key": { "kty": "EC", "crv": "P-256", "x": b64url(dx), "y": b64url(dy), "d": b64url(&device.to_bytes()) },
    "secret_seed": nym_vega::hex(&seed),
  }))
}

/// The one position of `pat` in `hay`, or an error naming `what`.
fn once(hay: &[u8], pat: &[u8], what: &str) -> Result<(), String> {
  let n = hay.windows(pat.len()).filter(|w| *w == pat).count();
  if n == 1 { Ok(()) } else { Err(format!("{what}: found {n} times, the v0.5 circuits read it exactly once")) }
}

/// One holder's rulebook v0.5 credential (compact profile): `bsc` and `psc`, the same device key,
/// seed, Document Signer and validity as the v0.4 one; checked against the layout the v0.5
/// Longfellow circuits read.
#[allow(clippy::too_many_arguments)]
fn issue_v05(issuer: &SigningKey, ds: &[u8], birth_date: &Date, valid_from: &Time, valid_until: &Time, device: &SigningKey, seed: &[u8; 16], private_seed: &[u8; 16]) -> Result<serde_json::Value, String> {
  let device_point = device.verifying_key().to_encoded_point(false);
  let (dx, dy) = (device_point.x().ok_or("device x")?, device_point.y().ok_or("device y")?);
  let birth = birth_date.text();
  if birth.len() != 10 {
    return Err(format!("birth_date {birth} is not 10 bytes"));
  }
  let bsc = sha256(&[&seed[..], birth.as_bytes()].concat());
  let psc = sha256(private_seed);
  let bsc_item = item_bytes(0, &random::<16>(), "bsc", Value::Bytes(bsc.to_vec()));
  let psc_item = item_bytes(1, &random::<16>(), "psc", Value::Bytes(psc.to_vec()));
  let cose_key = Value::Map(vec![
    (int(1), int(2)),
    (int(-1), int(1)),
    (int(-2), Value::Bytes(dx.to_vec())),
    (int(-3), Value::Bytes(dy.to_vec())),
  ]);
  let bsc_digest = sha256(&bsc_item);
  let digests = Value::Map(vec![
    (Value::Unsigned(0), Value::Bytes(bsc_digest.to_vec())),
    (Value::Unsigned(1), Value::Bytes(sha256(&psc_item).to_vec())),
  ]);
  // The compact profile's order (rulebook v0.5, "Compact profile").
  let mso = record(vec![
    ("version", text("1.0")),
    ("digestAlgorithm", text("SHA-256")),
    ("docType", text(DOC_TYPE)),
    ("valueDigests", Value::Map(vec![(text(DOC_TYPE), digests)])),
    ("deviceKeyInfo", record(vec![("deviceKey", cose_key)])),
    (
      "validityInfo",
      record(vec![
        ("signed", tag(0, text(&valid_from.text()))),
        ("validFrom", tag(0, text(&valid_from.text()))),
        ("validUntil", tag(0, text(&valid_until.text()))),
      ]),
    ),
  ]);
  let payload = tag(24, Value::Bytes(mso.encode())).encode();
  let protected = Value::Map(vec![(int(1), int(-7))]).encode();
  let sig_structure = Value::Array(vec![
    text("Signature1"),
    Value::Bytes(protected.clone()),
    Value::Bytes(Vec::new()),
    Value::Bytes(payload.clone()),
  ])
  .encode();
  let signature: Signature = issuer.sign(&sig_structure);
  let issuer_auth = Value::Array(vec![
    Value::Bytes(protected),
    Value::Map(vec![(int(33), Value::Bytes(ds.to_vec()))]),
    Value::Bytes(payload),
    Value::Bytes(signature.to_bytes().to_vec()),
  ]);
  let issuer_signed = record(vec![
    ("nameSpaces", Value::Map(vec![(text(DOC_TYPE), Value::Array(vec![Value::Encoded(bsc_item.clone()), Value::Encoded(psc_item.clone())]))])),
    ("issuerAuth", issuer_auth),
  ])
  .encode();

  // The layout the v0.5 circuits read (nym-auth-longfellow-v1, INTEGRATION.md §5).
  println!("    Sig_structure: {} B (circuits: 376 to 439; rulebook vector: 423)", sig_structure.len());
  println!("    bsc item: {} B (circuits: 56 to 119), psc item: {} B", bsc_item.len(), psc_item.len());
  if !(376..=439).contains(&sig_structure.len()) || !(56..=119).contains(&bsc_item.len()) {
    return Err("the v0.5 credential is outside the lengths the circuits read: not written".into());
  }
  let mut doc_type = vec![0x67];
  doc_type.extend_from_slice(b"docType");
  doc_type.extend_from_slice(&text(DOC_TYPE).encode());
  let mut device_key = b"\x69deviceKey\xa4\x01\x02\x20\x01\x21\x58\x20".to_vec();
  device_key.extend_from_slice(dx);
  device_key.extend_from_slice(b"\x22\x58\x20");
  device_key.extend_from_slice(dy);
  let mut listed = vec![0x58, 0x20];
  listed.extend_from_slice(&bsc_digest);
  once(&sig_structure, &doc_type, "docType")?;
  once(&sig_structure, &device_key, "deviceKey")?;
  once(&sig_structure, b"\x69validFrom\xc0\x74", "validFrom")?;
  once(&sig_structure, b"\x6avalidUntil\xc0\x74", "validUntil")?;
  once(&sig_structure, &listed, "the bsc digest")?;
  once(&bsc_item, b"\x71elementIdentifier\x63bsc", "the bsc identifier")?;
  let mut value = b"\x6celementValue\x58\x20".to_vec();
  value.extend_from_slice(&bsc);
  once(&bsc_item, &value, "the bsc value")?;
  println!("    IssuerSigned: {} B; bsc {}; psc {}", issuer_signed.len(), nym_vega::hex(&bsc), nym_vega::hex(&psc));

  Ok(json!({
    "credential": { "format": "mso_mdoc", "doctype": DOC_TYPE, "rulebook": "0.5", "issuer_signed": b64url(&issuer_signed) },
    "birth_date": birth,
    "private_seed": nym_vega::hex(private_seed),
  }))
}

/// The circuits' Sig_structure template for the v0.6 layout: a copy of
/// `nym_auth_zk_decoy::mdoc::TEMPLATE` (every constant byte, the seven private fields zero), which
/// native/longfellow's tests compare with the crate's.
const V06_TEMPLATE_HEX: &str = include_str!("v06_template.hex");
/// The private fields of the v0.6 Sig_structure: (offset, length) of bsc, psc, the device key's x
/// and y, signed, validFrom, validUntil (INTEGRATION.md §5).
const V06_FIELDS: [(usize, usize); 7] = [(148, 32), (183, 32), (248, 32), (283, 32), (338, 20), (370, 20), (403, 20)];
const V06_MSO_BYTES: usize = 398;

/// A CBOR text string with a head of one or two bytes (lengths under 256).
fn tstr(s: &str) -> Vec<u8> {
  let mut out = if s.len() < 24 { vec![0x60 | s.len() as u8] } else { vec![0x78, s.len() as u8] };
  out.extend_from_slice(s.as_bytes());
  out
}

/// One holder's rulebook v0.6 credential, the decoy-digest layout (INTEGRATION.md §5), written byte
/// by byte: `bsc` and `psc` as the MSO's valueDigests 0 and 1, no IssuerSignedItems, no
/// `nameSpaces`. The same device key, seed, private_seed, Document Signer and validity as the
/// v0.5 one. Checked against the circuits' template before it is returned.
#[allow(clippy::too_many_arguments)]
fn issue_v06(issuer: &SigningKey, ds: &[u8], birth_date: &Date, valid_from: &Time, valid_until: &Time, device: &SigningKey, seed: &[u8; 16], private_seed: &[u8; 16]) -> Result<serde_json::Value, String> {
  let device_point = device.verifying_key().to_encoded_point(false);
  let (dx, dy) = (device_point.x().ok_or("device x")?, device_point.y().ok_or("device y")?);
  let birth = birth_date.text();
  if birth.len() != 10 {
    return Err(format!("birth_date {birth} is not 10 bytes"));
  }
  let bsc = sha256(&[&seed[..], birth.as_bytes()].concat());
  let psc = sha256(private_seed);
  let tdate = |t: &Time| -> Result<Vec<u8>, String> {
    let text = t.text();
    if text.len() != 20 {
      return Err(format!("the tdate {text} is not 20 characters"));
    }
    Ok([&[0xc0, 0x74][..], text.as_bytes()].concat())
  };
  let (signed, from, until) = (tdate(valid_from)?, tdate(valid_from)?, tdate(valid_until)?);

  // The MSO, in the layout's key order and heads (INTEGRATION.md §5).
  let mut mso = vec![0xa6];
  mso.extend(tstr("version"));
  mso.extend(tstr("1.0"));
  mso.extend(tstr("digestAlgorithm"));
  mso.extend(tstr("SHA-256"));
  mso.extend(tstr("docType"));
  mso.extend(tstr(DOC_TYPE));
  mso.extend(tstr("valueDigests"));
  mso.push(0xa1);
  mso.extend(tstr(DOC_TYPE));
  mso.extend_from_slice(&[0xa2, 0x00, 0x58, 0x20]);
  mso.extend_from_slice(&bsc);
  mso.extend_from_slice(&[0x01, 0x58, 0x20]);
  mso.extend_from_slice(&psc);
  mso.extend(tstr("deviceKeyInfo"));
  mso.push(0xa1);
  mso.extend(tstr("deviceKey"));
  mso.extend_from_slice(&[0xa4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20]);
  mso.extend_from_slice(dx);
  mso.extend_from_slice(&[0x22, 0x58, 0x20]);
  mso.extend_from_slice(dy);
  mso.extend(tstr("validityInfo"));
  mso.push(0xa3);
  mso.extend(tstr("signed"));
  mso.extend(signed);
  mso.extend(tstr("validFrom"));
  mso.extend(from);
  mso.extend(tstr("validUntil"));
  mso.extend(until);
  if mso.len() != V06_MSO_BYTES {
    return Err(format!("the v0.6 MSO is {} B, not {V06_MSO_BYTES}: not written", mso.len()));
  }

  // payload = bstr(#6.24(bstr(MSO))): 59 01 93 d8 18 59 01 8e <MSO>.
  let payload = [&[0x59, 0x01, 0x93, 0xd8, 0x18, 0x59, 0x01, 0x8e][..], &mso].concat();
  // Sig_structure = ["Signature1", h'a10126', h'', payload].
  let sig_structure = [&[0x84][..], &tstr("Signature1"), &[0x43, 0xa1, 0x01, 0x26, 0x40], &payload].concat();
  let template_hex: String = V06_TEMPLATE_HEX.split_whitespace().collect();
  let template: Vec<u8> = (0..template_hex.len())
    .step_by(2)
    .map(|i| template_hex.get(i..i + 2).ok_or("odd template hex").and_then(|h| u8::from_str_radix(h, 16).map_err(|_| "template hex")))
    .collect::<Result<_, _>>()?;
  if template.len() != SIG_STRUCTURE_BYTES || sig_structure.len() != SIG_STRUCTURE_BYTES {
    return Err(format!("the v0.6 Sig_structure is {} B and the template {} B, not {SIG_STRUCTURE_BYTES}: not written", sig_structure.len(), template.len()));
  }
  let private = |i: usize| V06_FIELDS.iter().any(|&(at, n)| at <= i && i < at + n);
  if let Some(i) = (0..SIG_STRUCTURE_BYTES).find(|&i| !private(i) && sig_structure[i] != template[i]) {
    return Err(format!("the v0.6 Sig_structure differs from the circuits' template at byte {i}: not written"));
  }
  if sig_structure[148..180] != bsc || sig_structure[183..215] != psc || sig_structure[248..280] != dx[..] || sig_structure[283..315] != dy[..] {
    return Err("the v0.6 Sig_structure does not hold bsc, psc and the device key at their offsets: not written".into());
  }
  let signature: Signature = issuer.sign(&sig_structure);

  // IssuerSigned = { "issuerAuth": [h'a10126', {33: x5chain}, payload, r || s] }, no nameSpaces.
  let mut issuer_signed = vec![0xa1];
  issuer_signed.extend(tstr("issuerAuth"));
  issuer_signed.extend_from_slice(&[0x84, 0x43, 0xa1, 0x01, 0x26, 0xa1, 0x18, 0x21]);
  match ds.len() {
    24..=255 => issuer_signed.extend_from_slice(&[0x58, ds.len() as u8]),
    256..=65535 => issuer_signed.extend_from_slice(&[0x59, (ds.len() >> 8) as u8, ds.len() as u8]),
    n => return Err(format!("the Document Signer certificate is {n} B: no minimal bstr head of 2 or 3 bytes")),
  }
  issuer_signed.extend_from_slice(ds);
  issuer_signed.extend_from_slice(&payload);
  issuer_signed.extend_from_slice(&[0x58, 0x40]);
  issuer_signed.extend_from_slice(&signature.to_bytes());
  println!("    MSO: {} B, Sig_structure: {} B (the layout: 398, 423); constant bytes equal the circuits' template", mso.len(), sig_structure.len());
  println!("    IssuerSigned: {} B; bsc {}; psc {}", issuer_signed.len(), nym_vega::hex(&bsc), nym_vega::hex(&psc));

  Ok(json!({
    "credential": { "format": "mso_mdoc", "doctype": DOC_TYPE, "rulebook": "0.6", "issuer_signed": b64url(&issuer_signed) },
    "birth_date": birth,
    "private_seed": nym_vega::hex(private_seed),
  }))
}

fn run() -> Result<(), String> {
  let a = args()?;
  let valid_from = midnight(a.valid_from);
  let until = |h: &Holder| -> Result<Time, String> {
    match &a.valid_until {
      Some(t) => Ok(*t),
      None => dates::from_unix(dates::unix(&valid_from)? + h.days.unwrap_or(a.days) * 86_400),
    }
  };
  let untils = a.holders.iter().map(until).collect::<Result<Vec<_>, _>>()?;
  let from = dates::unix(&valid_from)?;
  let mut longest = from;
  for t in &untils {
    let u = dates::unix(t)?;
    if u <= from {
      return Err("a validity must end after --valid-from".into());
    }
    longest = longest.max(u);
  }
  // One year past the longest validity, and at most 9999-12-31T23:59:59Z.
  let farthest = dates::unix(&dates::date_time("9999-12-31T23:59:59Z")?)?;
  let cert_until = dates::from_unix((longest + 365 * 86_400).min(farthest))?;

  let previous: Vec<serde_json::Value> = match &a.keep {
    Some(path) => {
      let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
      let file: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))?;
      let list = file.get("holders").and_then(|h| h.as_array()).ok_or_else(|| format!("{path}: no holders list"))?.clone();
      if list.len() != a.holders.len() {
        return Err(format!("--keep: {path} has {} holders, --holder gives {}", list.len(), a.holders.len()));
      }
      list
    }
    None => Vec::new(),
  };

  let issuer = SigningKey::random(&mut OsRng);
  let ds = document_signer(&issuer, &valid_from, &cert_until)?;
  let mut holders = Vec::new();
  for (k, h) in a.holders.iter().enumerate() {
    println!("holder {} (born {}){}:", k + 1, h.birth_date.text(), if a.keep.is_some() { ", device key and seed kept" } else { "" });
    let keep = previous.get(k).map(|p| kept(p, k)).transpose()?;
    let (device, seed) = keep.unwrap_or_else(|| (SigningKey::random(&mut OsRng), random()));
    let mut holder = issue(&issuer, ds.der(), &h.birth_date, &valid_from, &untils[k], &device, seed)?;
    // One private_seed per holder, shared by its v0.5 and v0.6 credentials.
    let private_seed = match previous.get(k) {
      Some(p) => kept_private_seed(p, k)?.unwrap_or_else(random),
      None => random(),
    };
    if a.v05 {
      println!("  v0.5:");
      holder["v05"] = issue_v05(&issuer, ds.der(), &h.birth_date, &valid_from, &untils[k], &device, &seed, &private_seed)?;
    }
    if a.v06 {
      println!("  v0.6 (decoy-digest layout):");
      holder["v06"] = issue_v06(&issuer, ds.der(), &h.birth_date, &valid_from, &untils[k], &device, &seed, &private_seed)?;
    }
    holders.push(holder);
  }

  let wallet = json!({
    "comment": "Demo holder material for the mocked SIROS ID wallet, issued by native/vega/issuer (nym-issuer): one rulebook v0.4 credential per holder and, under v05, its rulebook v0.5 credential (bsc, psc) and, under v06, its rulebook v0.6 credential (the decoy-digest layout: bsc and psc as the MSO's valueDigests), each with the birth_date and private_seed that open them, all signed by the same Document Signer over the same device key and secret_seed. No true holder binding: the device private keys and the seeds sit in the page.",
    "holders": holders,
  });
  let text = serde_json::to_string_pretty(&wallet).map_err(|e| e.to_string())? + "\n";
  std::fs::write(&a.wallet_out, text).map_err(|e| format!("{}: {e}", a.wallet_out))?;
  std::fs::write(&a.trust_out, ds.pem()).map_err(|e| format!("{}: {e}", a.trust_out))?;
  let signer = x509::parse(ds.der())?;
  println!("Document Signer: {} (until {})", signer.subject, cert_until.text());
  println!("wrote {} and {}", a.wallet_out, a.trust_out);
  Ok(())
}

fn main() -> ExitCode {
  match run() {
    Ok(()) => ExitCode::SUCCESS,
    Err(e) => {
      eprintln!("nym-issuer: {e}");
      ExitCode::from(2)
    }
  }
}
