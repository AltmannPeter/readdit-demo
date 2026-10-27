#!/usr/bin/env python3
"""
Deterministic TEST fixture generator for a nym_auth mso_mdoc, compact profile
(rulebook v0.4 on fix-birthdate: data elements bsc + psc, no ssc).

TEST ONLY: every key below is derived from a public label. Never use them outside tests.

Two variants, written side by side:
  (no suffix)   psc = SHA-256(private_seed)
  _zero_psc     psc = 32 zero bytes (holder provided no psc; -psc configurations are unsatisfiable)

Per variant:
  nym_auth_test_vectors<sfx>.json      inputs, intermediates, layout offsets, expected outputs (hex)
  issuer_signed<sfx>.cbor              IssuerSigned (nameSpaces + issuerAuth)
  mso<sfx>.cbor                        MobileSecurityObject (untagged CBOR)
  device_response_redirect<sfx>.cbor   DeviceResponse bound to an OpenID4VPHandover
  device_response_dcapi<sfx>.cbor      DeviceResponse bound to an OpenID4VPDCAPIHandover
Shared: iaca.der, ds.der

Usage: python3 gen_nym_auth_mdoc.py [outdir]
Requires: cbor2, cryptography >= 44 (deterministic ECDSA, RFC 6979).
"""
import datetime as dt, hashlib, json, pathlib, sys
import cbor2
from cbor2 import CBORTag
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

OUT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
OUT.mkdir(parents=True, exist_ok=True)

DOCTYPE = NS = "eu.europa.ec.eudi.nym_auth.1"
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
sha256 = lambda b: hashlib.sha256(b).digest()
enc = lambda o: cbor2.dumps(o)                    # definite-length; maps keep insertion order
tag24 = lambda o: CBORTag(24, enc(o))
tdate = lambda s: CBORTag(0, s)                   # compact profile: YYYY-MM-DDTHH:MM:SSZ
ECDSA = ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
H = lambda b: b.hex()

def key(label):
    d = int.from_bytes(sha256(b"nym_auth TEST ONLY key: " + label.encode()), "big") % (P256_N - 1) + 1
    return ec.derive_private_key(d, ec.SECP256R1())

def xy(pub):
    n = pub.public_numbers()
    return n.x.to_bytes(32, "big"), n.y.to_bytes(32, "big")

def cose_sign1(priv, protected, unprotected, payload, detached=False):
    prot = enc(protected)
    to_be_signed = enc(["Signature1", prot, b"", payload])
    r, s = decode_dss_signature(priv.sign(to_be_signed, ECDSA))
    return [prot, unprotected, None if detached else payload, r.to_bytes(32, "big") + s.to_bytes(32, "big")], to_be_signed

# ---------------------------------------------------------------- holder inputs
secret_seed  = bytes(range(16))                      # 000102...0f
private_seed = bytes(range(0x10, 0x20))              # 101112...1f
birth_date   = "2010-05-17"
SIGNED, VALID_UNTIL = "2026-10-27T00:00:00Z", "2027-10-27T00:00:00Z"
bsc = sha256(secret_seed + birth_date.encode())      # 26-byte input

# ---------------------------------------------------------------- keys and certificates (shared)
iaca_key, ds_key, dev_key = key("iaca"), key("document-signer"), key("device")
nb, na = dt.datetime(2026, 10, 1, tzinfo=dt.timezone.utc), dt.datetime(2028, 10, 1, tzinfo=dt.timezone.utc)
name = lambda cn: x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "SE"), x509.NameAttribute(NameOID.COMMON_NAME, cn)])
iaca_name, ds_name = name("nym_auth TEST IACA"), name("nym_auth TEST Document Signer")
ski = lambda k: x509.SubjectKeyIdentifier.from_public_key(k.public_key())
iaca = (x509.CertificateBuilder().subject_name(iaca_name).issuer_name(iaca_name)
        .public_key(iaca_key.public_key()).serial_number(1).not_valid_before(nb).not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(ski(iaca_key), critical=False)
        .sign(iaca_key, hashes.SHA256(), ecdsa_deterministic=True))
ds = (x509.CertificateBuilder().subject_name(ds_name).issuer_name(iaca_name)
      .public_key(ds_key.public_key()).serial_number(2).not_valid_before(nb).not_valid_after(na)
      .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
      .add_extension(x509.ExtendedKeyUsage([ObjectIdentifier("1.0.18013.5.1.2")]), critical=True)
      .add_extension(ski(ds_key), critical=False)
      .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(iaca_key.public_key()), critical=False)
      .sign(iaca_key, hashes.SHA256(), ecdsa_deterministic=True))
ds_der, iaca_der = ds.public_bytes(serialization.Encoding.DER), iaca.public_bytes(serialization.Encoding.DER)
(OUT / "iaca.der").write_bytes(iaca_der); (OUT / "ds.der").write_bytes(ds_der)
dx, dy = xy(dev_key.public_key())
ix, iy = xy(ds_key.public_key())

# ---------------------------------------------------------------- session inputs (rulebook Binding section)
jwk = {"crv": "P-256", "kty": "EC", "x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
       "y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"}   # Verifier enc key from the rulebook example
jwk_thumb = sha256(json.dumps(jwk, separators=(",", ":"), sort_keys=True).encode())  # RFC 7638
client_id, nonce = "x509_san_dns:rp.example.com", "n-0S6_WzA2Mj"
response_uri, origin = "https://rp.example.com/response", "https://rp.example.com"
handovers = {
    "redirect": ["OpenID4VPHandover", sha256(enc([client_id, nonce, jwk_thumb, response_uri]))],
    "dcapi":    ["OpenID4VPDCAPIHandover", sha256(enc([origin, nonce, jwk_thumb]))],
}
session_inputs = {
    "redirect": {"client_id": client_id, "nonce": nonce, "jwk_thumbprint": H(jwk_thumb), "response_uri": response_uri},
    "dcapi": {"origin": origin, "nonce": nonce, "jwk_thumbprint": H(jwk_thumb)},
}

# ---------------------------------------------------------------- expected pseudonyms (prf sha-256, ver 1)
def nym(config, seed, prover_input, verifier_input):
    return sha256(f"nym_auth/v1/{config}".encode() + seed + prover_input + verifier_input)
Z = bytes(32)
verifier_id, verifier_context, user_value = client_id, "account-42", "my-linking-secret"
vi = sha256(verifier_id.encode())

# ---------------------------------------------------------------- age ranges (rulebook age_check)
import re
import calendar
PROOF_TIME = "2026-10-27T12:00:00Z"           # inside the MSO validity window

def _latest_on_or_before(y, m, d):            # (y, m, d) may be no calendar date: only (y, 2, 29) in a non-leap year
    return dt.date(y, m, d) if (m, d) != (2, 29) or calendar.isleap(y) else dt.date(y, 2, 28)

def _earliest_after(y, m, d):
    return dt.date(y, m, d) + dt.timedelta(days=1) if (m, d) != (2, 29) or calendar.isleap(y) else dt.date(y, 3, 1)

def age_bounds(D, rng):
    """E and C for a range at date D (dt.date); None for a missing bound."""
    m = re.fullmatch(r"(\d+)-(\d+)|(\d+)\+|(\d+)-", rng)
    if not m:
        raise ValueError("bad range")
    if m.group(1) is not None:
        A, B = int(m.group(1)), int(m.group(2))
        if A > B:
            raise ValueError("A > B")
    elif m.group(3) is not None:
        A, B = int(m.group(3)), None
    else:
        A, B = None, int(m.group(4))
    C = _latest_on_or_before(D.year - A, D.month, D.day) if A is not None else None
    E = _earliest_after(D.year - (B + 1), D.month, D.day) if B is not None else None
    return E, C

def age_case(D, rng):
    E, C = age_bounds(D, rng)
    bd = dt.date.fromisoformat(birth_date)
    return {"range": rng, "E": E.isoformat() if E else None, "C": C.isoformat() if C else None,
            "holds": (E is None or E <= bd) and (C is None or bd <= C)}

D_PROOF = dt.date.fromisoformat(PROOF_TIME[:10])
AGE_CHECK = {
    "proof_time": PROOF_TIME, "D": D_PROOF.isoformat(), "birth_date": birth_date,
    "cases": [age_case(D_PROOF, r) for r in ["13-17", "16-16", "16+", "16-", "17+", "12-15", "18+"]],
}
RANGE_CONVERSION = [dict(D=D.isoformat(), range=r, **{k: (v.isoformat() if v else None)
                         for k, v in zip(("E", "C"), age_bounds(D, r))})
                    for D, r in [(dt.date(2026, 10, 20), "13-17"), (dt.date(2026, 10, 9), "13-17"),
                                 (dt.date(2028, 2, 29), "13+"), (dt.date(2028, 2, 29), "17-"),
                                 (dt.date(2027, 3, 1), "15-15"), (dt.date(2027, 2, 28), "0-0")]]

def build(sfx, psc, has_private_seed):
    # IssuerSignedItems: bsc at digestID 0, psc at digestID 1; keys digestID, random, elementIdentifier, elementValue
    items, item_bytes, digests = [], [], {}
    for i, (ident, val) in enumerate([("bsc", bsc), ("psc", psc)]):
        rnd = sha256(b"nym_auth TEST random " + sfx.encode() + bytes([i]))[:16]
        t = tag24({"digestID": i, "random": rnd, "elementIdentifier": ident, "elementValue": val})
        items.append(t); item_bytes.append(enc(t)); digests[i] = sha256(enc(t))
    # MSO in the compact-profile key order
    mso = {
        "version": "1.0",
        "digestAlgorithm": "SHA-256",
        "docType": DOCTYPE,
        "valueDigests": {NS: digests},
        "deviceKeyInfo": {"deviceKey": {1: 2, -1: 1, -2: dx, -3: dy}},
        "validityInfo": {"signed": tdate(SIGNED), "validFrom": tdate(SIGNED), "validUntil": tdate(VALID_UNTIL)},
    }
    mso_bytes = enc(tag24(mso))
    issuer_auth, issuer_tbs = cose_sign1(ds_key, {1: -7}, {33: ds_der}, mso_bytes)
    issuer_signed = {"nameSpaces": {NS: items}, "issuerAuth": issuer_auth}

    sessions = {}
    device_ns_bytes = tag24({})
    for ch, ho in handovers.items():
        st = [None, None, ho]
        da_bytes = enc(tag24(["DeviceAuthentication", st, DOCTYPE, device_ns_bytes]))
        dev_sig, dev_tbs = cose_sign1(dev_key, {1: -7}, {}, da_bytes, detached=True)
        doc = {"docType": DOCTYPE, "issuerSigned": issuer_signed,
               "deviceSigned": {"nameSpaces": device_ns_bytes, "deviceAuth": {"deviceSignature": dev_sig}}}
        resp = enc({"version": "1.0", "documents": [doc], "status": 0})
        (OUT / f"device_response_{ch}{sfx}.cbor").write_bytes(resp)
        sessions[ch] = {"inputs": session_inputs[ch], "handover_hash": H(ho[1]), "session_transcript": H(enc(st)),
                        "device_authentication_bytes_tag24": H(da_bytes), "device_sig_structure": H(dev_tbs),
                        "device_signature_r_s": H(dev_sig[3]), "device_response": H(resp)}
    (OUT / f"issuer_signed{sfx}.cbor").write_bytes(enc(issuer_signed))
    (OUT / f"mso{sfx}.cbor").write_bytes(enc(mso))

    # byte offsets of the per-holder fields inside the issuerAuth Sig_structure and inside each item
    off = lambda hay, needle: hay.index(needle)
    layout = {
        "sig_structure_length": len(issuer_tbs),
        "sig_structure_sha256_blocks": (len(issuer_tbs) + 9 + 63) // 64,
        "sig_structure_offsets": {
            "digest_bsc": off(issuer_tbs, digests[0]), "digest_psc": off(issuer_tbs, digests[1]),
            "device_key_x": off(issuer_tbs, dx), "device_key_y": off(issuer_tbs, dy),
            "validity_signed": off(issuer_tbs, b"\xc0\x74" + SIGNED.encode()) + 2,
            "validity_valid_until": off(issuer_tbs, b"\xc0\x74" + VALID_UNTIL.encode()) + 2,
        },
        "issuer_signed_item_length": len(item_bytes[0]),
        "issuer_signed_item_offsets": {
            "random": off(item_bytes[0], cbor2.loads(items[0].value)["random"]),
            "element_value": off(item_bytes[0], bsc),
        },
    }
    pseudonyms = {
        "known-offender-matching-ssc": H(nym("known-offender-matching-ssc", secret_seed, Z, vi)),
        "known-offender-matching-psc": (H(nym("known-offender-matching-psc", private_seed, Z, vi)) if has_private_seed
                                        else "unsatisfiable: psc is 32 zero bytes"),
        "account-recovery-ssc": H(nym("account-recovery-ssc", secret_seed, Z, sha256(vi + sha256(verifier_context.encode())))),
        "user-managed-pseudonym-xsite-ssc": H(nym("user-managed-pseudonym-xsite-ssc", secret_seed, sha256(user_value.encode()), Z)),
    }
    priv_hex = lambda k: k.private_numbers().private_value.to_bytes(32, "big").hex()
    vec = {
        "_comment": ("TEST ONLY. nym_auth mso_mdoc fixture, compact profile (bsc at digestID 0, psc at 1, fixed key orders). "
                     "All keys derive from public labels." + ("" if has_private_seed else " Variant: psc is 32 zero bytes.")),
        "holder_openings": {"secret_seed": H(secret_seed), "birth_date": birth_date, "birth_date_utf8": H(birth_date.encode()),
                            "private_seed": H(private_seed) if has_private_seed else None},
        "commitments": {"bsc": H(bsc), "bsc_input": H(secret_seed + birth_date.encode()), "psc": H(psc)},
        "issuer_signed_items": [{"elementIdentifier": i, "digestID": n, "item_bytes_tag24": H(b), "digest": H(digests[n])}
                                for n, (i, b) in enumerate(zip(["bsc", "psc"], item_bytes))],
        "mso": {"mobile_security_object_bytes_tag24": H(mso_bytes), "mso_untagged": H(enc(mso)),
                "validity": {"signed": SIGNED, "validFrom": SIGNED, "validUntil": VALID_UNTIL}},
        "issuer_auth": {"alg": "ES256", "protected": H(issuer_auth[0]), "sig_structure": H(issuer_tbs),
                        "signature_r_s": H(issuer_auth[3])},
        "layout": layout,
        "issuer_signed_cbor": H(enc(issuer_signed)),
        "keys": {"document_signer": {"x": H(ix), "y": H(iy), "d": priv_hex(ds_key), "cert_der": H(ds_der)},
                 "iaca": {"d": priv_hex(iaca_key), "cert_der": H(iaca_der)},
                 "device": {"x": H(dx), "y": H(dy), "d": priv_hex(dev_key)}},
        "sessions": sessions,
        "expected": {
            "age_check": AGE_CHECK,
            "range_conversion": RANGE_CONVERSION,
            "pseudonym_inputs": {"verifier_id": verifier_id, "verifier_input_sha256": H(vi),
                                 "verifier_context": verifier_context, "user_supplied_value": user_value},
            "pseudonyms_sha256": pseudonyms,
        },
    }
    (OUT / f"nym_auth_test_vectors{sfx}.json").write_text(json.dumps(vec, indent=2) + "\n")

build("", sha256(private_seed), True)
build("_zero_psc", bytes(32), False)
print("wrote", sorted(p.name for p in OUT.iterdir()))
