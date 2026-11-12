#!/usr/bin/env python3
"""Independent check of the generated fixtures: parses only the output files, recomputes everything,
and checks the compact-profile rules (rulebook v0.4 on fix-birthdate: bsc + psc, fixed key orders)."""
import hashlib, json, pathlib, re, sys
import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

D = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
sha = lambda b: hashlib.sha256(b).digest()
NS = "eu.europa.ec.eudi.nym_auth.1"
MSO_KEYS = ["version", "digestAlgorithm", "docType", "valueDigests", "deviceKeyInfo", "validityInfo"]
ITEM_KEYS = ["digestID", "random", "elementIdentifier", "elementValue"]
res = []
def ok(c, m):
    print(("PASS " if c else "FAIL ") + m); res.append(bool(c))

def verify(pub, sig, data):
    try:
        pub.verify(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")), data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

iaca = x509.load_der_x509_certificate((D / "iaca.der").read_bytes())
sig_structures = {}
for sfx in ("", "_zero_psc"):
    V = json.loads((D / f"nym_auth_test_vectors{sfx}.json").read_text())
    tag = sfx or "_with_psc"
    for ch in ("redirect", "dcapi"):
        p = f"[{tag[1:]}/{ch}]"
        raw = (D / f"device_response_{ch}{sfx}.cbor").read_bytes()
        resp = cbor2.loads(raw)
        ok(cbor2.dumps(resp) == raw, f"{p} DeviceResponse re-encodes byte-identically")
        doc = resp["documents"][0]; isd = doc["issuerSigned"]
        prot, unprot, payload, sig = isd["issuerAuth"]
        ok(prot == bytes.fromhex("a10126"), f"{p} protected header is exactly {{1: -7}}")
        ds = x509.load_der_x509_certificate(unprot[33])
        try:
            iaca.public_key().verify(ds.signature, ds.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256())); chained = True
        except Exception:
            chained = False
        ok(chained, f"{p} DS cert in x5chain (label 33) chains to IACA")
        tbs = cbor2.dumps(["Signature1", prot, b"", payload])
        ok(verify(ds.public_key(), sig, tbs), f"{p} issuerAuth signature")
        if ch == "redirect":
            sig_structures[tag] = tbs
        mso_tag = cbor2.loads(payload); mso = cbor2.loads(mso_tag.value)
        ok(mso_tag.tag == 24 and list(mso) == MSO_KEYS, f"{p} MSO keys exactly {MSO_KEYS}")
        ok(mso["version"] == "1.0" and mso["digestAlgorithm"] == "SHA-256" and mso["docType"] == NS == doc["docType"], f"{p} version/digestAlgorithm/docType")
        ok(list(mso["valueDigests"]) == [NS] and list(mso["valueDigests"][NS]) == [0, 1], f"{p} valueDigests: only nym_auth namespace, digestIDs 0,1")
        ok(list(mso["deviceKeyInfo"]) == ["deviceKey"], f"{p} deviceKeyInfo contains only deviceKey")
        ck = mso["deviceKeyInfo"]["deviceKey"]
        ok(list(ck) == [1, -1, -2, -3] and ck[1] == 2 and ck[-1] == 1 and all(isinstance(ck[k], bytes) and len(ck[k]) == 32 for k in (-2, -3)),
           f"{p} deviceKey entries exactly 1,-1,-2,-3; uncompressed 32-byte x and y")
        ok(list(mso["validityInfo"]) == ["signed", "validFrom", "validUntil"], f"{p} validityInfo keys exactly signed, validFrom, validUntil")
        ok(len(re.findall(rb"\xc0\x74\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", mso_tag.value)) == 3, f"{p} validityInfo values are tag-0 YYYY-MM-DDTHH:MM:SSZ")
        vals = {}
        for n, it_tag in enumerate(isd["nameSpaces"][NS]):
            ib = cbor2.dumps(it_tag); it = cbor2.loads(it_tag.value)
            ok(list(it) == ITEM_KEYS and it["digestID"] == n and len(it["random"]) == 16 and isinstance(it["elementValue"], bytes)
               and len(it["elementValue"]) == 32 and len(ib) == 108 and mso["valueDigests"][NS][n] == sha(ib),
               f"{p} item {it['elementIdentifier']}: key order, digestID {n}, 16-byte random, 32-byte value, 108 bytes, digest in MSO")
            vals[it["elementIdentifier"]] = it["elementValue"]
        ok(list(vals) == ["bsc", "psc"], f"{p} data elements are exactly bsc, psc (no ssc, no birth_date)")
        h = V["holder_openings"]; seed = bytes.fromhex(h["secret_seed"]); bd = h["birth_date"]
        ok(len(bd.encode()) == 10 and vals["bsc"] == sha(seed + bd.encode()), f"{p} bsc == SHA-256(secret_seed || birth_date), 26-byte input")
        if h["private_seed"] is None:
            ok(vals["psc"] == bytes(32), f"{p} psc is 32 zero bytes; no private_seed held")
        else:
            ok(vals["psc"] == sha(bytes.fromhex(h["private_seed"])), f"{p} psc == SHA-256(private_seed)")
        dev_pub = ec.EllipticCurvePublicNumbers(int.from_bytes(ck[-2], "big"), int.from_bytes(ck[-3], "big"), ec.SECP256R1()).public_key()
        # rebuild the SessionTranscript from the rulebook's rules, not from the vectors
        s = V["sessions"][ch]["inputs"]; jt = bytes.fromhex(s["jwk_thumbprint"])
        jwk = '{"crv":"P-256","kty":"EC","x":"TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc","y":"ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ"}'
        ok(jt == sha(jwk.encode()), f"{p} jwkThumbprint is RFC 7638 of the example enc key")
        ho = (["OpenID4VPHandover", sha(cbor2.dumps([s["client_id"], s["nonce"], jt, s["response_uri"]]))] if ch == "redirect"
              else ["OpenID4VPDCAPIHandover", sha(cbor2.dumps([s["origin"], s["nonce"], jt]))])
        dsn = doc["deviceSigned"]
        da = cbor2.dumps(cbor2.CBORTag(24, cbor2.dumps(["DeviceAuthentication", [None, None, ho], NS, dsn["nameSpaces"]])))
        dprot, _, dpayload, dsig = dsn["deviceAuth"]["deviceSignature"]
        ok(dpayload is None and verify(dev_pub, dsig, cbor2.dumps(["Signature1", dprot, b"", da])), f"{p} device signature over DeviceAuthentication (detached)")
    L = V["layout"]
    ok(L["sig_structure_offsets"]["digest_bsc"] == 148, f"[{tag[1:]}] first per-holder byte (bsc digest) at Sig_structure offset 148")

a, b = sig_structures["_with_psc"], sig_structures["_zero_psc"]
ok(len(a) == len(b), f"[layout] both variants have the same Sig_structure length ({len(a)} bytes, {(len(a) + 72) // 64} SHA-256 blocks)")
ok(a[:148] == b[:148], "[layout] first 148 bytes identical across variants (2 SHA-256 blocks precomputable)")
# ---------------------------------------------------------------- age ranges: independent E/C conversion
import datetime as dt
def subtract_years(D, n):
    """D minus n years as (y, m, d); may be no calendar date."""
    return (D.year - n, D.month, D.day)
def is_date(t):
    try: dt.date(*t); return True
    except ValueError: return False
def bounds(D, rng):
    m = re.fullmatch(r"(\d+)(-(\d+)|\+|-)", rng)
    assert m, rng
    a, tail, b = int(m.group(1)), m.group(2), m.group(3)
    A, B = (a, int(b)) if b is not None else ((a, None) if tail == "+" else (None, a))
    C = E = None
    if A is not None:   # latest calendar date on or before D - A years
        t = subtract_years(D, A); C = dt.date(*t) if is_date(t) else dt.date(t[0], t[1], t[2] - 1)
    if B is not None:   # earliest calendar date after D - (B+1) years
        t = subtract_years(D, B + 1); E = dt.date(*t) + dt.timedelta(days=1) if is_date(t) else dt.date(t[0], 3, 1)
    return E, C
iso = lambda d: d.isoformat() if d else None

for sfx in ("", "_zero_psc"):
    V = json.loads((D / f"nym_auth_test_vectors{sfx}.json").read_text())
    A_ = V["expected"]["age_check"]; pt = A_["proof_time"]; Dd = dt.date.fromisoformat(pt[:10])
    vi = V["mso"]["validity"]
    ok(vi["validFrom"] <= pt <= vi["validUntil"] and A_["D"] == Dd.isoformat(), f"[age{sfx}] validFrom <= proof_time <= validUntil; D is its UTC date")
    bd = V["holder_openings"]["birth_date"]
    for c in A_["cases"]:
        E, C = bounds(Dd, c["range"])
        holds = (E is None or iso(E) <= bd) and (C is None or bd <= iso(C))
        as_int = lambda s: int.from_bytes(s.encode(), "big")          # the circuit's 80-bit comparison
        holds_int = (E is None or as_int(iso(E)) <= as_int(bd)) and (C is None or as_int(bd) <= as_int(iso(C)))
        ok([iso(E), iso(C)] == [c["E"], c["C"]] and holds == holds_int == c["holds"],
           f"[age{sfx}] range {c['range']} at D={Dd}: E={c['E']} C={c['C']} holds={c['holds']}")
    for r in V["expected"]["range_conversion"]:
        E, C = bounds(dt.date.fromisoformat(r["D"]), r["range"])
        ok([iso(E), iso(C)] == [r["E"], r["C"]], f"[age{sfx}] conversion {r['range']} at D={r['D']}: E={r['E']} C={r['C']}")

print(f"\n{sum(res)}/{len(res)} checks passed"); sys.exit(0 if all(res) else 1)
