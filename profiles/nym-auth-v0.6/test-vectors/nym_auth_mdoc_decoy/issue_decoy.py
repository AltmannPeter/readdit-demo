# TEST ONLY. Issues nym_auth mdoc credentials in the decoy-digest layout (INTEGRATION.md §5) with the
# rulebook v0.5 test vectors' TEST Document Signer and device keys, for holders A (the vectors'
# holder), A0 (the same with a zero psc), B, C and D (edges: see README.md).
#
#   python3 issue_decoy.py nym_auth_test_vectors.json OUT_DIR
#
# Writes OUT_DIR/decoy_<holder>.cbor and OUT_DIR/holders.json. ECDSA signatures are randomized, so
# a new run gives other bytes (and the same layout). Needs: cbor2, cryptography.
import json, sys, hashlib, cbor2, os
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
vec_path, out_dir = sys.argv[1:3]
v = json.load(open(vec_path))
H = lambda b: hashlib.sha256(b).digest()
dt = "eu.europa.ec.eudi.nym_auth.1"
ds = v['keys']['document_signer']; dev = v['keys']['device']
ds_sk = ec.derive_private_key(int(ds['d'], 16), ec.SECP256R1())
dev_sk = ec.derive_private_key(int(dev['d'], 16), ec.SECP256R1())
cert = bytes.fromhex(ds['cert_der'])
def tstr(s):
    s = s.encode()
    return (bytes([0x60 + len(s)]) if len(s) < 24 else bytes([0x78, len(s)])) + s
def mso_bytes(bsc, psc, x, y, signed, vf, vu):
    m = (b'\xa6' + tstr('version') + tstr('1.0') + tstr('digestAlgorithm') + tstr('SHA-256') + tstr('docType') + tstr(dt)
         + tstr('valueDigests') + b'\xa1' + tstr(dt) + b'\xa2' + b'\x00\x58\x20' + bsc + b'\x01\x58\x20' + psc
         + tstr('deviceKeyInfo') + b'\xa1' + tstr('deviceKey') + b'\xa4\x01\x02\x20\x01' + b'\x21\x58\x20' + x + b'\x22\x58\x20' + y
         + tstr('validityInfo') + b'\xa3' + tstr('signed') + b'\xc0\x74' + signed.encode() + tstr('validFrom') + b'\xc0\x74' + vf.encode()
         + tstr('validUntil') + b'\xc0\x74' + vu.encode())
    assert len(m) == 398, len(m)
    return m
def credential(bsc, psc, x, y, signed, vf, vu, key=ds_sk):
    mso = mso_bytes(bsc, psc, x, y, signed, vf, vu)
    payload = b'\xd8\x18\x59' + len(mso).to_bytes(2, 'big') + mso
    sig_structure = b'\x84' + tstr('Signature1') + b'\x43\xa1\x01\x26' + b'\x40' + b'\x59' + len(payload).to_bytes(2, 'big') + payload
    assert len(sig_structure) == 423
    der = key.sign(sig_structure, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    xh = (b'\x59' + len(cert).to_bytes(2, 'big')) if len(cert) >= 256 else (b'\x58' + bytes([len(cert)]))
    cred = (b'\xa1' + tstr('issuerAuth') + b'\x84' + b'\x43\xa1\x01\x26' + b'\xa1\x18\x21' + xh + cert
            + payload[:0] + b'\x59\x01\x93' + payload + b'\x58\x40' + sig)
    assert cbor2.loads(cred)['issuerAuth'][2] == payload
    return cred, sig_structure
pub = lambda sk: sk.public_key().public_numbers()
def xy(sk): n = pub(sk); return n.x.to_bytes(32, 'big'), n.y.to_bytes(32, 'big')
x, y = xy(dev_sk)
assert x.hex() == dev['x'] and y.hex() == dev['y']
ho = v['holder_openings']
holders = {
  # name: (secret_seed, birth_date, psc, validFrom, validUntil, device key)
  'A': (bytes.fromhex(ho['secret_seed']), ho['birth_date'], H(bytes.fromhex(ho['private_seed'])), '2026-10-27T00:00:00Z', '2027-10-27T00:00:00Z', dev_sk),
  'A0': (bytes.fromhex(ho['secret_seed']), ho['birth_date'], bytes(32), '2026-10-27T00:00:00Z', '2027-10-27T00:00:00Z', dev_sk),
  'B': (bytes(range(0x20, 0x30)), '2008-10-28', H(bytes(range(0x40, 0x50))), '2026-10-27T12:00:00Z', '2026-10-27T12:00:00Z', dev_sk),
  'C': (bytes(range(0x50, 0x60)), '2000-02-29', H(bytes(range(0x60, 0x70))), '2020-01-01T00:00:00Z', '2099-12-31T23:59:59Z', dev_sk),
  'D': (bytes([0xff] * 16), '2013-10-27', bytes(32), '2026-10-26T23:59:59Z', '2026-10-27T12:00:00Z', dev_sk),
}
meta = {}
for name, (seed, birth, psc, vf, vu, dk) in holders.items():
    bsc = H(seed + birth.encode()); x, y = xy(dk)
    cred, ss = credential(bsc, psc, x, y, vf, vf, vu)
    open(os.path.join(out_dir, f'decoy_{name}.cbor'), 'wb').write(cred)
    meta[name] = {'secret_seed': seed.hex(), 'birth_date': birth, 'bsc': bsc.hex(), 'psc': psc.hex(),
                  'valid_from': vf, 'valid_until': vu, 'e': H(ss).hex(), 'sig_structure': ss.hex()}
json.dump(meta, open(os.path.join(out_dir, 'holders.json'), 'w'), indent=1)

# Self-check: every credential parses into the template (constant bytes) with tdates of 20 characters.
for name, m in meta.items():
    ss = bytes.fromhex(m['sig_structure'])
    assert len(ss) == 423 and ss[148:180].hex() == m['bsc'] and ss[183:215].hex() == m['psc']
print('issued', ', '.join(meta))
