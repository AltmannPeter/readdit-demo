# TEST ONLY. Issues nym_auth rulebook v0.7 mdoc credentials (INTEGRATION.md §5) with the rulebook
# v0.5 test vectors' TEST Document Signer and device keys, for holders A (the vectors' holder), A0
# (the same with a zero psc), B, C, D and E (edges: see README.md; E has its own TEST device key
# with an odd y).
#
#   python3 issue_v07.py nym_auth_test_vectors.json OUT_DIR
#
# Writes OUT_DIR/v07_<holder>.cbor and OUT_DIR/holders.json. ECDSA signatures are randomized, so
# a new run gives other bytes (and the same layout). Needs: cbor2, cryptography.
import json, sys, hashlib, cbor2, os
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

vec_path, out_dir = sys.argv[1:3]
v = json.load(open(vec_path))
H = lambda b: hashlib.sha256(b).digest()
DT = "eu.europa.ec.eudi.nym_auth.1"
NS = "eu.nym_auth.v1"
DST = b"nym_auth/v1/aes-128/known-offender-matching-ssc"
ds = v['keys']['document_signer']; dev = v['keys']['device']
ds_sk = ec.derive_private_key(int(ds['d'], 16), ec.SECP256R1())
dev_sk = ec.derive_private_key(int(dev['d'], 16), ec.SECP256R1())
cert = bytes.fromhex(ds['cert_der'])

def aes(key, block):
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(block) + e.finalize()

def bsc_of(secret_seed, birth_date):
    """bsc = AES-128(secret_seed, "nym/b" || 01 || birth_date) || AES-128(secret_seed, "nym/b" || 02 || 0^10)"""
    return aes(secret_seed, b"nym/b\x01" + birth_date.encode()) + aes(secret_seed, b"nym/b\x02" + bytes(10))

def psc_of(private_seed):
    """psc = AES-128(private_seed, "nym/p" || 01 || 0^10) || AES-128(private_seed, "nym/p" || 02 || 0^10)"""
    return aes(private_seed, b"nym/p\x01" + bytes(10)) + aes(private_seed, b"nym/p\x02" + bytes(10))

def pseudonym(secret_seed, verifier_id):
    """known-offender-matching-ssc, prf aes-128: AES-128(seed, H[0..16]) || AES-128(seed, H[16..32])"""
    h = H(DST + bytes(32) + H(verifier_id.encode()))
    return aes(secret_seed, h[:16]) + aes(secret_seed, h[16:])

def tstr(s):
    s = s.encode()
    return (bytes([0x60 + len(s)]) if len(s) < 24 else bytes([0x78, len(s)])) + s

def mso_bytes(bsc, psc, x, odd, signed, vf, vu):
    m = (b'\xa6' + tstr('version') + tstr('1.0') + tstr('digestAlgorithm') + tstr('SHA-256') + tstr('docType') + tstr(DT)
         + tstr('valueDigests') + b'\xa1' + tstr(NS) + b'\xa2' + b'\x00\x58\x20' + bsc + b'\x01\x58\x20' + psc
         + tstr('deviceKeyInfo') + b'\xa1' + tstr('deviceKey') + b'\xa4\x01\x02\x20\x01' + b'\x21\x58\x20' + x
         + b'\x22' + (b'\xf5' if odd else b'\xf4')
         + tstr('validityInfo') + b'\xa3' + tstr('signed') + b'\xc0\x74' + signed.encode() + tstr('validFrom') + b'\xc0\x74' + vf.encode()
         + tstr('validUntil') + b'\xc0\x74' + vu.encode())
    assert len(m) == 350, len(m)
    return m

def credential(bsc, psc, x, odd, signed, vf, vu):
    mso = mso_bytes(bsc, psc, x, odd, signed, vf, vu)
    payload = b'\xd8\x18\x59' + len(mso).to_bytes(2, 'big') + mso
    sig_structure = b'\x84' + tstr('Signature1') + b'\x43\xa1\x01\x26' + b'\x40' + b'\x59' + len(payload).to_bytes(2, 'big') + payload
    assert len(sig_structure) == 375
    r, s = utils.decode_dss_signature(ds_sk.sign(sig_structure, ec.ECDSA(hashes.SHA256())))
    sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    xh = (b'\x59' + len(cert).to_bytes(2, 'big')) if len(cert) >= 256 else (b'\x58' + bytes([len(cert)]))
    cred = (b'\xa1' + tstr('issuerAuth') + b'\x84' + b'\x43\xa1\x01\x26' + b'\xa1\x18\x21' + xh + cert
            + b'\x59' + len(payload).to_bytes(2, 'big') + payload + b'\x58\x40' + sig)
    assert cbor2.loads(cred)['issuerAuth'][2] == payload
    return cred, sig_structure

def xy(sk):
    n = sk.public_key().public_numbers()
    return n.x.to_bytes(32, 'big'), n.y.to_bytes(32, 'big')

x, y = xy(dev_sk)
assert x.hex() == dev['x'] and y.hex() == dev['y']
# Holder E's TEST device key: the first d from 2 up whose public key has an odd y.
d = 2
while xy(ec.derive_private_key(d, ec.SECP256R1()))[1][-1] & 1 == 0:
    d += 1
dev_e = ec.derive_private_key(d, ec.SECP256R1())

ho = v['holder_openings']
seed_a = bytes.fromhex(ho['secret_seed'])
holders = {
  # name: (secret_seed, birth_date, psc, validFrom, validUntil, device key)
  'A': (seed_a, ho['birth_date'], psc_of(bytes.fromhex(ho['private_seed'])), '2026-10-27T00:00:00Z', '2027-10-27T00:00:00Z', dev_sk),
  'A0': (seed_a, ho['birth_date'], bytes(32), '2026-10-27T00:00:00Z', '2027-10-27T00:00:00Z', dev_sk),
  'B': (bytes(range(0x20, 0x30)), '2008-10-28', psc_of(bytes(range(0x40, 0x50))), '2026-10-27T12:00:00Z', '2026-10-27T12:00:00Z', dev_sk),
  'C': (bytes(range(0x50, 0x60)), '2000-02-29', psc_of(bytes(range(0x60, 0x70))), '2020-01-01T00:00:00Z', '2099-12-31T23:59:59Z', dev_sk),
  'D': (bytes([0xff] * 16), '2013-10-27', bytes(32), '2026-10-26T23:59:59Z', '2026-10-27T12:00:00Z', dev_sk),
  'E': (bytes(range(0x70, 0x80)), '1990-01-01', psc_of(bytes(range(0x80, 0x90))), '2026-10-27T00:00:00Z', '2027-10-27T00:00:00Z', dev_e),
}
verifier_id = v['expected']['pseudonym_inputs']['verifier_id']
os.makedirs(out_dir, exist_ok=True)
meta = {}
for name, (seed, birth, psc, vf, vu, dk) in holders.items():
    bsc = bsc_of(seed, birth); x, y = xy(dk); odd = bool(y[-1] & 1)
    cred, ss = credential(bsc, psc, x, odd, vf, vf, vu)
    open(os.path.join(out_dir, f'v07_{name}.cbor'), 'wb').write(cred)
    meta[name] = {'secret_seed': seed.hex(), 'birth_date': birth, 'bsc': bsc.hex(), 'psc': psc.hex(),
                  'valid_from': vf, 'valid_until': vu, 'device_x': x.hex(), 'device_y': y.hex(), 'device_sign': odd,
                  'e': H(ss).hex(), 'sig_structure': ss.hex(), 'pseudonym': pseudonym(seed, verifier_id).hex()}
    if dk is not dev_sk:
        meta[name]['device_d'] = dk.private_numbers().private_value.to_bytes(32, 'big').hex()
json.dump({'verifier_id': verifier_id, 'holders': meta}, open(os.path.join(out_dir, 'holders.json'), 'w'), indent=1)

# Self-check: the fields at the layout's offsets.
for name, m in meta.items():
    ss = bytes.fromhex(m['sig_structure'])
    assert ss[133:165].hex() == m['bsc'] and ss[168:200].hex() == m['psc'] and ss[233:265].hex() == m['device_x']
    assert ss[266] == (0xf5 if m['device_sign'] else 0xf4)
print('issued', ', '.join(meta))
