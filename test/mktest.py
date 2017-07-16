import subprocess
import struct
import hashlib
from os import path

SIGALG_ECDSA_SHA256 = 0x0403
SIGALG_ECDSA_SHA384 = 0x0503
SIGALG_RSA_SHA256 = 0x0401

SIGALG_HASH = {
    SIGALG_RSA_SHA256: 'sha256',
    SIGALG_ECDSA_SHA256: 'sha256',
    SIGALG_ECDSA_SHA384: 'sha384',
}

class SCT(object):
    def __init__(self):
        self.version = 0
        self.type = 0
        self.id = '\x11\x22\x33\x44' * 8
        self.timestamp = 1234
        self.enttype = 0
        self.exts = '\x00\x00'
        self.sig = 0

    def sign(self, key, alg, cert):
        to_sign = struct.pack('!BBQHBH', self.version, self.type, self.timestamp, self.enttype, 0, len(cert)) \
                + cert + self.exts

        sig = subprocess.check_output(['openssl', 'dgst', '-' + SIGALG_HASH[alg], '-sign', key, 'sigin.bin'])
        self.sig = struct.pack('!HH', alg, len(sig)) + sig

    def encode(self):
        return struct.pack('!B32sQ', self.version, self.id, self.timestamp) + self.exts + self.sig

def genrsa(len):
    priv, pub = 'rsa-%d-priv.pem' % len, 'rsa-%d-pub.pem' % len
    if not path.exists(pub):
        subprocess.check_call(['openssl', 'genrsa', '-out', priv, str(len)])
        subprocess.check_call(['openssl', 'rsa', '-in', priv, '-pubout', '-out', pub])
    return priv, pub

def genecdsa(curve):
    priv, pub = 'ecdsa-%s-priv.pem' % curve, 'ecdsa-%s-pub.pem' % curve
    if not path.exists(pub):
        subprocess.check_call(['openssl', 'ecparam', '-genkey', '-name', curve, '-out', priv])
        subprocess.check_call(['openssl', 'ec', '-in', priv, '-pubout', '-out', pub])
    return priv, pub

def convert_der(pub):
    der = pub.replace('.pem', '.der')
    subprocess.check_call(['openssl', 'asn1parse', '-in', pub, '-out', der], stdout = subprocess.PIPE)
    return der

def keyhash(pub):
    der = convert_der(pub)
    return hashlib.sha256(open(der).read()).digest()

def raw_public_key(spki):
    def take_byte(b):
        return ord(b[0]), b[1:]

    def take_len(b):
        v, b = take_byte(b)

        if v & 0x80:
            r = 0
            for _ in range(v & 3):
                x, b = take_byte(b)
                r <<= 8
                r |= x
            return r, b

        return v, b

    def take_seq(b):
        tag, b = take_byte(b)
        ll, b = take_len(b)
        assert tag == 0x30
        return b[:ll], b[ll:]

    def take_bitstring(b):
        tag, b = take_byte(b)
        ll, b = take_len(b)
        bits, b = take_byte(b)
        assert tag == 0x03
        assert bits == 0
        return b[:ll-1], b[ll-1:]

    spki, rest = take_seq(spki)
    assert rest == ''
    id, data = take_seq(spki)
    keydata, rest = take_bitstring(data)
    assert rest == ''
    return keydata

def format_bytes(b):
    return ', '.join(map(lambda x: '0x%02x' % ord(x), b))

keys = [
    ('rsa2048', genrsa(2048)),
    ('rsa3072', genrsa(3072)),
    ('rsa4096', genrsa(4096)),
    ('ecdsa_p256', genecdsa('prime256v1')),
    ('ecdsa_p384', genecdsa('secp384r1')),
]

algs = dict(
        rsa2048 = SIGALG_RSA_SHA256,
        rsa3072 = SIGALG_RSA_SHA256,
        rsa4096 = SIGALG_RSA_SHA256,
        ecdsa_p256 = SIGALG_ECDSA_SHA256,
        ecdsa_p384 = SIGALG_ECDSA_SHA384
        )

print 'use super::{Log, verify_sct};'
print

for name, (priv, pub) in keys:
    pubder = convert_der(pub)
    pubraw = pubder.replace('.der', '.raw')
    open(pubraw, 'w').write(raw_public_key(open(pubder).read()))

    print """static TEST_LOG_%s: Log = Log {
    description: "fake test %s log",
    url: "",
    operated_by: "random python script",
    max_merge_delay: 0,
    key: include_bytes!("testdata/%s"),
    id: [%s],
};
""" % (name.upper(),
        name,
        pubraw,
        format_bytes(keyhash(pub)))

for name, (priv, pub) in keys:
    sct = SCT()
    sct.sign(priv, algs[name], 'cert')
    sct.id = keyhash(pub)

    open('%s-basic-sct.bin' % name, 'w').write(sct.encode())

    print """#[test]
pub fn test_basic_%s() {
    let sct = include_bytes!("testdata/%s-basic-sct.bin");
    let cert = b"cert";
    let logs = [&TEST_LOG_%s];
    let now = 1235;
    
    assert_eq!(0,
               verify_sct(cert, sct, now, &logs).unwrap());
}
""" % (name, name, name.upper())
