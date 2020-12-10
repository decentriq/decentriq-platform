from OpenSSL import crypto
from OpenSSL.crypto import PKey, X509Req, X509, sign, dump_certificate, FILETYPE_PEM


class Pki:
    DIGEST_ALGO = "sha512"

    def __init__(self, cert_chain_pem: bytes, keypair: PKey):
        if keypair.check():
            self.cert_chain_pem: bytes = cert_chain_pem
            self.keypair: PKey = keypair

    def get_certificate_chain_pem(self) -> bytes:
        return self.cert_chain_pem

    def sign(self, data: bytes) -> bytes:
        return sign(self.keypair, data, self.DIGEST_ALGO)


def generate_key(key_type=crypto.TYPE_RSA, bit_size=4096) -> PKey:
    key: PKey = crypto.PKey()
    key.generate_key(key_type, bit_size)
    return key


def generate_csr(user_email: str, key: PKey) -> X509Req:
    req: X509Req = crypto.X509Req()
    req.get_subject().CN = user_email
    base_constraints = ([
        crypto.X509Extension("keyUsage".encode('ascii'), False, "Digital Signature, Non Repudiation, Key Encipherment".encode('ascii')),
        crypto.X509Extension("basicConstraints".encode('ascii'), False, "CA:FALSE".encode('ascii')),
    ])
    req.add_extensions(base_constraints)
    req.set_pubkey(key)
    req.sign(key, "sha256")
    return req