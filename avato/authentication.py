from OpenSSL import crypto
from OpenSSL.crypto import PKey, X509Req, sign


class Pki:
    DIGEST_ALGO = "sha512"

    def __init__(self, certificate_chain: bytes, keypair: PKey, user_id: str):
        if keypair.check():
            self.certificate_chain: bytes = certificate_chain
            self.kp: PKey = keypair
            self.user_id: str = user_id

    def get_keypair(self) -> PKey:
        return self.kp

    def get_user_id(self) -> str:
        return self.user_id

    def get_certificate_chain_pem(self) -> bytes:
        return self.certificate_chain

    def sign(self, data: bytes) -> bytes:
        return sign(self.kp, data, self.DIGEST_ALGO)


class Sigma:
    DIGEST_ALGO = "sha512"

    def __init__(self, signature: bytes, mac_tag: bytes, pki: Pki):
        self.signature: bytes = signature
        self.mac_tag: bytes = mac_tag
        self.auth_pki: Pki = pki

    def get_mac_tag(self) -> bytes:
        return self.mac_tag

    def get_signature(self) -> bytes:
        return self.signature

    def get_cert_chain(self) -> bytes:
        return self.auth_pki.get_certificate_chain_pem()


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
    req.sign(key, "sha512")
    return req
