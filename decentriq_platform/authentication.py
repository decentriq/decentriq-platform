from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization

PKey = rsa.RSAPrivateKey;

class Auth:
    def __init__(self, certificate_chain: bytes, keypair: PKey, user_id: str, access_token: str = None):
        self.certificate_chain: bytes = certificate_chain
        self.kp: PKey = keypair
        self.user_id: str = user_id
        self.access_token: str = access_token

    def get_user_id(self) -> str:
        return self.user_id

    def get_access_token(self) -> str:
        return self.access_token

    def get_certificate_chain_pem(self) -> bytes:
        return self.certificate_chain

    def sign(self, data: bytes) -> bytes:
        return self.kp.sign(data, padding.PKCS1v15(), hashes.SHA512())


class Sigma:
    def __init__(self, signature: bytes, mac_tag: bytes, auth_pki: Auth):
        self.signature: bytes = signature
        self.mac_tag: bytes = mac_tag
        self.auth_pki: Auth = auth_pki

    def get_mac_tag(self) -> bytes:
        return self.mac_tag

    def get_signature(self) -> bytes:
        return self.signature

    def get_cert_chain(self) -> bytes:
        return self.auth_pki.get_certificate_chain_pem()


def generate_key(bit_size: int = 4096) -> PKey:
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bit_size,
    )
    return key


def generate_csr(user_email: str, key: PKey) -> bytes:
    csr_builder = x509.CertificateSigningRequestBuilder()
    csr = csr_builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, user_email)
    ])).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    ).sign(key, hashes.SHA512())
    return csr.public_bytes(serialization.Encoding.PEM)
