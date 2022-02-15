from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

__all__ = ["Auth"]

PKey = rsa.RSAPrivateKey;

class Auth:
    """
    This class wraps the certificate used to identify a user and implements the
    signing of the messages that are sent to the enclave
    """
    def __init__(
            self,
            certificate_chain: bytes,
            keypair: PKey,
            user_id: str,
    ):
        """
        Create an authentication object with the supplied certificate chain and
        keypair. To use the identity provider of the decentriq platform use
        `decentriq_platform.Client.create_auth`
        """
        self.certificate_chain = certificate_chain
        self.kp = keypair
        self.user_id = user_id

    def _get_user_id(self) -> str:
        return self.user_id

    def _sign(self, data: bytes) -> bytes:
        return self.kp.sign(data, padding.PKCS1v15(), hashes.SHA512())

    def get_certificate_chain_pem(self) -> bytes:
        """
        Returns the chain of certificates in PEM format
        """
        return self.certificate_chain

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
