from .proto import EnclaveEndorsement, EnclaveEndorsements

from typing import Optional
from cryptography import x509
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import datetime

__all__ = ["Auth"]

PKey = rsa.RSAPrivateKey;

class Auth:
    """
    This class wraps the certificate used to identify a user and implements the
    signing of the messages that are sent to the enclave
    """

    _endorsements: EnclaveEndorsements

    def __init__(
            self,
            certificate_chain: bytes,
            keypair: PKey,
            user_id: str,
    ):
        """
        Create an authentication object with the supplied certificate chain and
        keypair. To authenticate to the platform, you must create an auth object
        with `decentriq_platform.Client.create_auth`, retrieve the necessary endorsements
        e.g., with `decentriq_platform.Endorser.get_decentriq_pki_endorsement` and 
        attach the endorsement to your auth object with 
        `decentriq_platform.authentication.Auth.attach_endorsement`.
        """
        self.certificate_chain = certificate_chain
        self.kp = keypair
        self.user_id = user_id
        self._endorsements = EnclaveEndorsements()

    def _get_user_id(self) -> str:
        return self.user_id

    def _sign(self, data: bytes) -> bytes:
        return self.kp.sign(data, padding.PKCS1v15(), hashes.SHA512())

    def get_certificate_chain_pem(self) -> bytes:
        """
        Returns the chain of certificates in PEM format
        """
        return self.certificate_chain

    @property
    def endorsements(self) -> EnclaveEndorsements:
        return self._endorsements

    def attach_endorsement(
            self,
            /,
            decentriq_pki: Optional[EnclaveEndorsement] = None,
            personal_pki: Optional[EnclaveEndorsement] = None,
            dcr_secret: Optional[EnclaveEndorsement] = None
    ):
        if decentriq_pki:
            self._endorsements.dqPki.CopyFrom(decentriq_pki)
        if personal_pki:
            self._endorsements.personalPki.CopyFrom(personal_pki)
        if dcr_secret:
            self._endorsements.dcrSecret.CopyFrom(dcr_secret)
    
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

def generate_self_signed_certificate(user_email: str, key: PKey) -> bytes:
    cert_builder = x509.CertificateBuilder()
    now = datetime.datetime.utcnow()
    cert: Certificate = cert_builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, user_email)])
    ).issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, user_email)]) 
    ).serial_number(1
    ).not_valid_before(
        now - datetime.timedelta(days=1)
    ).not_valid_after(
        now + datetime.timedelta(days=10)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).public_key(key.public_key()
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
    return cert.public_bytes(serialization.Encoding.PEM)

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
