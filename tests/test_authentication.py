import os
from OpenSSL.crypto import verify, load_certificate, FILETYPE_PEM

from avato.authentication import Pki
from avato.client import Client

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, "fixtures")
user_email = os.environ["TEST_USER_ID_1"]

client = Client(
    api_token=os.environ["TEST_API_TOKEN_1"],
    instance_types=[],
)


def test_auth_complete():
    user_pki_auth: Pki = client.get_user_pki_authenticator(user_email)
    message: bytes = b"Hello Bob, this is Alice."
    signature: bytes = user_pki_auth.sign(message)
    certificate = load_certificate(FILETYPE_PEM, user_pki_auth.get_certificate_chain_pem())
    assert verify(certificate, signature, message, Pki.DIGEST_ALGO) is None
