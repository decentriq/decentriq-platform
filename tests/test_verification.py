import os
import pytest
from avato.verification import Verification, EnclaveQuoteFlagsError

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, "fixtures")

with open(os.path.join(fixtures_dir, "IAS_OK_DEBUG_EPID"), "rb") as f:
    certificate = f.read()
with open(os.path.join(fixtures_dir, "IAS_OK_RESPONSE"), "rb") as f:
    message = f.read()
with open(os.path.join(fixtures_dir, "IAS_OK_SIG"), "rb") as f:
    signature = f.read()


def test_verification():
    verification = Verification(accept_debug=True)
    verification.verify(certificate, message, signature)


def test_fail_without_debug_accept():
    with pytest.raises(EnclaveQuoteFlagsError):
        verification = Verification()
        verification.verify(certificate, message, signature)
