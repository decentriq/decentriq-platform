from sgx_ias_structs import QuoteBody as _QuoteBody
from asn1crypto import pem
from oscrypto import asymmetric
from certvalidator import CertificateValidator, ValidationContext
from enum import IntFlag
import json

intel_sgx_root_ca = b"""
-----BEGIN CERTIFICATE-----
MIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV
BAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0
YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy
MzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL
U2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD
DCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G
CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e
LmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh
rgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT
L/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe
NpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ
byinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H
afuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf
6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM
RoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX
MFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50
L0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW
BBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr
NXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq
hkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir
IEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ
sFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi
zLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra
Ud4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA
152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB
3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O
DD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv
DaVzWh5aiEx+idkSGMnX
-----END CERTIFICATE-----
"""

class QuoteBody:
    """Represents the body of the SGX IAS Quote"""

    def __init__(self, quote):
        if not isinstance(quote, _QuoteBody):
            raise Exception("QuoteBody must be converted from sgx_ias_structs repr.")
        self.version = quote.version
        self.sign_type = quote.sign_type
        self.qe_svn = quote.qe_svn
        self.pce_svn = quote.pce_svn
        self.xeid = quote.xeid
        self.epid_group_id = quote.epid_group_id
        self.basename = quote.basename
        self.reportdata = quote.reportdata
        self.cpusvn = quote.cpusvn
        self.mrenclave = quote.mrenclave
        self.mrsigner = quote.mrsigner
        self.isvprodid = quote.isvprodid
        self.isvsvn = quote.isvsvn
        self.flags = quote.flags

    def __str__(self):
        obj_dict = {
            k: bytes(v).hex() if isinstance(v, (list, bytes)) else v
            for (k, v) in self.__dict__.items()
        }
        return json.dumps(obj_dict, indent=4)

    @classmethod
    def from_base64_string(cls, data):
        return cls(_QuoteBody.from_base64_string(data))


class CertificateValidationError(Exception):
    """Raised when the certificate validation failed"""

    pass


class SignatureValidationError(Exception):
    """Raised when the signature validation failed"""

    pass


class MessageParsingError(Exception):
    """Raised when the json message parsing failed"""

    pass


class ISVEnclaveQuoteStatusError(Exception):
    """Raised when the isv enclave quote status is not in an accepted status"""

    pass


class EnclaveQuoteFlagsError(Exception):
    """Raised when the flags in quote body don't match expected values"""

    pass


class MeasurementMismatchError(Exception):
    """Raised when enclave measurement does not match expected value"""

    pass


class Verification:
    class IASAttributeFlags(IntFlag):
        INIT = 1
        DEBUG = 2
        MODE64BIT = 4
        PROVISIONKEY = 8
        EINITTOKENKEY = 16

    def __init__(
        self,
        expected_measurement=None,
        accept_debug=False,
        accept_configuration_needed=False,
        accept_group_out_of_date=False,
    ):
        self.expected_measurement = expected_measurement
        self.accept_debug = accept_debug
        self.accept_configuration_needed = accept_configuration_needed
        self.accept_group_out_of_date = accept_group_out_of_date
        trust_roots = []
        for _, _, der_bytes in pem.unarmor(intel_sgx_root_ca, multiple=True): # type: ignore
            trust_roots.append(der_bytes)
        self.context = ValidationContext(trust_roots=trust_roots)

    def verify(self, certificate, message, signature) -> QuoteBody:
        """
        :param certificate:
            A byte string of the certificate
 
        :param message:
            A byte string of the data the signature is for
 
        :param signature:
            A byte string of the data the signature is for
 
        :raises:
            CertificateValidationError
            SignatureValidationError
            MessageParsingError
            ISVEnclaveQuoteStatusError
            EnclaveQuoteFlagsError
            MeasurementMismatchError
 
        :return:
            the QuoteBody inside the message
        """

        # Step 1: validate certificate with Intel SGX attestation root CA
        try:
            validator = CertificateValidator(
                certificate, validation_context=self.context
            )
            validator.validate_usage(set(["digital_signature"]))
        except:
            raise CertificateValidationError

        # Step 2: verify message signature
        try:
            pubk = asymmetric.load_public_key(certificate)
            asymmetric.rsa_pkcs1v15_verify(pubk, signature, message, "sha256")
        except:
            raise SignatureValidationError

        # Step 3: parse message and get quote body
        try:
            message_dic = json.loads(message)
            quote_body_encoded = message_dic["isvEnclaveQuoteBody"]
            isv_enclave_quote_status = message_dic["isvEnclaveQuoteStatus"]
            quote_body = _QuoteBody.from_base64_string(quote_body_encoded)
        except:
            raise MessageParsingError

        # Step 4: check isv enclave quote status
        if isv_enclave_quote_status == "OK":
            pass
        elif isv_enclave_quote_status == "CONFIGURATION_NEEDED":
            if not self.accept_configuration_needed:
                raise ISVEnclaveQuoteStatusError
        elif isv_enclave_quote_status == "GROUP_OUT_OF_DATE":
            if not self.accept_group_out_of_date:
                raise ISVEnclaveQuoteStatusError
        else:
            raise ISVEnclaveQuoteStatusError

        # Step 5: check enclave quote flags
        flags = quote_body.flags
        if not (flags & Verification.IASAttributeFlags.INIT):
            raise EnclaveQuoteFlagsError
        if not (flags & Verification.IASAttributeFlags.MODE64BIT):
            raise EnclaveQuoteFlagsError
        if flags & Verification.IASAttributeFlags.DEBUG:
            if not self.accept_debug:
                raise EnclaveQuoteFlagsError

        # Step 6: assert expected measurement
        if self.expected_measurement:
            measurement = bytes(quote_body.mrenclave).hex()
            if not (measurement == self.expected_measurement):
                raise MeasurementMismatchError(
                    f"Expected: {self.expected_measurement}. Actual: {measurement}."
                )

        return QuoteBody(quote_body)
