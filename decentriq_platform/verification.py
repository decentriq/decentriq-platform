import json
import struct

import asn1crypto.x509
import asn1crypto.pem
from sgx_ias_structs import QuoteBody as _QuoteBody
from oscrypto import asymmetric
from certvalidator import CertificateValidator, ValidationContext
from enum import IntFlag

from .types import IasResponse, Tcb, TcbInfoContainer, TcbLevel
from .proto import (
    AttestationSpecification, Fatquote, FatquoteEpid, FatquoteDcap,
    AttestationSpecificationIntelDcap
)
from ecdsa import VerifyingKey
from hashlib import sha256
from typing import List, Optional
import pem as Pem
from .certs import intel_sgx_ias_root_ca, intel_sgx_dcap_root_ca


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
            attestation_specification: AttestationSpecification,
    ):
        self.attestation_specification = attestation_specification
        self.check_known_root_ca = True

    # Warning: this is unsafe to do, only do this if you deliberately want to test fake roots (e.g. for mocked enclaves)
    def disable_known_root_ca_check(self):
        self.check_known_root_ca = False

    def _verify_epid(self, epid: FatquoteEpid) -> bytes:
        if self.attestation_specification.WhichOneof("attestation_specification") != "intelEpid":
            raise Exception(f'Incompatible attestation specification, expected EPID')
        spec_epid = self.attestation_specification.intelEpid
        trust_roots = [spec_epid.iasRootCaDer]
        validation_context = ValidationContext(trust_roots)
        validator = CertificateValidator(epid.iasCertificate, validation_context=validation_context)
        validator.validate_usage({"digital_signature"})

        # Step 2: verify message signature
        pubk = asymmetric.load_public_key(epid.iasCertificate)
        asymmetric.rsa_pkcs1v15_verify(pubk, epid.iasSignature, epid.iasResponseBody, "sha256")

        # Step 3: parse message and get quote body
        message_dic: IasResponse = json.loads(epid.iasResponseBody)
        quote_body_encoded = message_dic["isvEnclaveQuoteBody"]
        isv_enclave_quote_status = message_dic["isvEnclaveQuoteStatus"]
        quote_body = _QuoteBody.from_base64_string(quote_body_encoded)

        # Step 4: check isv enclave quote status
        if isv_enclave_quote_status == "OK":
            pass
        elif spec_epid.accept_configuration_needed and isv_enclave_quote_status == "CONFIGURATION_NEEDED":
            pass
        elif spec_epid.accept_group_out_of_date and isv_enclave_quote_status == "GROUP_OUT_OF_DATE":
            pass
        else:
            raise ISVEnclaveQuoteStatusError("Status " + isv_enclave_quote_status + " not accepted")

        # Step 5: check enclave quote flags
        flags = quote_body.flags
        if not (flags & Verification.IASAttributeFlags.INIT):
            raise EnclaveQuoteFlagsError
        if not (flags & Verification.IASAttributeFlags.MODE64BIT):
            raise EnclaveQuoteFlagsError
        if flags & Verification.IASAttributeFlags.DEBUG:
            if spec_epid.accept_debug:
                print("!!!WARNING!!! DEBUG quote is being accepted, quote is NOT to be trusted !!!WARNING!!!")
            else:
                raise EnclaveQuoteFlagsError

        # Step 6: assert expected measurement
        measurement = bytes(quote_body.mrenclave)
        if not (spec_epid.mrenclave == measurement):
            raise MeasurementMismatchError(
                f"Wrong measurement, expected measurement: {spec_epid.mrenclave.hex()}, actual measurement: {measurement.hex()}."
            )

        return quote_body.reportdata

    def _get_cpusvn(self, tcb: Tcb) -> List[int]:
        cpusvn_array = [
            tcb["sgxtcbcomp01svn"],
            tcb["sgxtcbcomp02svn"],
            tcb["sgxtcbcomp03svn"],
            tcb["sgxtcbcomp04svn"],
            tcb["sgxtcbcomp05svn"],
            tcb["sgxtcbcomp06svn"],
            tcb["sgxtcbcomp07svn"],
            tcb["sgxtcbcomp08svn"],
            tcb["sgxtcbcomp09svn"],
            tcb["sgxtcbcomp10svn"],
            tcb["sgxtcbcomp11svn"],
            tcb["sgxtcbcomp12svn"],
            tcb["sgxtcbcomp13svn"],
            tcb["sgxtcbcomp14svn"],
            tcb["sgxtcbcomp15svn"],
            tcb["sgxtcbcomp16svn"]
        ]
        return cpusvn_array

    def _dcap_get_cert(self, quote: bytes):
        auth_len = int.from_bytes(quote[1012:1014], "little")

        cert = quote[1014 + auth_len + 2 + 4:]
        return cert

    def _dcap_check_status(self, spec_dcap: AttestationSpecificationIntelDcap, status: str):
        if status == "UpToDate" or status == "SWHardeningNeeded":
            return
        if spec_dcap.accept_out_of_date and status in [
            "OutOfDate",
            "OutOfDateConfigurationNeeded",
        ]:
            return
        if spec_dcap.accept_configuration_needed and status in [
            "ConfigurationNeeded",
            "OutOfDateConfigurationNeeded",
            "ConfigurationAndSWHardeningNeeded",
        ]:
            return
        if spec_dcap.accept_revoked and status in [
            "Revoked"
        ]:
            return
        raise Exception(f'TCB status ${status} not accepted')

    def _dcap_find_tcb_level(
            self,
            tcb_levels: List[TcbLevel],
            cpusvn: List[int],
            pcesvn: int
    ) -> Optional[TcbLevel]:
        for level in tcb_levels:
            tcb_cpusvn = self._get_cpusvn(level["tcb"])
            if all([a >= b for a, b in zip(cpusvn, tcb_cpusvn)]):
                if pcesvn >= level["tcb"]["pcesvn"]:
                    return level
        return None

    def _verify_dcap(self, dcap: FatquoteDcap) -> bytes:
        if self.attestation_specification.WhichOneof("attestation_specification") != "intelDcap":
            raise Exception(f'Incompatible attestation specification, expected DCAP')
        spec_dcap = self.attestation_specification.intelDcap
        # https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/b6d6145c21e7a452f05838af24b09965ae9b6f10/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_3.h#L177
        quote = dcap.dcapQuote
        certificate = self._dcap_get_cert(quote)
        pck_certs = Pem.parse(certificate)
        # Validate PCK Cert Chain
        trust_roots = [spec_dcap.dcapRootCaDer]
        validation_context = ValidationContext(trust_roots)
        validator = CertificateValidator(pck_certs[0].as_bytes(), intermediate_certs=map(lambda cert: cert.as_bytes(), pck_certs[1:]), validation_context=validation_context)
        validator.validate_usage({"digital_signature"})

        # Verify that the QE REPORT signature
        pubk = asymmetric.dump_public_key(
            asymmetric.load_public_key(certificate))
        vk = VerifyingKey.from_pem(pubk)
        vk.verify(quote[948:1012], quote[564:948], hashfunc=sha256)

        flags = quote[96]
        if not (flags & Verification.IASAttributeFlags.INIT):
            raise EnclaveQuoteFlagsError
        if not (flags & Verification.IASAttributeFlags.MODE64BIT):
            raise EnclaveQuoteFlagsError
        if flags & Verification.IASAttributeFlags.DEBUG:
            if spec_dcap.accept_debug:
                print("!!!WARNING!!! DEBUG quote is being accepted, quote is NOT to be trusted !!!WARNING!!!")
            else:
                raise EnclaveQuoteFlagsError

        # Asserting measurement
        measurement = bytes(quote[112:144])
        if not (spec_dcap.mrenclave == measurement):
            raise MeasurementMismatchError(
                f"Wrong measurement, expected measurement: {spec_dcap.mrenclave.hex()}, actual measurement: {measurement.hex()}."
            )

        tcb_info_dic: TcbInfoContainer = json.loads(dcap.tcbInfo)
        tcb_info_body = bytes(json.dumps(tcb_info_dic["tcbInfo"], separators=(',', ':')), "utf-8")
        tcb_info_sign = bytearray.fromhex(tcb_info_dic["signature"])

        # Verify TCB Sign Cert

        validator_tcb = CertificateValidator(dcap.tcbSignCert, validation_context=validation_context)
        validator_tcb.validate_usage({"digital_signature"})

        # Verify signature over the tcb info body
        tcb_pubk = asymmetric.dump_public_key(asymmetric.load_public_key(dcap.tcbSignCert))
        tcb_vk = VerifyingKey.from_pem(tcb_pubk)
        tcb_vk.verify(tcb_info_sign, tcb_info_body, hashfunc=sha256)

        # Checking the tcbStatus is supported
        cpusvn = [x for x in quote[48:64]]
        pcesvn = struct.unpack("<H", quote[10:12])[0]
        tcb_level = self._dcap_find_tcb_level(tcb_info_dic["tcbInfo"]["tcbLevels"], cpusvn, pcesvn)
        if tcb_level is None:
            raise Exception("TCB level not supported")
        self._dcap_check_status(spec_dcap, tcb_level["tcbStatus"])

        qe_id_dic = json.loads(dcap.qeIdentity)
        qe_id_body = bytes(json.dumps(qe_id_dic["enclaveIdentity"], separators=(',', ':')), "utf-8")
        qe_id_sign = bytearray.fromhex(qe_id_dic["signature"])

        # Verify the Qe Sign Cert
        validator_qe = CertificateValidator(dcap.qeSignCert, validation_context=validation_context)
        validator_qe.validate_usage({"digital_signature"})

        # Verify Signature over enclave identity
        qe_pubk = asymmetric.dump_public_key(asymmetric.load_public_key(dcap.qeSignCert))
        qe_vk = VerifyingKey.from_pem(qe_pubk)
        qe_vk.verify(qe_id_sign, qe_id_body, hashfunc=sha256)

        # Checking if isvprodid is matching
        isvprodid_qe = int.from_bytes(quote[820:822], "little")
        if qe_id_dic["enclaveIdentity"]["isvprodid"] != isvprodid_qe:
            raise Exception(
                f'QE identity of quote {isvprodid_qe} does not match expected identity {qe_id_dic["enclaveIdentity"]["isvprodid"]}')

        isvsvn = int.from_bytes(quote[822:824], "little")

        # Cheking if tcbStatus of the QUoting enclave is supported
        qe_tcb_level = next(
            (level for level in qe_id_dic["enclaveIdentity"]["tcbLevels"] if level["tcb"]["isvsvn"] <= isvsvn), None)
        if qe_tcb_level is None:
            raise Exception("QE TCB level not supported")

        return quote[368:400]

    def verify(self, fatquote: Fatquote) -> bytes:
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

        if self.check_known_root_ca:
            if fatquote.HasField("epid"):
                _, _, ias_root_ca = asn1crypto.pem.unarmor(intel_sgx_ias_root_ca)
                if ias_root_ca != fatquote.epid.iasRootCaDer:
                    raise Exception(f'Intel IAS Root CA in fatquote does not match known value')
            elif fatquote.HasField("dcap"):
                _, _, dcap_root_ca = asn1crypto.pem.unarmor(intel_sgx_dcap_root_ca)
                if dcap_root_ca != fatquote.dcap.dcapRootCaDer:
                    raise Exception(f'Intel DCAP Root CA in fatquote does not match known value')
            else:
                raise Exception(f'Unknown fatquote type')

        if fatquote.HasField("epid"):
            return self._verify_epid(fatquote.epid)
        elif fatquote.HasField("dcap"):
            return self._verify_dcap(fatquote.dcap)
        else:
            raise Exception(f'Unknown fatquote type')
