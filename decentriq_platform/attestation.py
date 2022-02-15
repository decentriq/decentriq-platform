from .types import EnclaveSpecification
from .proto import (
    AttestationSpecification,
    AttestationSpecificationIntelEpid
)
from .verification import intel_sgx_ias_root_ca
import asn1crypto.pem


intel_sgx_ias_root_ca_der = asn1crypto.pem.unarmor(intel_sgx_ias_root_ca)[2]


class EnclaveSpecifications:
    """
    The list of available enclave specifications provided by this package.

    Enclave specifications enable you to express which particular enclaves you trust.
    The field containing the measurement (e.g. `mrenclave` in the case of Intel SGX) identifies
    the exact binary that will process your data.
    Users of the Decentriq platform are encouraged to reproduce this value by building the enclave
    binary from audited source code and re-producing the measurement (in the case of Intel SGX,
    this would involve simply hashing the produced executable).

    When connecting to the driver enclave, the configured attestation algorithm will guarantee that the
    enclave you connect to is the one corresponding to the enclave specification you chose.
    The associated root certificate will be used to verify that the attestation was signed
    by the expected party (e.g. Intel/AMD/Amazon, depending on the CC technology used).

    Any communication between the driver enclave and worker enclaves handling your data will also
    first be secured by additional attestation procedures. Which enclaves are trusted by the
    driver enclave is controlled by choosing the additional enclave specs from the respective
    compute packages.

    A list of enclave specifications, each encoding your trust in a particular enclave type, is called an
    *enclave specification set*. Enclave specification sets are obtained by concatenating multiple such specs
    and converting them to a dictionary that maps the enclave name to the trusted enclave spec.
    """
    V1_SGX = [
        EnclaveSpecification(
            name="decentriq.driver",
            version="1",
            proto= AttestationSpecification(
                intelEpid=AttestationSpecificationIntelEpid(
                    mrenclave=bytes.fromhex(
                        "ce2c7ff27a3efe21968dc1a54e662441a88f92bcf7c53b3cc00f7e579cca6591"
                    ),
                    iasRootCaDer=intel_sgx_ias_root_ca_der,
                )
            )
        )
    ]
