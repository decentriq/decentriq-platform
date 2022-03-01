from typing import Dict, List
from .types import EnclaveSpecification
from .proto import (
    AttestationSpecification,
    AttestationSpecificationIntelEpid,
    AttestationSpecificationIntelDcap,
    AttestationSpecificationAwsNitro,
    ComputeNodeProtocol,
)
import asn1crypto.pem
from .certs import (
    aws_nitro_root_ca_pem,
    intel_sgx_dcap_root_ca,
    intel_sgx_ias_root_ca
)


intel_sgx_dcap_root_ca_der = asn1crypto.pem.unarmor(intel_sgx_dcap_root_ca)[2]
intel_sgx_ias_root_ca_der = asn1crypto.pem.unarmor(intel_sgx_ias_root_ca)[2]
aws_nitro_root_ca_der = asn1crypto.pem.unarmor(aws_nitro_root_ca_pem)[2]

SPECIFICATIONS = {
    "decentriq.driver:v2": EnclaveSpecification(
        name="decentriq.driver",
        version="2",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex("ac492b8e6b0145ce3debb76fe5444a62377fbba3a2479efbc202f8e68304309f"),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
            )
        ),
        protocol=ComputeNodeProtocol(
            version=0
        )
    ),
    "decentriq.driver:v1": EnclaveSpecification(
        name="decentriq.driver",
        version="1",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "ce2c7ff27a3efe21968dc1a54e662441a88f92bcf7c53b3cc00f7e579cca6591"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
            )
        ),
        protocol=ComputeNodeProtocol(
            version=0
        )
    ),
    "decentriq.sql-worker:v2": EnclaveSpecification(
        name="decentriq.sql-worker",
        version="2",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "1675a93fd14c61f9294f41e0a7e8b48b8c15e06c62514e0303daf6e6e8cea3c5"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
            )
        ),
        protocol=ComputeNodeProtocol(
            version=0
        )
    ),
    "decentriq.sql-worker:v1": EnclaveSpecification(
        name="decentriq.sql-worker",
        version="1",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "16506a96801ca841e784eeb55f6c162c2ef141667f1a1030df23ab61f69e0873"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
            )
        ),
        protocol=ComputeNodeProtocol(
            version=0
        )
    ),
    "decentriq.python-ml-worker:v1": EnclaveSpecification(
        name="decentriq.python-ml-worker",
        version="1",
        proto=AttestationSpecification(
            awsNitro=AttestationSpecificationAwsNitro(
                nitroRootCaDer=aws_nitro_root_ca_der,
                pcr0=bytes.fromhex(""),
                pcr1=bytes.fromhex(""),
                pcr2=bytes.fromhex(""),
                pcr8=bytes.fromhex("")
            )
        ),
        protocol=ComputeNodeProtocol(
            version=0
        )
    )
}


class EnclaveSpecifications:
    """
    Provider of the available enclave specifications provided by the Decentriq platform.

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

    A list of enclave specifications, each encoding your trust in a particular enclave type, can
    be obtained by selecting a subset of the enclave specifications provided by the object
    `decentriq_platform.enclave_specifications`. Selecting the subset of versions should be done
    by calling its `versions` method.
    """

    def __init__(self, specifications: Dict[str, EnclaveSpecification]):
        self.specifications = specifications

    def versions(self, **enclave_versions: List[str]) -> Dict[str, EnclaveSpecification]:
        """
        Get the enclave specifications for the given versioned enclave types.

        Make sure to always include the specification of a *driver enclave*, e.g.
        `"decentriq.driver:v1"` as this is the node with which you communicate directly.
        Add additional versioned enclaves depending on the compute module you use.
        Refer to the main documentation page of each compute module to learn which
        enclaves are available.
        """
        selected_specifcations = {}
        for version in enclave_versions:
            enclave_type = version.split(":")[0]
            selected_specifcations[enclave_type] = version
        return selected_specifcations

    def merge(self, other):
        """
        Merge two sets of enclave specifications into a single set.
        """
        return EnclaveSpecifications({**self.specifications, **other.specifications})


enclave_specifications: EnclaveSpecifications = EnclaveSpecifications(SPECIFICATIONS)
"""The main catalogue of enclave specifications available within the Decentriq platform."""
