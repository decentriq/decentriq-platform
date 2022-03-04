from typing import Dict, List, Tuple
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
                mrenclave=bytes.fromhex(
                    "a88ec2195974edf693e45b2ccdf39cf53c9382bb5309ba3863b5d0f2591542f1"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_sw_hardening_needed=False,
                accept_revoked=False,
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
                    "c04e429edd5fc767e00ec4839b1f8c57375fda178905866ac6d4debee4fbe7d1"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_sw_hardening_needed=False,
                accept_revoked=False,
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
                pcr0=bytes.fromhex("9103b7019cd97a2837b1631648bc683b3470b402b3c0638d8ff16178c7fd031407c06aeff8f96517a320fb573d7d281f"),
                pcr1=bytes.fromhex("9103b7019cd97a2837b1631648bc683b3470b402b3c0638d8ff16178c7fd031407c06aeff8f96517a320fb573d7d281f"),
                pcr2=bytes.fromhex("21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a"),
                pcr8=bytes.fromhex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
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

    def list(self) -> List[str]:
        """Get a list of all available enclave identifiers."""
        return sorted(self.specifications.keys())

    def versions(self, enclave_versions: List[str]) -> Dict[str, EnclaveSpecification]:
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
            selected_specifcations[enclave_type] = self.specifications[version]
        return selected_specifcations

    def merge(self, other):
        """
        Merge two sets of enclave specifications into a single set.
        """
        return EnclaveSpecifications({**self.specifications, **other.specifications})


enclave_specifications: EnclaveSpecifications = EnclaveSpecifications(SPECIFICATIONS)
"""The main catalogue of enclave specifications available within the Decentriq platform."""
