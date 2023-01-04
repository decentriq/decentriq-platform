import base64
from typing import Dict, List, Tuple
from .types import EnclaveSpecification
from .compute import GcgDriverDecoder
from .sql.compute import SqlWorkerDecoder
from .container.compute import ContainerWorkerDecoder
from .s3_sink.compute import S3SinkWorkerDecoder
from .proto import (
    AttestationSpecification,
    AttestationSpecificationIntelDcap,
    AttestationSpecificationAwsNitro,
    AttestationSpecificationAmdSnp,
)
import asn1crypto.pem
from .certs import (
    aws_nitro_root_ca_pem,
    amd_snp_ark_pem,
    intel_sgx_dcap_root_ca,
    intel_sgx_ias_root_ca,
)


intel_sgx_dcap_root_ca_der = asn1crypto.pem.unarmor(intel_sgx_dcap_root_ca)[2]
intel_sgx_ias_root_ca_der = asn1crypto.pem.unarmor(intel_sgx_ias_root_ca)[2]
aws_nitro_root_ca_der = asn1crypto.pem.unarmor(aws_nitro_root_ca_pem)[2]
amd_snp_ark_der = asn1crypto.pem.unarmor(amd_snp_ark_pem)[2]


# From https://developers.cloudflare.com/time-services/roughtime/recipes/
roughtime_public_key = base64.b64decode("gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo=")


# Allowed Decentriq AMD CPU Chip IDs
# This list is hashed and used for the attestation spec, so this list needs to be in the same order in these files:
# - avato-backend/frontend/client/src/attestation.ts
# - trusted/delta-attestation/src/snp.rs
amd_snp_authorized_chip_ids = [
  bytes.fromhex("372499d1b652b98aa1cde6d146136ad2b3e8f93b8223c367087577a73b76813928ad25545327032f7dc44a288965eb8e7f16179dbdb3a71fddc36cc19478ce47"),
  bytes.fromhex("ce8a61aea3f76bbdd05706bcbfb4ade4c65b33ad41f49d0e89dec177951117d247781a3195de2e85399b7117d9eee2f6f2c2e5d21064a4d7e2815380212f0937"),
  bytes.fromhex("86185338a275af6b5e26e06a21b4e0c65db0fc9033e4a24e27cb528321726dc152f28b08c05493c48e8fba3047aba6f0a0dd01d3eebb055b3318c1029c0a74ee"),
  bytes.fromhex("7d2e30af8f43cc6de4e6c3ee59a7ab0d9ddfbff4caba3de0e54430215bd640c571d0e4b49d0cd1502fa74ae8a59475fe06dd9e7635500d584478e13f1191dc27"),
  bytes.fromhex("02926acb4dab55b176946d75e5955154b11269dd8bfe7ff7bcd162b26ea47d8b9557bebd927e90667e34e6dbf9f1bb3bff4bdd36f41d2b755cccabf50270e324"),
]


SPECIFICATIONS = {
    "decentriq.driver:v10": EnclaveSpecification(
        name="decentriq.driver",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "799044e44e189338553b18706e32284725300926569bbec19af576557abfba19"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GcgDriverDecoder(),
        clientProtocols=[3],
    ),
    "decentriq.sql-worker:v10": EnclaveSpecification(
        name="decentriq.sql-worker",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "dcc9847948837a5cdb85d4fb13d6b77ff6ff5dab63bef35c95901adfa7f1a102"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=SqlWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-ml-worker-32-64:v10": EnclaveSpecification(
        name="decentriq.python-ml-worker",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "9a6a0fd3d0652eae039011346c80cedf572c8e725cbb294a2067ce0a66e7c128c7baf370a77b1005eba3f98f467c9cde"
                ),
                roughtimePubKey=roughtime_public_key,
                authorizedChipIds=amd_snp_authorized_chip_ids,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-synth-data-worker-32-64:v10": EnclaveSpecification(
        name="decentriq.python-synth-data-worker",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "8b9f780b6524418f4fc8d4bc8b2450c82e09aefb17b36aebfcf0630b6dea8b1451f12c35203d6ddc9c94b74351db9a22"
                ),
                roughtimePubKey=roughtime_public_key,
                authorizedChipIds=amd_snp_authorized_chip_ids,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.r-latex-worker-32-32:v10": EnclaveSpecification(
        name="decentriq.r-latex-worker",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "5f0a74f6c0633d9d4781d8c112617ce386507b86869b341a89b2183c8e41f01032c3ec9821567530f023f26c0f8a846d"
                ),
                roughtimePubKey=roughtime_public_key,
                authorizedChipIds=amd_snp_authorized_chip_ids,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
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

    def all(self) -> List[EnclaveSpecification]:
        """Get a list of all available enclave specifications."""
        return list(self.specifications.values())

    def merge(self, other):
        """
        Merge two sets of enclave specifications into a single set.
        """
        return EnclaveSpecifications({**self.specifications, **other.specifications})


enclave_specifications: EnclaveSpecifications = EnclaveSpecifications(SPECIFICATIONS)
"""The main catalogue of enclave specifications available within the Decentriq platform."""
