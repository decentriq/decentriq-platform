from ..proto.attestation_pb2 import (
    AttestationSpecification,
    AttestationSpecificationIntelEpid
)
from ..types import EnclaveSpecification
from ..attestation import intel_sgx_ias_root_ca_der


class EnclaveSpecifications:
    """
    The list of available `EnclaveSpecification`s provided by this compute package.

    Refer to the class with the same name located in the main package for more information.
    """
    V1_SGX = [
        EnclaveSpecification(
            name="decentriq.sql-worker",
            version="1",
            proto=AttestationSpecification(
                intelEpid=AttestationSpecificationIntelEpid(
                    mrenclave=bytes.fromhex("16506a96801ca841e784eeb55f6c162c2ef141667f1a1030df23ab61f69e0873"),
                    iasRootCaDer=intel_sgx_ias_root_ca_der
                )
            )
        )
    ]
