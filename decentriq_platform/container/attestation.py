from ..proto.attestation_pb2 import (
    AttestationSpecification,
    AttestationSpecificationAwsNitro,
)
import asn1crypto.pem
from ..certs import aws_nitro_root_ca_pem


aws_nitro_root_ca_der = asn1crypto.pem.unarmor(aws_nitro_root_ca_pem)[2]


class EnclaveSpecification:
    """
    The list of available enclave specifications provided by this compute package.

    Refer to the class with the same name located in the main package for more information.
    """
    # V0_NITRO = [
    #     {
    #         "name": "decentriq.python-worker",
    #         "version": "0",
    #         "proto": AttestationSpecification(
    #             awsNitro=AttestationSpecificationAwsNitro(
    #                 nitroRootCaDer=aws_nitro_root_ca_der,
    #                 ...
    #             )
    #         )
    #     }
    # ]
