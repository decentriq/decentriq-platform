from google.protobuf.json_format import MessageToDict

from ...proto import (
    ComputeNodeFormat,
    parse_length_delimited,
    serialize_length_delimited,
)
from ..node import Node
from .proto import ExportRole, PermutiveWorkerConfiguration, SinkInput, ImportRole


class DataSourcePermutive(Node):
    """
    Compute node that fetches a dataset from Permutive.
    """

    def __init__(
        self,
        name: str,
        credentials_dependency: str,
    ) -> None:
        config = PermutiveWorkerConfiguration(
            credentialsDependency=credentials_dependency, importRole=ImportRole()
        )
        config_serialized = serialize_length_delimited(config)
        super().__init__(
            name,
            config=config_serialized,
            enclave_type="decentriq.permutive-worker",
            dependencies=[credentials_dependency],
            output_format=ComputeNodeFormat.RAW,
        )


class PermutiveDataTransformer(Node):
    """
    Compute node that transforms data into a Permutive compliant form.
    """

    def __init__(
        self,
        name: str,
        credentials_dependency: str,
        input: SinkInput,
        import_id: str,
        segment_name: str,
        segment_code: str,
        input_has_headers: bool,
    ) -> None:
        config = PermutiveWorkerConfiguration(
            credentialsDependency=credentials_dependency,
            exportRole=ExportRole(input=input),
            importId=import_id,
            segmentName=segment_name,
            segmentCode=segment_code,
            inputHasHeaders=input_has_headers,
        )
        config_serialized = serialize_length_delimited(config)
        super().__init__(
            name,
            config=config_serialized,
            enclave_type="decentriq.permutive-worker",
            dependencies=[credentials_dependency, input.dependency],
            output_format=ComputeNodeFormat.RAW,
        )


class PermutiveWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = PermutiveWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


__all__ = ["DataSourcePermutive", "PermutiveDataTransformer", "PermutiveWorkerDecoder"]
