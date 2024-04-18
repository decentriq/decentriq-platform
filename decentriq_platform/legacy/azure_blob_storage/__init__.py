from google.protobuf.json_format import MessageToDict

from ...proto import (
    ComputeNodeFormat,
    serialize_length_delimited,
)
from ..node import Node
from .proto import AzureBlobStorageWorkerConfiguration, ExportRole, SinkInput, ImportRole


class DataSourceAzureBlobStorage(Node):
    """
    Compute node that fetches a dataset from a Azure blob storage.
    """

    def __init__(
        self,
        name: str,
        credentials_dependency: str,
    ) -> None:
        config = AzureBlobStorageWorkerConfiguration(
            credentialsDependency=credentials_dependency, importRole=ImportRole()
        )
        config_serialized = serialize_length_delimited(config)
        super().__init__(
            name,
            config=config_serialized,
            enclave_type="decentriq.azure-blob-storage-worker",
            dependencies=[credentials_dependency],
            output_format=ComputeNodeFormat.RAW,
        )


class DataSinkAzureBlobStorage(Node):
    """
    Compute node that exports data to Azure blob storage.
    """

    def __init__(
        self,
        name: str,
        credentials_dependency: str,
        input: SinkInput,
    ) -> None:
        config = AzureBlobStorageWorkerConfiguration(
            credentialsDependency=credentials_dependency,
            exportRole=ExportRole(input=input),
        )
        config_serialized = serialize_length_delimited(config)
        super().__init__(
            name,
            config=config_serialized,
            enclave_type="decentriq.azure-blob-storage-worker",
            dependencies=[credentials_dependency, input.dependency],
            output_format=ComputeNodeFormat.RAW,
        )


from ...decoder import AzureBlobStorageWorkerDecoder

__all__ = [
    "DataSourceAzureBlobStorage",
    "DataSinkAzureBlobStorage",
    "AzureBlobStorageWorkerDecoder",
]
