from google.protobuf.json_format import MessageToDict
from ..proto import serialize_length_delimited, ComputeNodeFormat, parse_length_delimited
from ..node import Node
from typing import Optional
from .proto import (
    DatasetSinkWorkerConfiguration,
)

__docformat__ = "restructuredtext"
__pdoc__ = {
    "proto": False,
}

class DatasetSink(Node):
    """
    Compute node that re-encrypts input data with a user-provided key
    and creates a dataset entry in the database.
    """

    def __init__(
            self,
            name: str,
            input_dependency: str,
            encryption_key_dependency: str,
            dataset_name: str,
            dataset_scope_id,
            dataset_description: Optional[str],
            dataset_import_id: Optional[str] = None,
    ) -> None:
        config = DatasetSinkWorkerConfiguration(
            inputDependency=input_dependency,
            encryptionKeyDependency=encryption_key_dependency,
            datasetName=dataset_name,
            datasetDescription=dataset_description,
            datasetScopeId=dataset_scope_id,
            datasetImportId=dataset_import_id,
        )
        config_serialized = serialize_length_delimited(config)
        super().__init__(
            name,
            config=config_serialized,
            enclave_type="decentriq.dataset-sink-worker",
            dependencies=[input_dependency, encryption_key_dependency],
            output_format=ComputeNodeFormat.ZIP
        )


class DatasetSinkWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = DatasetSinkWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)

__all__ = [
    "DatasetSink",
]
