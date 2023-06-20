from google.protobuf.json_format import MessageToDict
from ..proto import serialize_length_delimited, ComputeNodeFormat, parse_length_delimited
from ..node import Node
from typing import Optional, List
from .proto import (
    DatasetSinkWorkerConfiguration,
    SinkInput
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
            inputs: List[SinkInput],
            encryption_key_dependency: str,
            dataset_import_id: Optional[str] = None,
            is_key_hex_encoded: bool = False,
    ) -> None:
        config = DatasetSinkWorkerConfiguration(
            inputs=inputs,
            encryptionKeyDependency=encryption_key_dependency,
            datasetImportId=dataset_import_id,
            isKeyHexEncoded=is_key_hex_encoded,
        )
        config_serialized = serialize_length_delimited(config)
        dependencies = (
            [input.dependency for input in inputs] +
            [encryption_key_dependency]
        )
        super().__init__(
            name,
            config=config_serialized,
            enclave_type="decentriq.dataset-sink-worker",
            dependencies=dependencies,
            output_format=ComputeNodeFormat.ZIP
        )


class DatasetSinkWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = DatasetSinkWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


from .helpers import store_computation_result_as_dataset


__all__ = [
    "DatasetSink",
    "store_computation_result_as_dataset"
]
