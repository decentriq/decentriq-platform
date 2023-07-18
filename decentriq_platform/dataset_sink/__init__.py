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
    This node allows users to store the result of a computation as a
    separate dataset that can be published to other Data Clean Rooms.
    """

    def __init__(
            self,
            name: str,
            inputs: List[SinkInput],
            encryption_key_dependency: str,
            dataset_import_id: Optional[str] = None,
            is_key_hex_encoded: bool = False,
    ) -> None:
        """
        Create a dataset sink node.

        **Parameters**:
        - `name`: A human-readable identifier of the node.
        - `inputs`: The data sources from which to read. The given
            encryption key will be used to encrypt all datasets derived
            from these inputs.
            Each input can either be a single raw input (for example,
            when reading a whole ZIP archive), or one ore more files
            contained in an input ZIP file. For each file contained
            in the selection, a separate dataset will be created.
        - `encryption_key_dependency`: The id of the node that provides
            the encryption key to be used. In most cases, this will be a
            data node to which the binary encryption key will be published.
        - `dataset_import_id`: The identifier of the associated `DatasetImport`.
            When using this node directly, this argument can be ommited.
        - `is_key_hex_encoded`: Whether the encryption key material provided
            by the node serving the key is hex-encoded. If this flag is set,
            the node will try to decode the given key.
        """
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
