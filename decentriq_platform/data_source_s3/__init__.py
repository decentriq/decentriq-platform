from google.protobuf.json_format import MessageToDict
from ..proto import serialize_length_delimited, ComputeNodeFormat, parse_length_delimited
from ..node import Node
from typing import List, Optional, Set, Tuple
from .proto import (
    DataSourceS3WorkerConfiguration,
    S3Source,
)
from ..sql.proto import TableSchema, NamedColumn, ColumnType

__docformat__ = "restructuredtext"
__pdoc__ = {
    "proto": False,
}

class DataSourceS3(Node):
    """
    Compute node that fetches a dataset from an S3 bucket.
    """

    def __init__(
            self,
            name: str,
            bucket: str,
            region: str,
            object_key: str,
            credentials_dependency: str,
    ) -> None:
        config = DataSourceS3WorkerConfiguration(
            source=S3Source(
                bucket=bucket,
                region=region,
                objectKey=object_key,

            ),
            credentialsDependency=credentials_dependency,
        )
        config_serialized = serialize_length_delimited(config)
        super().__init__(
            name,
            config=config_serialized,
            enclave_type="decentriq.data-source-s3-worker",
            dependencies=[credentials_dependency],
            output_format=ComputeNodeFormat.RAW
        )

class DataSourceS3WorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = DataSourceS3WorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)

__all__ = [
    "DataSourceS3",
]
