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
        """
        Create a S3 source node.

        **Parameters**:
        - `name`: A human-readable identifier of the node.
        - `bucket`: The name of the AWS bucket within which the source
            file is located.
        - `region`: The region identifier, e.g. "eu-west-3".
        - `object_key`: The path to the file within the specified bucket,
            e.g. "my/directory/my_file.csv" (notice the lack of a leading slash).
        - `credentials_dependency`: The id of the node that serves the credentials
            for connecting to AWS.
            This node should provide a single JSON with format:

            ```
            {
                "accessKey": "xxxx",
                "secretKey": "yyyy"
            }
            ```

            In most cases this node will be a simple data node to which the
            credentials JSON payload is published. Note that the credentials will
            always be encrypted end-to-end and won't be readable by anyone, including
            Decentriq. If using this node for a one-off import of a dataset,
            the credentials file can be deleted after the import has finished.
        """
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
