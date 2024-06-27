from typing import Literal, Optional

from google.protobuf.json_format import MessageToDict

from decentriq_platform.legacy.data_source_s3.proto.data_source_s3_pb2 import S3Provider

from ...proto import (
    ComputeNodeFormat,
    parse_length_delimited,
    serialize_length_delimited,
)
from ..node import Node
from .proto import DataSourceS3WorkerConfiguration, S3Source

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
        object_key: str,
        credentials_dependency: str,
        s3_provider: Literal["AWS", "GCS"],
        region: str = "",
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
            - For AWS:
            ```
            {
                "accessKey": "xxxx",
                "secretKey": "yyyy"
            }
            - For GCS, see [service account credentials](https://cloud.google.com/iam/docs/service-account-creds)
            ```

            In most cases this node will be a simple data node to which the
            credentials JSON payload is published. Note that the credentials will
            always be encrypted end-to-end and won't be readable by anyone, including
            Decentriq. If using this node for a one-off import of a dataset,
            the credentials file can be deleted after the import has finished.
        - `s3_provider`: A Literal indicating the cloud provider for the S3 storage.

            Supported providers are Amazon Web Services S3 buckets (`"AWS"`) and Google Cloud Storage buckets (`"GCS"`).
        """
        if s3_provider == "AWS":
            s3Provider = S3Provider.AWS
        elif s3_provider == "GCS":
            s3Provider = S3Provider.GCS
        else:
            raise Exception(f"Unsupported S3 provider: {s3_provider}")

        config = DataSourceS3WorkerConfiguration(
            source=S3Source(
                bucket=bucket,
                region=region,
                objectKey=object_key,
            ),
            credentialsDependency=credentials_dependency,
            s3Provider=s3Provider,
        )
        config_serialized = serialize_length_delimited(config)
        super().__init__(
            name,
            config=config_serialized,
            enclave_type="decentriq.data-source-s3-worker",
            dependencies=[credentials_dependency],
            output_format=ComputeNodeFormat.RAW,
        )


from ...decoder import DataSourceS3WorkerDecoder

__all__ = [
    "DataSourceS3",
]
