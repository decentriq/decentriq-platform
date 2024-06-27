from typing import List, Literal

from google.protobuf.json_format import MessageToDict

from ...proto import ComputeNodeFormat
from ...proto.length_delimited import parse_length_delimited, serialize_length_delimited
from ..node import Node
from .proto.compute_s3_sink_pb2 import S3Object, S3Provider, S3SinkWorkerConfiguration


class S3SinkCompute(Node):
    """
    Compute node which allows the upload of files to an S3 api compatible endpoint
    """

    def __init__(
        self,
        name: str,
        endpoint: str,
        credentials_dependency: str,
        s3_provider: Literal["AWS", "GCS"],
        objects: List[S3Object],
        region: str = "",
    ) -> None:
        """
        Create a container compute node.

        **Parameters**:
        - `name`: The name of the node. This serves as an identifier for the
            node and needs to be specified when you interact with the node
            (e.g. run its computation or retrieve its results).
        - `endpoint`: The S3 endpoint including the bucket name.
        - `region`: The S3 region used by the endpoint.
        - `credentials_dependency`: the id of the dependency that holds the credentials
            to access the S3 bucket
            This node should provide a single JSON with format:
            - For AWS:
            ```
            {
                "accessKey": "xxxx",
                "secretKey": "yyyy"
            }
            - For GCS, see [service account credentials](https://cloud.google.com/iam/docs/service-account-creds)
        - `objects`: The list of objects to upload to the S3 bucket
        """
        configuration = S3SinkWorkerConfiguration()
        configuration.endpoint = endpoint
        configuration.region = region
        configuration.credentialsDependency = credentials_dependency
        configuration.objects.extend(objects)
        if s3_provider == "AWS":
            configuration.s3Provider = S3Provider.AWS
        elif s3_provider == "GCS":
            configuration.s3Provider = S3Provider.GCS
        else:
            raise Exception(f"Invalid s3_provider: got {s3_provider}")

        config = serialize_length_delimited(configuration)
        dependencies = [credentials_dependency] + list(
            map(lambda a: a.dependency, objects)
        )

        super().__init__(
            name,
            config=config,
            enclave_type="decentriq.s3-sink-worker",
            dependencies=dependencies,
            output_format=ComputeNodeFormat.RAW,
        )


from ...decoder import S3SinkWorkerDecoder
