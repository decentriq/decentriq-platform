from typing import List
from google.protobuf.json_format import MessageToDict
from .proto.compute_s3_sink_pb2 import S3SinkWorkerConfiguration, S3Object
from ..proto.length_delimited import serialize_length_delimited, parse_length_delimited
from ..proto import ComputeNodeFormat
from ..node import Node


class S3SinkCompute(Node):
    """
    Compute node which allows the upload of files to an S3 api compatible endpoint
    """

    def __init__(
            self,
            name: str,
            endpoint: str,
            region: str,
            credentials_dependency: str,
            objects: List[S3Object],
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
        - `objects`: The list of objects to upload to the S3 bucket
        """
        configuration = S3SinkWorkerConfiguration()
        configuration.endpoint = endpoint
        configuration.region = region
        configuration.credentialsDependency = credentials_dependency
        configuration.objects.extend(objects)
        config = serialize_length_delimited(configuration)
        dependencies = [credentials_dependency] + list(map(lambda a: a.dependency, objects))

        super().__init__(
            name,
            config=config,
            enclave_type="decentriq.s3-sink-worker",
            dependencies=dependencies,
            output_format=ComputeNodeFormat.RAW
        )


class S3SinkWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = S3SinkWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)
