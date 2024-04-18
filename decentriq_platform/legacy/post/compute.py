from __future__ import annotations

from google.protobuf.json_format import MessageToDict

from ...proto import (
    ComputeNodeFormat,
    parse_length_delimited,
    serialize_length_delimited,
)
from ..node import Node
from .proto import PostWorkerConfiguration

__all__ = ["PostCompute"]


class PostWorkerDecoder:
    @staticmethod
    def decode(config: bytes):
        config_decoded = PostWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


class PostCompute(Node):
    """
    Computation node which makes a secure API call to the Post Address
    Maintainance Service to the check the input addresses
    """

    def __init__(
        self, name: str, dependency: str, use_mock_backend: bool = False
    ) -> None:
        configuration = PostWorkerConfiguration()
        configuration.useMockBackend = use_mock_backend
        config = serialize_length_delimited(configuration)

        super().__init__(
            name,
            config,
            enclave_type="decentriq.post-worker",
            dependencies=[dependency],
            output_format=ComputeNodeFormat.ZIP,
        )
