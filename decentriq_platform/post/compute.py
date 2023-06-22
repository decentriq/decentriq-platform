from __future__ import annotations
from google.protobuf.json_format import MessageToDict
from typing import List
from .proto import PostWorkerConfiguration
from ..proto import serialize_length_delimited, ComputeNodeFormat, parse_length_delimited
from ..node import Node


__all__ = ["PostCompute"]


class PostWorkerDecoder:
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
            self,
            name: str,
            dependency: str,
            use_mock_backend: bool = False
        ) -> None:
        configuration = PostWorkerConfiguration()
        configuration.useMockBackend = use_mock_backend
        config = serialize_length_delimited(configuration)

        super().__init__(
            name,
            config,
            enclave_type="decentriq.post-worker",
            dependencies=[dependency],
            output_format=ComputeNodeFormat.ZIP
        )
