from typing import List
from google.protobuf.json_format import MessageToDict
from .proto import (
    DriverTaskConfig,
    NoopConfig,
    serialize_length_delimited,
    StaticContentConfig,
    ComputeNodeFormat,
    parse_length_delimited
)

from .node import Node


class Noop(Node):
    """
    Computation node which does not perform any operation and produces an empty
    output. This is mostly used to allow users to test the execution of other
    computation nodes without giving access to the results.
    """

    def __init__(self, name: str, dependencies: List[str] = []) -> None:
        config = serialize_length_delimited(
            DriverTaskConfig(noop=NoopConfig())
        )
        super().__init__(
            name,
            config,
            "decentriq.driver",
            dependencies,
            ComputeNodeFormat.RAW
        )


class StaticContent(Node):
    """
    Computation node which outputs the content specified in its configuration.
    This is mostly used to allow users to specify dependencies with a static
    content, which are part of the DCR definition.
    """

    def __init__(
            self,
            name: str,
            content: bytes,
            dependencies: List[str] = []
    ) -> None:
        """
        Create a node with the given name and content.

        In case the source of the content is a file on your local machine,
        you can open the file in binary mode before reading it:

        ```
        # Note the "rb" argument
        with open("my_script.py", "rb") as data:
            my_script_content = data.read()

        # my_script_content can now be passed to the StaticContent constructor
        ```
        """
        config = serialize_length_delimited(
            DriverTaskConfig(
                staticContent=StaticContentConfig(
                    content=content
                )
            )
        )
        super().__init__(
            name,
            config=config,
            enclave_type="decentriq.driver",
            dependencies=dependencies,
            output_format=ComputeNodeFormat.RAW
        )


class GcgDriverDecoder:
    def decode(self, config: bytes):
        config_decoded = DriverTaskConfig()
        parse_length_delimited(config, config_decoded)
        config_decoded_json = MessageToDict(config_decoded)
        if config_decoded.HasField("staticContent"):
            content = config_decoded.staticContent.content.decode("utf-8")
            config_decoded_json["staticContent"]["content"] = content
        return config_decoded_json

