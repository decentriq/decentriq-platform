from .proto import (
    DriverTaskConfig,
    NoopConfig,
    serialize_length_delimited,
    StaticContentConfig,
    ComputeNodeFormat,
)

class Noop():
    """
    Computation node which does not perform any operation and produces an empty
    output. This is mostly used to allow users to test the execution of other computation
    nodes without giving access to the results.
    """
    config: bytes
    """Serialized configuration to use in the compute node definition"""

    enclave_type: str
    """What type of enclave this node uses"""

    def __init__(self) -> None:
        self.config = serialize_length_delimited(DriverTaskConfig(noop=NoopConfig()))
        self.enclave_type = "decentriq.driver"
        self.output_format = ComputeNodeFormat.RAW


class StaticContent():
    """
    Computation node which outputs the content specified in its configuration.
    This is mostly used to allow users to specify dependencies with a static
    content, which are part of the DCR definition.
    """
    config: bytes
    """Serialized configuration to use in the compute node definition"""

    def __init__(self, content: bytes) -> None:
        self.config = serialize_length_delimited(
            DriverTaskConfig(
                staticContent=StaticContentConfig(
                    content=content
                )
            )
        )
        self.enclave_type = "decentriq.driver"
        self.output_format = ComputeNodeFormat.RAW
