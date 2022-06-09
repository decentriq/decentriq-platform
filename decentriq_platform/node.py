from typing import List, Any, Optional
import uuid


__all__ = [ "Node" ]


class Node:
    name: str
    """The name of the node."""

    config: bytes
    """Serialized configuration to use in the compute node definition."""

    enclave_type: str
    """What type of enclave this node uses."""

    dependencies: List[str]
    """A list of names of nodes on which this node directly depends."""

    output_format: Any
    """The `proto.ComputeNodeFormat` of the output from this node."""

    def __init__(
            self,
            name: str,
            config: bytes,
            enclave_type: str,
            dependencies: List[str],
            output_format: Any
    ):
        self.name = name
        self.config = config
        self.enclave_type = enclave_type
        self.dependencies = dependencies
        self.output_format = output_format
