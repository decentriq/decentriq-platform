from typing import List

from .proto.compute_container_pb2 import ContainerWorkerConfiguration, MountPoint
from ..proto.length_delimited import serialize_length_delimited
from ..proto import ComputeNodeFormat


class StaticContainerCompute():
    """
    Computation node which allows execution of programs inside a fixed
    container image
    """
    config: bytes
    """Serialized configuration to use in the compute node definition"""
    dependencies: List[str]
    """List of dependencies"""

    def __init__(
            self,
            command: List[str],
            mount_points: List[MountPoint],
            output_path: str,
            include_container_logs_on_error: bool
    ) -> None:
        configuration = ContainerWorkerConfiguration()
        configuration.static.command.extend(command)
        configuration.static.mountPoints.extend(mount_points)
        configuration.static.outputPath = output_path
        configuration.static.includeContainerLogsOnError = include_container_logs_on_error
        self.config = serialize_length_delimited(configuration)
        self.dependencies = list(map(lambda a: a.dependency, mount_points))
        self.enclave_type = "decentriq.python-worker"
        self.output_format = ComputeNodeFormat.ZIP
