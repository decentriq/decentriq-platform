from typing import List
from google.protobuf.json_format import MessageToDict
from .proto.compute_container_pb2 import ContainerWorkerConfiguration, MountPoint
from ..proto.length_delimited import serialize_length_delimited, parse_length_delimited
from ..proto import ComputeNodeFormat
from ..node import Node


class StaticContainerCompute(Node):
    """
    Compute node which allows the execution of programs inside a fixed
    container image.
    """

    def __init__(
            self,
            name: str,
            command: List[str],
            mount_points: List[MountPoint],
            output_path: str,
            enclave_type: str,
            include_container_logs_on_error: bool = False,
            include_container_logs_on_success: bool = False
    ) -> None:
        """
        Create a container compute node.

        **Parameters**:
        - `name`: The name of the node. This serves as an identifier for the
            node and needs to be specified when you interact with the node
            (e.g. run its computation or retrieve its results).
        - `command`: The command to execute within the container.
        - `mount_points`: A list of mount points that tell the enclave
            at which file system paths which input should be mounted
            (e.g. the contents of a data node or the output of another
            compute node).
        - `output_path`: A path to a directory that will contain all the
            output written by the command executed in this container.
            Files within this directory will be zipped and downloadable.
        - `enclave_type`: The particular enclave to use for this container.
            This setting controls the environment in which the given `command`
            will be run, i.e. what programs and libraries are available.
            This identifier corresponds to the worker name without the version suffix,
            i.e. `"decentriq.python-ml-worker-32-64"`.
        - `include_container_logs_on_error`: Whether to report the internal
            container logs to the outside in case of an error. These logs
            could contain sensitive data and therefore this setting should
            only be used for debugging.
        - `include_container_logs_on_success`: Whether to report the internal
            container logs as part of the result zip file.
            Note that these logs could contain sensitive data and therefore this
            setting should only be used for debugging.
        """
        configuration = ContainerWorkerConfiguration()
        configuration.static.command.extend(command)
        configuration.static.mountPoints.extend(mount_points)
        configuration.static.outputPath = output_path
        configuration.static.includeContainerLogsOnError = include_container_logs_on_error
        configuration.static.includeContainerLogsOnSuccess = include_container_logs_on_success
        config = serialize_length_delimited(configuration)
        dependencies = list(map(lambda a: a.dependency, mount_points))

        super().__init__(
            name,
            config=config,
            enclave_type=enclave_type,
            dependencies=dependencies,
            output_format=ComputeNodeFormat.ZIP
        )


class ContainerWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = ContainerWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)
