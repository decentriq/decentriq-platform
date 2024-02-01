from google.protobuf.json_format import MessageToDict
from ..proto import serialize_length_delimited, ComputeNodeFormat, parse_length_delimited
from ..node import Node
from .proto import (
    GoogleDv360SinkWorkerConfiguration,
    SinkInput,
)


__docformat__ = "restructuredtext"
__pdoc__ = {
    "proto": False,
}


class GoogleDv360Sink(Node):
    """
    Compute node that creates a custom audience on Google DV360.
    """

    def __init__(
            self,
            name: str,
            input: SinkInput,
            credentialsDependency: str,
            advertiserId: str,
            displayName: str,
            description: str,
            membershipDurationDays: str,
    ) -> None:
        config = GoogleDv360SinkWorkerConfiguration(
            input=input,
            credentialsDependency=credentialsDependency,
            advertiserId=advertiserId,
            displayName=displayName,
            description=description,
            membershipDurationDays=membershipDurationDays,
        )
        config_serialized = serialize_length_delimited(config)
        dependencies = [input.dependency, credentialsDependency]
        super().__init__(
            name,
            config=config_serialized,
            enclave_type="decentriq.google-dv-360-sink-worker",
            dependencies=dependencies,
            output_format=ComputeNodeFormat.RAW
        )


class GoogleDv360SinkWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = GoogleDv360SinkWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


__all__ = [
    "GoogleDv360Sink",
]

