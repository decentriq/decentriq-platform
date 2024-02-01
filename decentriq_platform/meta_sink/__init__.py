from google.protobuf.json_format import MessageToDict
from ..proto import serialize_length_delimited, ComputeNodeFormat, parse_length_delimited
from ..node import Node
from .proto import (
    MetaSinkWorkerConfiguration,
    SinkInput,
)


__docformat__ = "restructuredtext"
__pdoc__ = {
    "proto": False,
}


class MetaSink(Node):
    """
    Compute node that creates a custom audience on Meta and populates it with
    a list of user ids. The input file must contain a single column with one
    user id per line.
    """

    def __init__(
            self,
            name: str,
            input: SinkInput,
            access_token_dependency: str,
            ad_account_id: str,
            audience_name: str,
            api_version: str = "17.0",
    ) -> None:
        config = MetaSinkWorkerConfiguration(
            input=input,
            accessTokenDependency=access_token_dependency,
            adAccountId=ad_account_id,
            audienceName=audience_name,
            apiVersion=api_version,
        )
        config_serialized = serialize_length_delimited(config)
        dependencies = [input.dependency, access_token_dependency]
        super().__init__(
            name,
            config=config_serialized,
            enclave_type="decentriq.meta-sink-worker",
            dependencies=dependencies,
            output_format=ComputeNodeFormat.RAW
        )


class MetaSinkWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = MetaSinkWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


__all__ = [
    "MetaSink",
]
