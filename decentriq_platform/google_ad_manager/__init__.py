from google.protobuf.json_format import MessageToDict
from ..proto import serialize_length_delimited, ComputeNodeFormat, parse_length_delimited
from ..node import Node
from .proto import (
    GoogleAdManagerWorkerConfiguration,
    SinkInput,
)
from typing import Literal


__docformat__ = "restructuredtext"
__pdoc__ = {
    "proto": False,
}

GoogleAdManagerIdentifierKind = Literal[
                "cookie_encrypted",
                "cookie_idfa",
                "ppid",
                "cookie_rida",
                "cookie_tvos",
                "cookie_adid"]


class GoogleAdManager(Node):
    """
    Compute node that creates a Google Ad Manager segment list.
    """

    def __init__(
            self,
            name: str,
            input: SinkInput,
            credentialsDependency: str,
            identifier_kind: GoogleAdManagerIdentifierKind,
            list_id: str,
            input_has_headers: bool,
            bucket: str,
            object_name: str,
    ) -> None:
        config = GoogleAdManagerWorkerConfiguration(
            input=input,
            credentialsDependency=credentialsDependency,
            identifierKind=identifier_kind,
            listId=list_id,
            inputHasHeaders=input_has_headers,
            bucket=bucket,
            objectName=object_name,
        )
        config_serialized = serialize_length_delimited(config)
        dependencies = [input.dependency, credentialsDependency]
        super().__init__(
            name,
            config=config_serialized,
            enclave_type="decentriq.google-ad-manager-worker",
            dependencies=dependencies,
            output_format=ComputeNodeFormat.RAW
        )


class GoogleAdManagerWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = GoogleAdManagerWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


__all__ = [
    "GoogleAdManager",
]

