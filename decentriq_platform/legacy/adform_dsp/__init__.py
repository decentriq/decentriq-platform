from typing import List
from google.protobuf.json_format import MessageToDict

from ...proto import (
    ComputeNodeFormat,
    serialize_length_delimited,
)
from ..node import Node
from .proto import AdformDspWorkerConfiguration, SinkInput


class AdformDspDataTransformer(Node):
    """
    Compute node that transforms data into an Adform compliant form.
    """

    def __init__(
        self,
        name: str,
        segment_owners: List[str],
        input: SinkInput,
    ) -> None:
        config = AdformDspWorkerConfiguration(
            input=input,
            segment_owners=segment_owners,
        )
        config_serialized = serialize_length_delimited(config)
        super().__init__(
            name,
            config=config_serialized,
            enclave_type="decentriq.adform-dsp-worker",
            dependencies=[input.dependency],
            output_format=ComputeNodeFormat.RAW,
        )


from ...decoder import AdformDspWorkerDecoder

__all__ = [
    "AdformDspDataTransformer",
    "AdformDspWorkerDecoder",
]
