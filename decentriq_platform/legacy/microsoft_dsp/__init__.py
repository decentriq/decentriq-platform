from google.protobuf.json_format import MessageToDict

from ...proto import (
    ComputeNodeFormat,
    serialize_length_delimited,
)
from ..node import Node
from .proto import MicrosoftDspWorkerConfiguration, SinkInput, SegmentInfo


class DataSinkMicrosoftDsp(Node):
    """
    Compute node that exports data to Microsoft DSP.
    """

    def __init__(
        self,
        name: str,
        credentials_dependency: str,
        input: SinkInput,
        member_id: str,
        segment_short_name: str,
        segment_code: str,
    ) -> None:
        config = MicrosoftDspWorkerConfiguration(
            credentials_dependency=credentials_dependency,
            input=input,
            member_id=member_id,
            segment_info=SegmentInfo(short_name=segment_short_name, code=segment_code),
        )
        config_serialized = serialize_length_delimited(config)
        super().__init__(
            name,
            config=config_serialized,
            enclave_type="decentriq.microsoft-dsp-worker",
            dependencies=[credentials_dependency, input.dependency],
            output_format=ComputeNodeFormat.RAW,
        )


from ...decoder import MicrosoftDspWorkerDecoder

__all__ = [
    "DataSinkMicrosoftDsp",
    "MicrosoftDspWorkerDecoder",
]
