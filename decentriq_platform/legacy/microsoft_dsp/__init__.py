from google.protobuf.json_format import MessageToDict

from ...proto import (
    ComputeNodeFormat,
    serialize_length_delimited,
)
from ..node import Node
from .proto import (
    MicrosoftDspWorkerConfiguration,
    SinkInput,
    SegmentInfo,
    MemberInfo,
)


class DataSinkMicrosoftDsp(Node):
    """
    Compute node that exports data to Microsoft DSP.
    """

    def __init__(
        self,
        name: str,
        input: SinkInput,
        member_id: str,
        member_name: str,
        segment_short_name: str,
        segment_code: str,
    ) -> None:
        config = MicrosoftDspWorkerConfiguration(
            input=input,
            member_info=MemberInfo(id=member_id, name=member_name),
            segment_info=SegmentInfo(short_name=segment_short_name, code=segment_code),
        )
        config_serialized = serialize_length_delimited(config)
        super().__init__(
            name,
            config=config_serialized,
            enclave_type="decentriq.microsoft-dsp-worker",
            dependencies=[input.dependency],
            output_format=ComputeNodeFormat.RAW,
        )


from ...decoder import MicrosoftDspWorkerDecoder

__all__ = [
    "DataSinkMicrosoftDsp",
    "MicrosoftDspWorkerDecoder",
]
