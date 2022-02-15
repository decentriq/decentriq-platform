from typing import Tuple
from google.protobuf.message import Message
from google.protobuf.internal.encoder import _VarintBytes # type: ignore 
from google.protobuf.internal.decoder import _DecodeVarint32 # type: ignore 

# Returns the end offset from serialized_bytes
def parse_length_delimited(serialized_bytes: bytes, deserialized_object: Message) -> int:
    res: Tuple[int, int] = _DecodeVarint32(serialized_bytes, 0)
    message_length, offset = res
    end_offset = offset + message_length
    deserialized_object.ParseFromString(bytes(serialized_bytes[offset:end_offset]))
    return end_offset

def serialize_length_delimited(message_object: Message) -> bytes:
    serialized: bytes = _VarintBytes(message_object.ByteSize())
    serialized += message_object.SerializeToString()
    return serialized
