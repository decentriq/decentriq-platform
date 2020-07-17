from google.protobuf.internal.encoder import _VarintBytes
from google.protobuf.internal.decoder import _DecodeVarint32

# Returns the end offset from serialized_bytes
def parse_length_delimited(serialized_bytes, deserialized_object):
    message_length, offset = _DecodeVarint32(serialized_bytes, 0)
    end_offset = offset + message_length
    deserialized_object.ParseFromString(bytes(serialized_bytes[offset:end_offset]))
    return end_offset

def serialize_length_delimited(message_object):
    serialized = _VarintBytes(message_object.ByteSize())
    serialized += message_object.SerializeToString()
    return serialized
