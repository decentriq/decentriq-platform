from . import proto_util_pb2


def encode(data, nonce, pubkey):
    message = proto_util_pb2.DataNoncePubkey()
    message.data = data
    message.nonce = nonce
    message.pubkey = pubkey
    return message.SerializeToString()


def decode(message):
    parsed_msg = proto_util_pb2.DataNoncePubkey()
    parsed_msg.ParseFromString(message)
    return (parsed_msg.data, parsed_msg.nonce, parsed_msg.pubkey)
