from . import avato_enclave_pb2
from .length_delimited import parse_length_delimited, serialize_length_delimited

def encode(data, nonce, pubkey):
    message = avato_enclave_pb2.DataNoncePubkey()
    message.data = data
    message.nonce = nonce
    message.pubkey = pubkey
    return serialize_length_delimited(message)


def decode(message):
    parsed_msg = avato_enclave_pb2.DataNoncePubkey()
    parse_length_delimited(message, parsed_msg)
    return (parsed_msg.data, parsed_msg.nonce, parsed_msg.pubkey)
