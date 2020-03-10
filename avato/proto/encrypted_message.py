from . import avato_enclave_pb2


def encode(data, nonce, pubkey):
    message = avato_enclave_pb2.DataNoncePubkey()
    message.data = data
    message.nonce = nonce
    message.pubkey = pubkey
    return message.SerializeToString()


def decode(message):
    parsed_msg = avato_enclave_pb2.DataNoncePubkey()
    parsed_msg.ParseFromString(message)
    return (parsed_msg.data, parsed_msg.nonce, parsed_msg.pubkey)
