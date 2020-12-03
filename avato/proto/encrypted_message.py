from . import avato_enclave_pb2
from .length_delimited import parse_length_delimited, serialize_length_delimited

def encode(data, nonce, pubkey, pki=None):
    message = avato_enclave_pb2.DataNoncePubkey()
    message.data = data
    message.nonce = nonce
    message.pubkey = pubkey
    if pki is not None:
        message.auth.pki.certChain = pki.get_certificate_pem()
        message.auth.pki.signature = pki.sign(data)
    return serialize_length_delimited(message)

def decode(message):
    parsed_msg = avato_enclave_pb2.DataNoncePubkey()
    parse_length_delimited(message, parsed_msg)
    return (parsed_msg.data, parsed_msg.nonce, parsed_msg.pubkey)
