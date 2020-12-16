from . import avato_enclave_pb2
from .length_delimited import parse_length_delimited, serialize_length_delimited

def encode(encrypted_data, nonce, pubkey, sigma_auth=None):
    message = avato_enclave_pb2.DataNoncePubkey()
    message.data = encrypted_data
    message.nonce = nonce
    message.pubkey = pubkey
    if sigma_auth is not None:
        message.auth.pki.certChain = sigma_auth.get_cert_chain()
        message.auth.pki.signature = sigma_auth.get_signature()
        message.auth.pki.idMac = sigma_auth.get_mac_tag()
    return serialize_length_delimited(message)

def decode(message):
    parsed_msg = avato_enclave_pb2.DataNoncePubkey()
    parse_length_delimited(message, parsed_msg)
    return (parsed_msg.data, parsed_msg.nonce, parsed_msg.pubkey)
