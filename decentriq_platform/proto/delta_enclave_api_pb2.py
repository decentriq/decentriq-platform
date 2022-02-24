# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: delta_enclave_api.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x17\x64\x65lta_enclave_api.proto\x12\x11\x64\x65lta_enclave_api\"\x91\x01\n\x07Request\x12:\n\x0c\x64\x65ltaRequest\x18\x01 \x01(\x0b\x32\".delta_enclave_api.DataNoncePubkeyH\x00\x12?\n\x10\x65xtensionMessage\x18\x02 \x01(\x0b\x32#.delta_enclave_api.ExtensionMessageH\x00\x42\t\n\x07request\"1\n\x10\x45xtensionMessage\x12\x0c\n\x04name\x18\x01 \x01(\t\x12\x0f\n\x07payload\x18\x02 \x01(\x0c\"T\n\x08Response\x12\x1c\n\x12successfulResponse\x18\x01 \x01(\x0cH\x00\x12\x1e\n\x14unsuccessfulResponse\x18\x02 \x01(\tH\x00\x42\n\n\x08response\"m\n\x0f\x44\x61taNoncePubkey\x12\x0c\n\x04\x64\x61ta\x18\x01 \x01(\x0c\x12\r\n\x05nonce\x18\x02 \x01(\x0c\x12\x0e\n\x06pubkey\x18\x03 \x01(\x0c\x12%\n\x03pki\x18\x04 \x01(\x0b\x32\x16.delta_enclave_api.PkiH\x00\x42\x06\n\x04\x61uth\"=\n\x03Pki\x12\x14\n\x0c\x63\x65rtChainPem\x18\x01 \x01(\x0c\x12\x11\n\tsignature\x18\x02 \x01(\x0c\x12\r\n\x05idMac\x18\x03 \x01(\x0c\"(\n\tDataNonce\x12\x0c\n\x04\x64\x61ta\x18\x01 \x01(\x0c\x12\r\n\x05nonce\x18\x02 \x01(\x0c\"j\n\x16SealedEncryptedMessage\x12\x36\n\x10\x65ncryptedMessage\x18\x01 \x01(\x0b\x32\x1c.delta_enclave_api.DataNonce\x12\x18\n\x10sealingKeyParams\x18\x02 \x01(\x0c\"W\n\x10\x45ncryptionHeader\x12/\n\x08\x63hilyKey\x18\x01 \x01(\x0b\x32\x1b.delta_enclave_api.ChilyKeyH\x00\x42\x12\n\x10\x65ncryptionHeader\"#\n\x08\x43hilyKey\x12\x17\n\x0f\x65ncryptionNonce\x18\x02 \x01(\x0c\" \n\rVersionHeader\x12\x0f\n\x07version\x18\x01 \x01(\x03\"#\n\x0b\x43hunkHeader\x12\x14\n\x0c\x65xtraEntropy\x18\x01 \x01(\x0c\x62\x06proto3')



_REQUEST = DESCRIPTOR.message_types_by_name['Request']
_EXTENSIONMESSAGE = DESCRIPTOR.message_types_by_name['ExtensionMessage']
_RESPONSE = DESCRIPTOR.message_types_by_name['Response']
_DATANONCEPUBKEY = DESCRIPTOR.message_types_by_name['DataNoncePubkey']
_PKI = DESCRIPTOR.message_types_by_name['Pki']
_DATANONCE = DESCRIPTOR.message_types_by_name['DataNonce']
_SEALEDENCRYPTEDMESSAGE = DESCRIPTOR.message_types_by_name['SealedEncryptedMessage']
_ENCRYPTIONHEADER = DESCRIPTOR.message_types_by_name['EncryptionHeader']
_CHILYKEY = DESCRIPTOR.message_types_by_name['ChilyKey']
_VERSIONHEADER = DESCRIPTOR.message_types_by_name['VersionHeader']
_CHUNKHEADER = DESCRIPTOR.message_types_by_name['ChunkHeader']
Request = _reflection.GeneratedProtocolMessageType('Request', (_message.Message,), {
  'DESCRIPTOR' : _REQUEST,
  '__module__' : 'delta_enclave_api_pb2'
  # @@protoc_insertion_point(class_scope:delta_enclave_api.Request)
  })
_sym_db.RegisterMessage(Request)

ExtensionMessage = _reflection.GeneratedProtocolMessageType('ExtensionMessage', (_message.Message,), {
  'DESCRIPTOR' : _EXTENSIONMESSAGE,
  '__module__' : 'delta_enclave_api_pb2'
  # @@protoc_insertion_point(class_scope:delta_enclave_api.ExtensionMessage)
  })
_sym_db.RegisterMessage(ExtensionMessage)

Response = _reflection.GeneratedProtocolMessageType('Response', (_message.Message,), {
  'DESCRIPTOR' : _RESPONSE,
  '__module__' : 'delta_enclave_api_pb2'
  # @@protoc_insertion_point(class_scope:delta_enclave_api.Response)
  })
_sym_db.RegisterMessage(Response)

DataNoncePubkey = _reflection.GeneratedProtocolMessageType('DataNoncePubkey', (_message.Message,), {
  'DESCRIPTOR' : _DATANONCEPUBKEY,
  '__module__' : 'delta_enclave_api_pb2'
  # @@protoc_insertion_point(class_scope:delta_enclave_api.DataNoncePubkey)
  })
_sym_db.RegisterMessage(DataNoncePubkey)

Pki = _reflection.GeneratedProtocolMessageType('Pki', (_message.Message,), {
  'DESCRIPTOR' : _PKI,
  '__module__' : 'delta_enclave_api_pb2'
  # @@protoc_insertion_point(class_scope:delta_enclave_api.Pki)
  })
_sym_db.RegisterMessage(Pki)

DataNonce = _reflection.GeneratedProtocolMessageType('DataNonce', (_message.Message,), {
  'DESCRIPTOR' : _DATANONCE,
  '__module__' : 'delta_enclave_api_pb2'
  # @@protoc_insertion_point(class_scope:delta_enclave_api.DataNonce)
  })
_sym_db.RegisterMessage(DataNonce)

SealedEncryptedMessage = _reflection.GeneratedProtocolMessageType('SealedEncryptedMessage', (_message.Message,), {
  'DESCRIPTOR' : _SEALEDENCRYPTEDMESSAGE,
  '__module__' : 'delta_enclave_api_pb2'
  # @@protoc_insertion_point(class_scope:delta_enclave_api.SealedEncryptedMessage)
  })
_sym_db.RegisterMessage(SealedEncryptedMessage)

EncryptionHeader = _reflection.GeneratedProtocolMessageType('EncryptionHeader', (_message.Message,), {
  'DESCRIPTOR' : _ENCRYPTIONHEADER,
  '__module__' : 'delta_enclave_api_pb2'
  # @@protoc_insertion_point(class_scope:delta_enclave_api.EncryptionHeader)
  })
_sym_db.RegisterMessage(EncryptionHeader)

ChilyKey = _reflection.GeneratedProtocolMessageType('ChilyKey', (_message.Message,), {
  'DESCRIPTOR' : _CHILYKEY,
  '__module__' : 'delta_enclave_api_pb2'
  # @@protoc_insertion_point(class_scope:delta_enclave_api.ChilyKey)
  })
_sym_db.RegisterMessage(ChilyKey)

VersionHeader = _reflection.GeneratedProtocolMessageType('VersionHeader', (_message.Message,), {
  'DESCRIPTOR' : _VERSIONHEADER,
  '__module__' : 'delta_enclave_api_pb2'
  # @@protoc_insertion_point(class_scope:delta_enclave_api.VersionHeader)
  })
_sym_db.RegisterMessage(VersionHeader)

ChunkHeader = _reflection.GeneratedProtocolMessageType('ChunkHeader', (_message.Message,), {
  'DESCRIPTOR' : _CHUNKHEADER,
  '__module__' : 'delta_enclave_api_pb2'
  # @@protoc_insertion_point(class_scope:delta_enclave_api.ChunkHeader)
  })
_sym_db.RegisterMessage(ChunkHeader)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _REQUEST._serialized_start=47
  _REQUEST._serialized_end=192
  _EXTENSIONMESSAGE._serialized_start=194
  _EXTENSIONMESSAGE._serialized_end=243
  _RESPONSE._serialized_start=245
  _RESPONSE._serialized_end=329
  _DATANONCEPUBKEY._serialized_start=331
  _DATANONCEPUBKEY._serialized_end=440
  _PKI._serialized_start=442
  _PKI._serialized_end=503
  _DATANONCE._serialized_start=505
  _DATANONCE._serialized_end=545
  _SEALEDENCRYPTEDMESSAGE._serialized_start=547
  _SEALEDENCRYPTEDMESSAGE._serialized_end=653
  _ENCRYPTIONHEADER._serialized_start=655
  _ENCRYPTIONHEADER._serialized_end=742
  _CHILYKEY._serialized_start=744
  _CHILYKEY._serialized_end=779
  _VERSIONHEADER._serialized_start=781
  _VERSIONHEADER._serialized_end=813
  _CHUNKHEADER._serialized_start=815
  _CHUNKHEADER._serialized_end=850
# @@protoc_insertion_point(module_scope)
