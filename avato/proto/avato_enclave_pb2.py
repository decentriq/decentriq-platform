# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: avato_enclave.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='avato_enclave.proto',
  package='avato_enclave',
  syntax='proto2',
  serialized_options=None,
  serialized_pb=_b('\n\x13\x61vato_enclave.proto\x12\ravato_enclave\"i\n\x07Request\x12\x16\n\x0c\x61vatoRequest\x18\x01 \x01(\x0cH\x00\x12;\n\x10\x65xtensionMessage\x18\x02 \x01(\x0b\x32\x1f.avato_enclave.ExtensionMessageH\x00\x42\t\n\x07request\"1\n\x10\x45xtensionMessage\x12\x0c\n\x04name\x18\x01 \x02(\t\x12\x0f\n\x07payload\x18\x02 \x02(\x0c\"T\n\x08Response\x12\x1c\n\x12successfulResponse\x18\x01 \x01(\x0cH\x00\x12\x1e\n\x14unsuccessfulResponse\x18\x02 \x01(\tH\x00\x42\n\n\x08response\"k\n\x0f\x44\x61taNoncePubkey\x12\x0c\n\x04\x64\x61ta\x18\x01 \x02(\x0c\x12\r\n\x05nonce\x18\x02 \x02(\x0c\x12\x0e\n\x06pubkey\x18\x03 \x02(\x0c\x12+\n\x04\x61uth\x18\x04 \x01(\x0b\x32\x1d.avato_enclave.Authentication\"1\n\x0e\x41uthentication\x12\x1f\n\x03pki\x18\x01 \x02(\x0b\x32\x12.avato_enclave.Pki\"+\n\x03Pki\x12\x11\n\tcertChain\x18\x01 \x02(\x0c\x12\x11\n\tsignature\x18\x02 \x02(\x0c\"(\n\tDataNonce\x12\x0c\n\x04\x64\x61ta\x18\x01 \x02(\x0c\x12\r\n\x05nonce\x18\x02 \x02(\x0c\"f\n\x16SealedEncryptedMessage\x12\x32\n\x10\x65ncryptedMessage\x18\x01 \x02(\x0b\x32\x18.avato_enclave.DataNonce\x12\x18\n\x10sealingKeyParams\x18\x02 \x02(\x0c\"\xa3\x01\n\x10\x45ncryptionHeader\x12+\n\x08\x63hilyKey\x18\x01 \x01(\x0b\x32\x17.avato_enclave.ChilyKeyH\x00\x12N\n\x13\x63hilyKeyDiversified\x18\x02 \x01(\x0b\x32/.avato_enclave.ChilyKeyClusterSecretDiversifiedH\x00\x42\x12\n\x10\x65ncryptionHeader\"6\n\x08\x43hilyKey\x12\x11\n\tkeySha256\x18\x01 \x02(\x0c\x12\x17\n\x0f\x65ncryptionNonce\x18\x02 \x02(\x0c\"Z\n ChilyKeyClusterSecretDiversified\x12\x1c\n\x14keyDiversifiedSha256\x18\x01 \x02(\x0c\x12\x18\n\x10\x65ncryption_nonce\x18\x02 \x02(\x0c\"\x8b\x01\n\x0fIntegrityHeader\x12/\n\nbodySha256\x18\x01 \x01(\x0b\x32\x19.avato_enclave.BodySha256H\x00\x12\x33\n\x0cresultSha256\x18\x02 \x01(\x0b\x32\x1b.avato_enclave.ResultSha256H\x00\x42\x12\n\x10integrity_header\"\x0c\n\nBodySha256\")\n\x0cResultSha256\x12\x19\n\x11\x63omputationSha256\x18\x01 \x02(\x0c\" \n\rVersionHeader\x12\x0f\n\x07version\x18\x01 \x02(\x03\"=\n\x0b\x43hunkHeader\x12\x14\n\x0c\x65xtraEntropy\x18\x01 \x02(\x0c\x12\x18\n\x10\x66ormatIdentifier\x18\x02 \x02(\t')
)




_REQUEST = _descriptor.Descriptor(
  name='Request',
  full_name='avato_enclave.Request',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='avatoRequest', full_name='avato_enclave.Request.avatoRequest', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='extensionMessage', full_name='avato_enclave.Request.extensionMessage', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='request', full_name='avato_enclave.Request.request',
      index=0, containing_type=None, fields=[]),
  ],
  serialized_start=38,
  serialized_end=143,
)


_EXTENSIONMESSAGE = _descriptor.Descriptor(
  name='ExtensionMessage',
  full_name='avato_enclave.ExtensionMessage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='name', full_name='avato_enclave.ExtensionMessage.name', index=0,
      number=1, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='payload', full_name='avato_enclave.ExtensionMessage.payload', index=1,
      number=2, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=145,
  serialized_end=194,
)


_RESPONSE = _descriptor.Descriptor(
  name='Response',
  full_name='avato_enclave.Response',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='successfulResponse', full_name='avato_enclave.Response.successfulResponse', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='unsuccessfulResponse', full_name='avato_enclave.Response.unsuccessfulResponse', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='response', full_name='avato_enclave.Response.response',
      index=0, containing_type=None, fields=[]),
  ],
  serialized_start=196,
  serialized_end=280,
)


_DATANONCEPUBKEY = _descriptor.Descriptor(
  name='DataNoncePubkey',
  full_name='avato_enclave.DataNoncePubkey',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='data', full_name='avato_enclave.DataNoncePubkey.data', index=0,
      number=1, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='nonce', full_name='avato_enclave.DataNoncePubkey.nonce', index=1,
      number=2, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='pubkey', full_name='avato_enclave.DataNoncePubkey.pubkey', index=2,
      number=3, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='auth', full_name='avato_enclave.DataNoncePubkey.auth', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=282,
  serialized_end=389,
)


_AUTHENTICATION = _descriptor.Descriptor(
  name='Authentication',
  full_name='avato_enclave.Authentication',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='pki', full_name='avato_enclave.Authentication.pki', index=0,
      number=1, type=11, cpp_type=10, label=2,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=391,
  serialized_end=440,
)


_PKI = _descriptor.Descriptor(
  name='Pki',
  full_name='avato_enclave.Pki',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='certChain', full_name='avato_enclave.Pki.certChain', index=0,
      number=1, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='signature', full_name='avato_enclave.Pki.signature', index=1,
      number=2, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=442,
  serialized_end=485,
)


_DATANONCE = _descriptor.Descriptor(
  name='DataNonce',
  full_name='avato_enclave.DataNonce',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='data', full_name='avato_enclave.DataNonce.data', index=0,
      number=1, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='nonce', full_name='avato_enclave.DataNonce.nonce', index=1,
      number=2, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=487,
  serialized_end=527,
)


_SEALEDENCRYPTEDMESSAGE = _descriptor.Descriptor(
  name='SealedEncryptedMessage',
  full_name='avato_enclave.SealedEncryptedMessage',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='encryptedMessage', full_name='avato_enclave.SealedEncryptedMessage.encryptedMessage', index=0,
      number=1, type=11, cpp_type=10, label=2,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='sealingKeyParams', full_name='avato_enclave.SealedEncryptedMessage.sealingKeyParams', index=1,
      number=2, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=529,
  serialized_end=631,
)


_ENCRYPTIONHEADER = _descriptor.Descriptor(
  name='EncryptionHeader',
  full_name='avato_enclave.EncryptionHeader',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='chilyKey', full_name='avato_enclave.EncryptionHeader.chilyKey', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='chilyKeyDiversified', full_name='avato_enclave.EncryptionHeader.chilyKeyDiversified', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='encryptionHeader', full_name='avato_enclave.EncryptionHeader.encryptionHeader',
      index=0, containing_type=None, fields=[]),
  ],
  serialized_start=634,
  serialized_end=797,
)


_CHILYKEY = _descriptor.Descriptor(
  name='ChilyKey',
  full_name='avato_enclave.ChilyKey',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='keySha256', full_name='avato_enclave.ChilyKey.keySha256', index=0,
      number=1, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='encryptionNonce', full_name='avato_enclave.ChilyKey.encryptionNonce', index=1,
      number=2, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=799,
  serialized_end=853,
)


_CHILYKEYCLUSTERSECRETDIVERSIFIED = _descriptor.Descriptor(
  name='ChilyKeyClusterSecretDiversified',
  full_name='avato_enclave.ChilyKeyClusterSecretDiversified',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='keyDiversifiedSha256', full_name='avato_enclave.ChilyKeyClusterSecretDiversified.keyDiversifiedSha256', index=0,
      number=1, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='encryption_nonce', full_name='avato_enclave.ChilyKeyClusterSecretDiversified.encryption_nonce', index=1,
      number=2, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=855,
  serialized_end=945,
)


_INTEGRITYHEADER = _descriptor.Descriptor(
  name='IntegrityHeader',
  full_name='avato_enclave.IntegrityHeader',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='bodySha256', full_name='avato_enclave.IntegrityHeader.bodySha256', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='resultSha256', full_name='avato_enclave.IntegrityHeader.resultSha256', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='integrity_header', full_name='avato_enclave.IntegrityHeader.integrity_header',
      index=0, containing_type=None, fields=[]),
  ],
  serialized_start=948,
  serialized_end=1087,
)


_BODYSHA256 = _descriptor.Descriptor(
  name='BodySha256',
  full_name='avato_enclave.BodySha256',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1089,
  serialized_end=1101,
)


_RESULTSHA256 = _descriptor.Descriptor(
  name='ResultSha256',
  full_name='avato_enclave.ResultSha256',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='computationSha256', full_name='avato_enclave.ResultSha256.computationSha256', index=0,
      number=1, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1103,
  serialized_end=1144,
)


_VERSIONHEADER = _descriptor.Descriptor(
  name='VersionHeader',
  full_name='avato_enclave.VersionHeader',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='version', full_name='avato_enclave.VersionHeader.version', index=0,
      number=1, type=3, cpp_type=2, label=2,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1146,
  serialized_end=1178,
)


_CHUNKHEADER = _descriptor.Descriptor(
  name='ChunkHeader',
  full_name='avato_enclave.ChunkHeader',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='extraEntropy', full_name='avato_enclave.ChunkHeader.extraEntropy', index=0,
      number=1, type=12, cpp_type=9, label=2,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='formatIdentifier', full_name='avato_enclave.ChunkHeader.formatIdentifier', index=1,
      number=2, type=9, cpp_type=9, label=2,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto2',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1180,
  serialized_end=1241,
)

_REQUEST.fields_by_name['extensionMessage'].message_type = _EXTENSIONMESSAGE
_REQUEST.oneofs_by_name['request'].fields.append(
  _REQUEST.fields_by_name['avatoRequest'])
_REQUEST.fields_by_name['avatoRequest'].containing_oneof = _REQUEST.oneofs_by_name['request']
_REQUEST.oneofs_by_name['request'].fields.append(
  _REQUEST.fields_by_name['extensionMessage'])
_REQUEST.fields_by_name['extensionMessage'].containing_oneof = _REQUEST.oneofs_by_name['request']
_RESPONSE.oneofs_by_name['response'].fields.append(
  _RESPONSE.fields_by_name['successfulResponse'])
_RESPONSE.fields_by_name['successfulResponse'].containing_oneof = _RESPONSE.oneofs_by_name['response']
_RESPONSE.oneofs_by_name['response'].fields.append(
  _RESPONSE.fields_by_name['unsuccessfulResponse'])
_RESPONSE.fields_by_name['unsuccessfulResponse'].containing_oneof = _RESPONSE.oneofs_by_name['response']
_DATANONCEPUBKEY.fields_by_name['auth'].message_type = _AUTHENTICATION
_AUTHENTICATION.fields_by_name['pki'].message_type = _PKI
_SEALEDENCRYPTEDMESSAGE.fields_by_name['encryptedMessage'].message_type = _DATANONCE
_ENCRYPTIONHEADER.fields_by_name['chilyKey'].message_type = _CHILYKEY
_ENCRYPTIONHEADER.fields_by_name['chilyKeyDiversified'].message_type = _CHILYKEYCLUSTERSECRETDIVERSIFIED
_ENCRYPTIONHEADER.oneofs_by_name['encryptionHeader'].fields.append(
  _ENCRYPTIONHEADER.fields_by_name['chilyKey'])
_ENCRYPTIONHEADER.fields_by_name['chilyKey'].containing_oneof = _ENCRYPTIONHEADER.oneofs_by_name['encryptionHeader']
_ENCRYPTIONHEADER.oneofs_by_name['encryptionHeader'].fields.append(
  _ENCRYPTIONHEADER.fields_by_name['chilyKeyDiversified'])
_ENCRYPTIONHEADER.fields_by_name['chilyKeyDiversified'].containing_oneof = _ENCRYPTIONHEADER.oneofs_by_name['encryptionHeader']
_INTEGRITYHEADER.fields_by_name['bodySha256'].message_type = _BODYSHA256
_INTEGRITYHEADER.fields_by_name['resultSha256'].message_type = _RESULTSHA256
_INTEGRITYHEADER.oneofs_by_name['integrity_header'].fields.append(
  _INTEGRITYHEADER.fields_by_name['bodySha256'])
_INTEGRITYHEADER.fields_by_name['bodySha256'].containing_oneof = _INTEGRITYHEADER.oneofs_by_name['integrity_header']
_INTEGRITYHEADER.oneofs_by_name['integrity_header'].fields.append(
  _INTEGRITYHEADER.fields_by_name['resultSha256'])
_INTEGRITYHEADER.fields_by_name['resultSha256'].containing_oneof = _INTEGRITYHEADER.oneofs_by_name['integrity_header']
DESCRIPTOR.message_types_by_name['Request'] = _REQUEST
DESCRIPTOR.message_types_by_name['ExtensionMessage'] = _EXTENSIONMESSAGE
DESCRIPTOR.message_types_by_name['Response'] = _RESPONSE
DESCRIPTOR.message_types_by_name['DataNoncePubkey'] = _DATANONCEPUBKEY
DESCRIPTOR.message_types_by_name['Authentication'] = _AUTHENTICATION
DESCRIPTOR.message_types_by_name['Pki'] = _PKI
DESCRIPTOR.message_types_by_name['DataNonce'] = _DATANONCE
DESCRIPTOR.message_types_by_name['SealedEncryptedMessage'] = _SEALEDENCRYPTEDMESSAGE
DESCRIPTOR.message_types_by_name['EncryptionHeader'] = _ENCRYPTIONHEADER
DESCRIPTOR.message_types_by_name['ChilyKey'] = _CHILYKEY
DESCRIPTOR.message_types_by_name['ChilyKeyClusterSecretDiversified'] = _CHILYKEYCLUSTERSECRETDIVERSIFIED
DESCRIPTOR.message_types_by_name['IntegrityHeader'] = _INTEGRITYHEADER
DESCRIPTOR.message_types_by_name['BodySha256'] = _BODYSHA256
DESCRIPTOR.message_types_by_name['ResultSha256'] = _RESULTSHA256
DESCRIPTOR.message_types_by_name['VersionHeader'] = _VERSIONHEADER
DESCRIPTOR.message_types_by_name['ChunkHeader'] = _CHUNKHEADER
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Request = _reflection.GeneratedProtocolMessageType('Request', (_message.Message,), dict(
  DESCRIPTOR = _REQUEST,
  __module__ = 'avato_enclave_pb2'
  # @@protoc_insertion_point(class_scope:avato_enclave.Request)
  ))
_sym_db.RegisterMessage(Request)

ExtensionMessage = _reflection.GeneratedProtocolMessageType('ExtensionMessage', (_message.Message,), dict(
  DESCRIPTOR = _EXTENSIONMESSAGE,
  __module__ = 'avato_enclave_pb2'
  # @@protoc_insertion_point(class_scope:avato_enclave.ExtensionMessage)
  ))
_sym_db.RegisterMessage(ExtensionMessage)

Response = _reflection.GeneratedProtocolMessageType('Response', (_message.Message,), dict(
  DESCRIPTOR = _RESPONSE,
  __module__ = 'avato_enclave_pb2'
  # @@protoc_insertion_point(class_scope:avato_enclave.Response)
  ))
_sym_db.RegisterMessage(Response)

DataNoncePubkey = _reflection.GeneratedProtocolMessageType('DataNoncePubkey', (_message.Message,), dict(
  DESCRIPTOR = _DATANONCEPUBKEY,
  __module__ = 'avato_enclave_pb2'
  # @@protoc_insertion_point(class_scope:avato_enclave.DataNoncePubkey)
  ))
_sym_db.RegisterMessage(DataNoncePubkey)

Authentication = _reflection.GeneratedProtocolMessageType('Authentication', (_message.Message,), dict(
  DESCRIPTOR = _AUTHENTICATION,
  __module__ = 'avato_enclave_pb2'
  # @@protoc_insertion_point(class_scope:avato_enclave.Authentication)
  ))
_sym_db.RegisterMessage(Authentication)

Pki = _reflection.GeneratedProtocolMessageType('Pki', (_message.Message,), dict(
  DESCRIPTOR = _PKI,
  __module__ = 'avato_enclave_pb2'
  # @@protoc_insertion_point(class_scope:avato_enclave.Pki)
  ))
_sym_db.RegisterMessage(Pki)

DataNonce = _reflection.GeneratedProtocolMessageType('DataNonce', (_message.Message,), dict(
  DESCRIPTOR = _DATANONCE,
  __module__ = 'avato_enclave_pb2'
  # @@protoc_insertion_point(class_scope:avato_enclave.DataNonce)
  ))
_sym_db.RegisterMessage(DataNonce)

SealedEncryptedMessage = _reflection.GeneratedProtocolMessageType('SealedEncryptedMessage', (_message.Message,), dict(
  DESCRIPTOR = _SEALEDENCRYPTEDMESSAGE,
  __module__ = 'avato_enclave_pb2'
  # @@protoc_insertion_point(class_scope:avato_enclave.SealedEncryptedMessage)
  ))
_sym_db.RegisterMessage(SealedEncryptedMessage)

EncryptionHeader = _reflection.GeneratedProtocolMessageType('EncryptionHeader', (_message.Message,), dict(
  DESCRIPTOR = _ENCRYPTIONHEADER,
  __module__ = 'avato_enclave_pb2'
  # @@protoc_insertion_point(class_scope:avato_enclave.EncryptionHeader)
  ))
_sym_db.RegisterMessage(EncryptionHeader)

ChilyKey = _reflection.GeneratedProtocolMessageType('ChilyKey', (_message.Message,), dict(
  DESCRIPTOR = _CHILYKEY,
  __module__ = 'avato_enclave_pb2'
  # @@protoc_insertion_point(class_scope:avato_enclave.ChilyKey)
  ))
_sym_db.RegisterMessage(ChilyKey)

ChilyKeyClusterSecretDiversified = _reflection.GeneratedProtocolMessageType('ChilyKeyClusterSecretDiversified', (_message.Message,), dict(
  DESCRIPTOR = _CHILYKEYCLUSTERSECRETDIVERSIFIED,
  __module__ = 'avato_enclave_pb2'
  # @@protoc_insertion_point(class_scope:avato_enclave.ChilyKeyClusterSecretDiversified)
  ))
_sym_db.RegisterMessage(ChilyKeyClusterSecretDiversified)

IntegrityHeader = _reflection.GeneratedProtocolMessageType('IntegrityHeader', (_message.Message,), dict(
  DESCRIPTOR = _INTEGRITYHEADER,
  __module__ = 'avato_enclave_pb2'
  # @@protoc_insertion_point(class_scope:avato_enclave.IntegrityHeader)
  ))
_sym_db.RegisterMessage(IntegrityHeader)

BodySha256 = _reflection.GeneratedProtocolMessageType('BodySha256', (_message.Message,), dict(
  DESCRIPTOR = _BODYSHA256,
  __module__ = 'avato_enclave_pb2'
  # @@protoc_insertion_point(class_scope:avato_enclave.BodySha256)
  ))
_sym_db.RegisterMessage(BodySha256)

ResultSha256 = _reflection.GeneratedProtocolMessageType('ResultSha256', (_message.Message,), dict(
  DESCRIPTOR = _RESULTSHA256,
  __module__ = 'avato_enclave_pb2'
  # @@protoc_insertion_point(class_scope:avato_enclave.ResultSha256)
  ))
_sym_db.RegisterMessage(ResultSha256)

VersionHeader = _reflection.GeneratedProtocolMessageType('VersionHeader', (_message.Message,), dict(
  DESCRIPTOR = _VERSIONHEADER,
  __module__ = 'avato_enclave_pb2'
  # @@protoc_insertion_point(class_scope:avato_enclave.VersionHeader)
  ))
_sym_db.RegisterMessage(VersionHeader)

ChunkHeader = _reflection.GeneratedProtocolMessageType('ChunkHeader', (_message.Message,), dict(
  DESCRIPTOR = _CHUNKHEADER,
  __module__ = 'avato_enclave_pb2'
  # @@protoc_insertion_point(class_scope:avato_enclave.ChunkHeader)
  ))
_sym_db.RegisterMessage(ChunkHeader)


# @@protoc_insertion_point(module_scope)
