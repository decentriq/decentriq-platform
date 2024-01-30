# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: google_ad_manager.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='google_ad_manager.proto',
  package='google_ad_manager',
  syntax='proto3',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x17google_ad_manager.proto\x12\x11google_ad_manager\"\x1a\n\nSingleFile\x12\x0c\n\x04name\x18\x01 \x01(\t\"\t\n\x07RawFile\"K\n\x07ZipFile\x12\x33\n\nsingleFile\x18\x01 \x01(\x0b\x32\x1d.google_ad_manager.SingleFileH\x00\x42\x0b\n\tselection\"\x8b\x01\n\tSinkInput\x12\x12\n\ndependency\x18\x01 \x01(\t\x12\x0c\n\x04name\x18\x02 \x01(\t\x12)\n\x03raw\x18\x03 \x01(\x0b\x32\x1a.google_ad_manager.RawFileH\x00\x12)\n\x03zip\x18\x04 \x01(\x0b\x32\x1a.google_ad_manager.ZipFileH\x00\x42\x06\n\x04\x66ile\"\xd5\x01\n\"GoogleAdManagerWorkerConfiguration\x12+\n\x05input\x18\x01 \x01(\x0b\x32\x1c.google_ad_manager.SinkInput\x12\x1d\n\x15\x63redentialsDependency\x18\x02 \x01(\t\x12\x16\n\x0eidentifierKind\x18\x03 \x01(\t\x12\x0e\n\x06listId\x18\x04 \x01(\t\x12\x17\n\x0finputHasHeaders\x18\x05 \x01(\x08\x12\x0e\n\x06\x62ucket\x18\x06 \x01(\t\x12\x12\n\nobjectName\x18\x07 \x01(\tb\x06proto3'
)




_SINGLEFILE = _descriptor.Descriptor(
  name='SingleFile',
  full_name='google_ad_manager.SingleFile',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='name', full_name='google_ad_manager.SingleFile.name', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=46,
  serialized_end=72,
)


_RAWFILE = _descriptor.Descriptor(
  name='RawFile',
  full_name='google_ad_manager.RawFile',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=74,
  serialized_end=83,
)


_ZIPFILE = _descriptor.Descriptor(
  name='ZipFile',
  full_name='google_ad_manager.ZipFile',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='singleFile', full_name='google_ad_manager.ZipFile.singleFile', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='selection', full_name='google_ad_manager.ZipFile.selection',
      index=0, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
  ],
  serialized_start=85,
  serialized_end=160,
)


_SINKINPUT = _descriptor.Descriptor(
  name='SinkInput',
  full_name='google_ad_manager.SinkInput',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='dependency', full_name='google_ad_manager.SinkInput.dependency', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='name', full_name='google_ad_manager.SinkInput.name', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='raw', full_name='google_ad_manager.SinkInput.raw', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='zip', full_name='google_ad_manager.SinkInput.zip', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='file', full_name='google_ad_manager.SinkInput.file',
      index=0, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
  ],
  serialized_start=163,
  serialized_end=302,
)


_GOOGLEADMANAGERWORKERCONFIGURATION = _descriptor.Descriptor(
  name='GoogleAdManagerWorkerConfiguration',
  full_name='google_ad_manager.GoogleAdManagerWorkerConfiguration',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='input', full_name='google_ad_manager.GoogleAdManagerWorkerConfiguration.input', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='credentialsDependency', full_name='google_ad_manager.GoogleAdManagerWorkerConfiguration.credentialsDependency', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='identifierKind', full_name='google_ad_manager.GoogleAdManagerWorkerConfiguration.identifierKind', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='listId', full_name='google_ad_manager.GoogleAdManagerWorkerConfiguration.listId', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='inputHasHeaders', full_name='google_ad_manager.GoogleAdManagerWorkerConfiguration.inputHasHeaders', index=4,
      number=5, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='bucket', full_name='google_ad_manager.GoogleAdManagerWorkerConfiguration.bucket', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='objectName', full_name='google_ad_manager.GoogleAdManagerWorkerConfiguration.objectName', index=6,
      number=7, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=305,
  serialized_end=518,
)

_ZIPFILE.fields_by_name['singleFile'].message_type = _SINGLEFILE
_ZIPFILE.oneofs_by_name['selection'].fields.append(
  _ZIPFILE.fields_by_name['singleFile'])
_ZIPFILE.fields_by_name['singleFile'].containing_oneof = _ZIPFILE.oneofs_by_name['selection']
_SINKINPUT.fields_by_name['raw'].message_type = _RAWFILE
_SINKINPUT.fields_by_name['zip'].message_type = _ZIPFILE
_SINKINPUT.oneofs_by_name['file'].fields.append(
  _SINKINPUT.fields_by_name['raw'])
_SINKINPUT.fields_by_name['raw'].containing_oneof = _SINKINPUT.oneofs_by_name['file']
_SINKINPUT.oneofs_by_name['file'].fields.append(
  _SINKINPUT.fields_by_name['zip'])
_SINKINPUT.fields_by_name['zip'].containing_oneof = _SINKINPUT.oneofs_by_name['file']
_GOOGLEADMANAGERWORKERCONFIGURATION.fields_by_name['input'].message_type = _SINKINPUT
DESCRIPTOR.message_types_by_name['SingleFile'] = _SINGLEFILE
DESCRIPTOR.message_types_by_name['RawFile'] = _RAWFILE
DESCRIPTOR.message_types_by_name['ZipFile'] = _ZIPFILE
DESCRIPTOR.message_types_by_name['SinkInput'] = _SINKINPUT
DESCRIPTOR.message_types_by_name['GoogleAdManagerWorkerConfiguration'] = _GOOGLEADMANAGERWORKERCONFIGURATION
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

SingleFile = _reflection.GeneratedProtocolMessageType('SingleFile', (_message.Message,), {
  'DESCRIPTOR' : _SINGLEFILE,
  '__module__' : 'google_ad_manager_pb2'
  # @@protoc_insertion_point(class_scope:google_ad_manager.SingleFile)
  })
_sym_db.RegisterMessage(SingleFile)

RawFile = _reflection.GeneratedProtocolMessageType('RawFile', (_message.Message,), {
  'DESCRIPTOR' : _RAWFILE,
  '__module__' : 'google_ad_manager_pb2'
  # @@protoc_insertion_point(class_scope:google_ad_manager.RawFile)
  })
_sym_db.RegisterMessage(RawFile)

ZipFile = _reflection.GeneratedProtocolMessageType('ZipFile', (_message.Message,), {
  'DESCRIPTOR' : _ZIPFILE,
  '__module__' : 'google_ad_manager_pb2'
  # @@protoc_insertion_point(class_scope:google_ad_manager.ZipFile)
  })
_sym_db.RegisterMessage(ZipFile)

SinkInput = _reflection.GeneratedProtocolMessageType('SinkInput', (_message.Message,), {
  'DESCRIPTOR' : _SINKINPUT,
  '__module__' : 'google_ad_manager_pb2'
  # @@protoc_insertion_point(class_scope:google_ad_manager.SinkInput)
  })
_sym_db.RegisterMessage(SinkInput)

GoogleAdManagerWorkerConfiguration = _reflection.GeneratedProtocolMessageType('GoogleAdManagerWorkerConfiguration', (_message.Message,), {
  'DESCRIPTOR' : _GOOGLEADMANAGERWORKERCONFIGURATION,
  '__module__' : 'google_ad_manager_pb2'
  # @@protoc_insertion_point(class_scope:google_ad_manager.GoogleAdManagerWorkerConfiguration)
  })
_sym_db.RegisterMessage(GoogleAdManagerWorkerConfiguration)


# @@protoc_insertion_point(module_scope)
