# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: permutive.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='permutive.proto',
  package='permutive',
  syntax='proto3',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x0fpermutive.proto\x12\tpermutive\"\x0c\n\nImportRole\"1\n\nExportRole\x12#\n\x05input\x18\x01 \x01(\x0b\x32\x14.permutive.SinkInput\"\x1a\n\nSingleFile\x12\x0c\n\x04name\x18\x01 \x01(\t\"\t\n\x07RawFile\"C\n\x07ZipFile\x12+\n\nsingleFile\x18\x01 \x01(\x0b\x32\x15.permutive.SingleFileH\x00\x42\x0b\n\tselection\"{\n\tSinkInput\x12\x12\n\ndependency\x18\x01 \x01(\t\x12\x0c\n\x04name\x18\x02 \x01(\t\x12!\n\x03raw\x18\x03 \x01(\x0b\x32\x12.permutive.RawFileH\x00\x12!\n\x03zip\x18\x04 \x01(\x0b\x32\x12.permutive.ZipFileH\x00\x42\x06\n\x04\x66ile\"\xf4\x01\n\x1cPermutiveWorkerConfiguration\x12\x1d\n\x15\x63redentialsDependency\x18\x01 \x01(\t\x12+\n\nimportRole\x18\x02 \x01(\x0b\x32\x15.permutive.ImportRoleH\x00\x12+\n\nexportRole\x18\x03 \x01(\x0b\x32\x15.permutive.ExportRoleH\x00\x12\x10\n\x08importId\x18\x04 \x01(\t\x12\x13\n\x0bsegmentName\x18\x05 \x01(\t\x12\x13\n\x0bsegmentCode\x18\x06 \x01(\t\x12\x17\n\x0finputHasHeaders\x18\x07 \x01(\x08\x42\x06\n\x04roleb\x06proto3'
)




_IMPORTROLE = _descriptor.Descriptor(
  name='ImportRole',
  full_name='permutive.ImportRole',
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
  serialized_start=30,
  serialized_end=42,
)


_EXPORTROLE = _descriptor.Descriptor(
  name='ExportRole',
  full_name='permutive.ExportRole',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='input', full_name='permutive.ExportRole.input', index=0,
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
  ],
  serialized_start=44,
  serialized_end=93,
)


_SINGLEFILE = _descriptor.Descriptor(
  name='SingleFile',
  full_name='permutive.SingleFile',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='name', full_name='permutive.SingleFile.name', index=0,
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
  serialized_start=95,
  serialized_end=121,
)


_RAWFILE = _descriptor.Descriptor(
  name='RawFile',
  full_name='permutive.RawFile',
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
  serialized_start=123,
  serialized_end=132,
)


_ZIPFILE = _descriptor.Descriptor(
  name='ZipFile',
  full_name='permutive.ZipFile',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='singleFile', full_name='permutive.ZipFile.singleFile', index=0,
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
      name='selection', full_name='permutive.ZipFile.selection',
      index=0, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
  ],
  serialized_start=134,
  serialized_end=201,
)


_SINKINPUT = _descriptor.Descriptor(
  name='SinkInput',
  full_name='permutive.SinkInput',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='dependency', full_name='permutive.SinkInput.dependency', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='name', full_name='permutive.SinkInput.name', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='raw', full_name='permutive.SinkInput.raw', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='zip', full_name='permutive.SinkInput.zip', index=3,
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
      name='file', full_name='permutive.SinkInput.file',
      index=0, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
  ],
  serialized_start=203,
  serialized_end=326,
)


_PERMUTIVEWORKERCONFIGURATION = _descriptor.Descriptor(
  name='PermutiveWorkerConfiguration',
  full_name='permutive.PermutiveWorkerConfiguration',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='credentialsDependency', full_name='permutive.PermutiveWorkerConfiguration.credentialsDependency', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='importRole', full_name='permutive.PermutiveWorkerConfiguration.importRole', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='exportRole', full_name='permutive.PermutiveWorkerConfiguration.exportRole', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='importId', full_name='permutive.PermutiveWorkerConfiguration.importId', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='segmentName', full_name='permutive.PermutiveWorkerConfiguration.segmentName', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='segmentCode', full_name='permutive.PermutiveWorkerConfiguration.segmentCode', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='inputHasHeaders', full_name='permutive.PermutiveWorkerConfiguration.inputHasHeaders', index=6,
      number=7, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
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
      name='role', full_name='permutive.PermutiveWorkerConfiguration.role',
      index=0, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
  ],
  serialized_start=329,
  serialized_end=573,
)

_EXPORTROLE.fields_by_name['input'].message_type = _SINKINPUT
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
_PERMUTIVEWORKERCONFIGURATION.fields_by_name['importRole'].message_type = _IMPORTROLE
_PERMUTIVEWORKERCONFIGURATION.fields_by_name['exportRole'].message_type = _EXPORTROLE
_PERMUTIVEWORKERCONFIGURATION.oneofs_by_name['role'].fields.append(
  _PERMUTIVEWORKERCONFIGURATION.fields_by_name['importRole'])
_PERMUTIVEWORKERCONFIGURATION.fields_by_name['importRole'].containing_oneof = _PERMUTIVEWORKERCONFIGURATION.oneofs_by_name['role']
_PERMUTIVEWORKERCONFIGURATION.oneofs_by_name['role'].fields.append(
  _PERMUTIVEWORKERCONFIGURATION.fields_by_name['exportRole'])
_PERMUTIVEWORKERCONFIGURATION.fields_by_name['exportRole'].containing_oneof = _PERMUTIVEWORKERCONFIGURATION.oneofs_by_name['role']
DESCRIPTOR.message_types_by_name['ImportRole'] = _IMPORTROLE
DESCRIPTOR.message_types_by_name['ExportRole'] = _EXPORTROLE
DESCRIPTOR.message_types_by_name['SingleFile'] = _SINGLEFILE
DESCRIPTOR.message_types_by_name['RawFile'] = _RAWFILE
DESCRIPTOR.message_types_by_name['ZipFile'] = _ZIPFILE
DESCRIPTOR.message_types_by_name['SinkInput'] = _SINKINPUT
DESCRIPTOR.message_types_by_name['PermutiveWorkerConfiguration'] = _PERMUTIVEWORKERCONFIGURATION
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

ImportRole = _reflection.GeneratedProtocolMessageType('ImportRole', (_message.Message,), {
  'DESCRIPTOR' : _IMPORTROLE,
  '__module__' : 'permutive_pb2'
  # @@protoc_insertion_point(class_scope:permutive.ImportRole)
  })
_sym_db.RegisterMessage(ImportRole)

ExportRole = _reflection.GeneratedProtocolMessageType('ExportRole', (_message.Message,), {
  'DESCRIPTOR' : _EXPORTROLE,
  '__module__' : 'permutive_pb2'
  # @@protoc_insertion_point(class_scope:permutive.ExportRole)
  })
_sym_db.RegisterMessage(ExportRole)

SingleFile = _reflection.GeneratedProtocolMessageType('SingleFile', (_message.Message,), {
  'DESCRIPTOR' : _SINGLEFILE,
  '__module__' : 'permutive_pb2'
  # @@protoc_insertion_point(class_scope:permutive.SingleFile)
  })
_sym_db.RegisterMessage(SingleFile)

RawFile = _reflection.GeneratedProtocolMessageType('RawFile', (_message.Message,), {
  'DESCRIPTOR' : _RAWFILE,
  '__module__' : 'permutive_pb2'
  # @@protoc_insertion_point(class_scope:permutive.RawFile)
  })
_sym_db.RegisterMessage(RawFile)

ZipFile = _reflection.GeneratedProtocolMessageType('ZipFile', (_message.Message,), {
  'DESCRIPTOR' : _ZIPFILE,
  '__module__' : 'permutive_pb2'
  # @@protoc_insertion_point(class_scope:permutive.ZipFile)
  })
_sym_db.RegisterMessage(ZipFile)

SinkInput = _reflection.GeneratedProtocolMessageType('SinkInput', (_message.Message,), {
  'DESCRIPTOR' : _SINKINPUT,
  '__module__' : 'permutive_pb2'
  # @@protoc_insertion_point(class_scope:permutive.SinkInput)
  })
_sym_db.RegisterMessage(SinkInput)

PermutiveWorkerConfiguration = _reflection.GeneratedProtocolMessageType('PermutiveWorkerConfiguration', (_message.Message,), {
  'DESCRIPTOR' : _PERMUTIVEWORKERCONFIGURATION,
  '__module__' : 'permutive_pb2'
  # @@protoc_insertion_point(class_scope:permutive.PermutiveWorkerConfiguration)
  })
_sym_db.RegisterMessage(PermutiveWorkerConfiguration)


# @@protoc_insertion_point(module_scope)
