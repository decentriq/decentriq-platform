# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: synth_data.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from . import compute_sql_pb2 as compute__sql__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x10synth_data.proto\x12\nsynth_data\x1a\x11\x63ompute_sql.proto\"j\n\x11SyntheticDataConf\x12#\n\x07\x63olumns\x18\x01 \x03(\x0b\x32\x12.synth_data.Column\x12\x1f\n\x17outputOriginalDataStats\x18\x02 \x01(\x08\x12\x0f\n\x07\x65psilon\x18\x03 \x01(\x02\"\xeb\x01\n\x04Mask\x12+\n\x06\x66ormat\x18\x01 \x01(\x0e\x32\x1b.synth_data.Mask.MaskFormat\"\xb5\x01\n\nMaskFormat\x12\x12\n\x0eGENERIC_STRING\x10\x00\x12\x12\n\x0eGENERIC_NUMBER\x10\x01\x12\x08\n\x04NAME\x10\x02\x12\x0b\n\x07\x41\x44\x44RESS\x10\x03\x12\x0c\n\x08POSTCODE\x10\x04\x12\x10\n\x0cPHONE_NUMBER\x10\x05\x12\x1a\n\x16SOCIAL_SECURITY_NUMBER\x10\x06\x12\t\n\x05\x45MAIL\x10\x07\x12\x08\n\x04\x44\x41TE\x10\x08\x12\r\n\tTIMESTAMP\x10\t\x12\x08\n\x04IBAN\x10\n\"^\n\x06\x43olumn\x12\r\n\x05index\x18\x01 \x01(\x05\x12%\n\x04type\x18\x02 \x01(\x0b\x32\x17.compute_sql.ColumnType\x12\x1e\n\x04mask\x18\x03 \x01(\x0b\x32\x10.synth_data.Maskb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'synth_data_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  DESCRIPTOR._options = None
  _globals['_SYNTHETICDATACONF']._serialized_start=51
  _globals['_SYNTHETICDATACONF']._serialized_end=157
  _globals['_MASK']._serialized_start=160
  _globals['_MASK']._serialized_end=395
  _globals['_MASK_MASKFORMAT']._serialized_start=214
  _globals['_MASK_MASKFORMAT']._serialized_end=395
  _globals['_COLUMN']._serialized_start=397
  _globals['_COLUMN']._serialized_end=491
# @@protoc_insertion_point(module_scope)
