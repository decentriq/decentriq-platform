# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: data_source_snowflake.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x1b\x64\x61ta_source_snowflake.proto\x12\x15\x64\x61ta_source_snowflake\"x\n\x0fSnowflakeSource\x12\x15\n\rwarehouseName\x18\x01 \x01(\t\x12\x14\n\x0c\x64\x61tabaseName\x18\x02 \x01(\t\x12\x12\n\nschemaName\x18\x03 \x01(\t\x12\x11\n\ttableName\x18\x04 \x01(\t\x12\x11\n\tstageName\x18\x05 \x01(\t\"\x7f\n&DataSourceSnowflakeWorkerConfiguration\x12\x36\n\x06source\x18\x01 \x01(\x0b\x32&.data_source_snowflake.SnowflakeSource\x12\x1d\n\x15\x63redentialsDependency\x18\x02 \x01(\tb\x06proto3')



_SNOWFLAKESOURCE = DESCRIPTOR.message_types_by_name['SnowflakeSource']
_DATASOURCESNOWFLAKEWORKERCONFIGURATION = DESCRIPTOR.message_types_by_name['DataSourceSnowflakeWorkerConfiguration']
SnowflakeSource = _reflection.GeneratedProtocolMessageType('SnowflakeSource', (_message.Message,), {
  'DESCRIPTOR' : _SNOWFLAKESOURCE,
  '__module__' : 'data_source_snowflake_pb2'
  # @@protoc_insertion_point(class_scope:data_source_snowflake.SnowflakeSource)
  })
_sym_db.RegisterMessage(SnowflakeSource)

DataSourceSnowflakeWorkerConfiguration = _reflection.GeneratedProtocolMessageType('DataSourceSnowflakeWorkerConfiguration', (_message.Message,), {
  'DESCRIPTOR' : _DATASOURCESNOWFLAKEWORKERCONFIGURATION,
  '__module__' : 'data_source_snowflake_pb2'
  # @@protoc_insertion_point(class_scope:data_source_snowflake.DataSourceSnowflakeWorkerConfiguration)
  })
_sym_db.RegisterMessage(DataSourceSnowflakeWorkerConfiguration)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _SNOWFLAKESOURCE._serialized_start=54
  _SNOWFLAKESOURCE._serialized_end=174
  _DATASOURCESNOWFLAKEWORKERCONFIGURATION._serialized_start=176
  _DATASOURCESNOWFLAKEWORKERCONFIGURATION._serialized_end=303
# @@protoc_insertion_point(module_scope)
