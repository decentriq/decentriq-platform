# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: meta_sink.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0fmeta_sink.proto\x12\tmeta_sink\"\x1a\n\nSingleFile\x12\x0c\n\x04name\x18\x01 \x01(\t\"\t\n\x07RawFile\"C\n\x07ZipFile\x12+\n\nsingleFile\x18\x01 \x01(\x0b\x32\x15.meta_sink.SingleFileH\x00\x42\x0b\n\tselection\"{\n\tSinkInput\x12\x12\n\ndependency\x18\x01 \x01(\t\x12\x0c\n\x04name\x18\x02 \x01(\t\x12!\n\x03raw\x18\x03 \x01(\x0b\x32\x12.meta_sink.RawFileH\x00\x12!\n\x03zip\x18\x04 \x01(\x0b\x32\x12.meta_sink.ZipFileH\x00\x42\x06\n\x04\x66ile\"\xb4\x01\n\x1bMetaSinkWorkerConfiguration\x12#\n\x05input\x18\x01 \x01(\x0b\x32\x14.meta_sink.SinkInput\x12\x1d\n\x15\x61\x63\x63\x65ssTokenDependency\x18\x02 \x01(\t\x12\x13\n\x0b\x61\x64\x41\x63\x63ountId\x18\x03 \x01(\t\x12\x14\n\x0c\x61udienceName\x18\x04 \x01(\t\x12\x17\n\napiVersion\x18\x05 \x01(\tH\x00\x88\x01\x01\x42\r\n\x0b_apiVersionb\x06proto3')



_SINGLEFILE = DESCRIPTOR.message_types_by_name['SingleFile']
_RAWFILE = DESCRIPTOR.message_types_by_name['RawFile']
_ZIPFILE = DESCRIPTOR.message_types_by_name['ZipFile']
_SINKINPUT = DESCRIPTOR.message_types_by_name['SinkInput']
_METASINKWORKERCONFIGURATION = DESCRIPTOR.message_types_by_name['MetaSinkWorkerConfiguration']
SingleFile = _reflection.GeneratedProtocolMessageType('SingleFile', (_message.Message,), {
  'DESCRIPTOR' : _SINGLEFILE,
  '__module__' : 'meta_sink_pb2'
  # @@protoc_insertion_point(class_scope:meta_sink.SingleFile)
  })
_sym_db.RegisterMessage(SingleFile)

RawFile = _reflection.GeneratedProtocolMessageType('RawFile', (_message.Message,), {
  'DESCRIPTOR' : _RAWFILE,
  '__module__' : 'meta_sink_pb2'
  # @@protoc_insertion_point(class_scope:meta_sink.RawFile)
  })
_sym_db.RegisterMessage(RawFile)

ZipFile = _reflection.GeneratedProtocolMessageType('ZipFile', (_message.Message,), {
  'DESCRIPTOR' : _ZIPFILE,
  '__module__' : 'meta_sink_pb2'
  # @@protoc_insertion_point(class_scope:meta_sink.ZipFile)
  })
_sym_db.RegisterMessage(ZipFile)

SinkInput = _reflection.GeneratedProtocolMessageType('SinkInput', (_message.Message,), {
  'DESCRIPTOR' : _SINKINPUT,
  '__module__' : 'meta_sink_pb2'
  # @@protoc_insertion_point(class_scope:meta_sink.SinkInput)
  })
_sym_db.RegisterMessage(SinkInput)

MetaSinkWorkerConfiguration = _reflection.GeneratedProtocolMessageType('MetaSinkWorkerConfiguration', (_message.Message,), {
  'DESCRIPTOR' : _METASINKWORKERCONFIGURATION,
  '__module__' : 'meta_sink_pb2'
  # @@protoc_insertion_point(class_scope:meta_sink.MetaSinkWorkerConfiguration)
  })
_sym_db.RegisterMessage(MetaSinkWorkerConfiguration)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _SINGLEFILE._serialized_start=30
  _SINGLEFILE._serialized_end=56
  _RAWFILE._serialized_start=58
  _RAWFILE._serialized_end=67
  _ZIPFILE._serialized_start=69
  _ZIPFILE._serialized_end=136
  _SINKINPUT._serialized_start=138
  _SINKINPUT._serialized_end=261
  _METASINKWORKERCONFIGURATION._serialized_start=264
  _METASINKWORKERCONFIGURATION._serialized_end=444
# @@protoc_insertion_point(module_scope)
