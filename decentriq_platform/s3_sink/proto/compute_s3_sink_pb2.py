# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: compute_s3_sink.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x15\x63ompute_s3_sink.proto\x12\x0f\x63ompute_s3_sink\"\x88\x01\n\x19S3SinkWorkerConfiguration\x12\x10\n\x08\x65ndpoint\x18\x01 \x01(\t\x12\x0e\n\x06region\x18\x02 \x01(\t\x12\x1d\n\x15\x63redentialsDependency\x18\x03 \x01(\t\x12*\n\x07objects\x18\x04 \x03(\x0b\x32\x19.compute_s3_sink.S3Object\"~\n\x08S3Object\x12\x12\n\ndependency\x18\x01 \x01(\t\x12)\n\x03zip\x18\x02 \x01(\x0b\x32\x1a.compute_s3_sink.ZipObjectH\x00\x12)\n\x03raw\x18\x03 \x01(\x0b\x32\x1a.compute_s3_sink.RawObjectH\x00\x42\x08\n\x06\x66ormat\"\x18\n\tRawObject\x12\x0b\n\x03key\x18\x01 \x01(\t\"{\n\tZipObject\x12\x31\n\nsingleFile\x18\x01 \x01(\x0b\x32\x1b.compute_s3_sink.SingleFileH\x00\x12\x33\n\x0b\x66ullContent\x18\x02 \x01(\x0b\x32\x1c.compute_s3_sink.FullContentH\x00\x42\x06\n\x04kind\"\'\n\nSingleFile\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\x0c\n\x04path\x18\x02 \x01(\t\"\r\n\x0b\x46ullContent\"5\n\rS3Credentials\x12\x11\n\taccessKey\x18\x01 \x01(\t\x12\x11\n\tsecretKey\x18\x02 \x01(\tb\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'compute_s3_sink_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _S3SINKWORKERCONFIGURATION._serialized_start=43
  _S3SINKWORKERCONFIGURATION._serialized_end=179
  _S3OBJECT._serialized_start=181
  _S3OBJECT._serialized_end=307
  _RAWOBJECT._serialized_start=309
  _RAWOBJECT._serialized_end=333
  _ZIPOBJECT._serialized_start=335
  _ZIPOBJECT._serialized_end=458
  _SINGLEFILE._serialized_start=460
  _SINGLEFILE._serialized_end=499
  _FULLCONTENT._serialized_start=501
  _FULLCONTENT._serialized_end=514
  _S3CREDENTIALS._serialized_start=516
  _S3CREDENTIALS._serialized_end=569
# @@protoc_insertion_point(module_scope)