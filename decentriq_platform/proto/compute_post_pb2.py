# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: compute_post.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x12\x63ompute_post.proto\x12\x0c\x63ompute_post\"1\n\x17PostWorkerConfiguration\x12\x16\n\x0euseMockBackend\x18\x01 \x01(\x08\x62\x06proto3')



_POSTWORKERCONFIGURATION = DESCRIPTOR.message_types_by_name['PostWorkerConfiguration']
PostWorkerConfiguration = _reflection.GeneratedProtocolMessageType('PostWorkerConfiguration', (_message.Message,), {
  'DESCRIPTOR' : _POSTWORKERCONFIGURATION,
  '__module__' : 'compute_post_pb2'
  # @@protoc_insertion_point(class_scope:compute_post.PostWorkerConfiguration)
  })
_sym_db.RegisterMessage(PostWorkerConfiguration)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _POSTWORKERCONFIGURATION._serialized_start=36
  _POSTWORKERCONFIGURATION._serialized_end=85
# @@protoc_insertion_point(module_scope)
