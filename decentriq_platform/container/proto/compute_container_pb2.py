# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: compute_container.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x17\x63ompute_container.proto\x12\x11\x63ompute_container\"a\n\x1c\x43ontainerWorkerConfiguration\x12\x30\n\x06static\x18\x01 \x01(\x0b\x32\x1e.compute_container.StaticImageH\x00\x42\x0f\n\rconfiguration\"\xb2\x01\n\x0bStaticImage\x12\x0f\n\x07\x63ommand\x18\x01 \x03(\t\x12\x32\n\x0bmountPoints\x18\x02 \x03(\x0b\x32\x1d.compute_container.MountPoint\x12\x12\n\noutputPath\x18\x03 \x01(\t\x12#\n\x1bincludeContainerLogsOnError\x18\x04 \x01(\x08\x12%\n\x1dincludeContainerLogsOnSuccess\x18\x05 \x01(\x08\".\n\nMountPoint\x12\x0c\n\x04path\x18\x01 \x01(\t\x12\x12\n\ndependency\x18\x02 \x01(\tb\x06proto3')



_CONTAINERWORKERCONFIGURATION = DESCRIPTOR.message_types_by_name['ContainerWorkerConfiguration']
_STATICIMAGE = DESCRIPTOR.message_types_by_name['StaticImage']
_MOUNTPOINT = DESCRIPTOR.message_types_by_name['MountPoint']
ContainerWorkerConfiguration = _reflection.GeneratedProtocolMessageType('ContainerWorkerConfiguration', (_message.Message,), {
  'DESCRIPTOR' : _CONTAINERWORKERCONFIGURATION,
  '__module__' : 'compute_container_pb2'
  # @@protoc_insertion_point(class_scope:compute_container.ContainerWorkerConfiguration)
  })
_sym_db.RegisterMessage(ContainerWorkerConfiguration)

StaticImage = _reflection.GeneratedProtocolMessageType('StaticImage', (_message.Message,), {
  'DESCRIPTOR' : _STATICIMAGE,
  '__module__' : 'compute_container_pb2'
  # @@protoc_insertion_point(class_scope:compute_container.StaticImage)
  })
_sym_db.RegisterMessage(StaticImage)

MountPoint = _reflection.GeneratedProtocolMessageType('MountPoint', (_message.Message,), {
  'DESCRIPTOR' : _MOUNTPOINT,
  '__module__' : 'compute_container_pb2'
  # @@protoc_insertion_point(class_scope:compute_container.MountPoint)
  })
_sym_db.RegisterMessage(MountPoint)

if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _CONTAINERWORKERCONFIGURATION._serialized_start=46
  _CONTAINERWORKERCONFIGURATION._serialized_end=143
  _STATICIMAGE._serialized_start=146
  _STATICIMAGE._serialized_end=324
  _MOUNTPOINT._serialized_start=326
  _MOUNTPOINT._serialized_end=372
# @@protoc_insertion_point(module_scope)
