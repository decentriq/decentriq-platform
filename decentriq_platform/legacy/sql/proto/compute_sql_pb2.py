# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: compute_sql.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x11\x63ompute_sql.proto\x12\x0b\x63ompute_sql\"\xa3\x01\n\x16SqlWorkerConfiguration\x12:\n\nvalidation\x18\x01 \x01(\x0b\x32$.compute_sql.ValidationConfigurationH\x00\x12<\n\x0b\x63omputation\x18\x02 \x01(\x0b\x32%.compute_sql.ComputationConfigurationH\x00\x42\x0f\n\rconfiguration\"H\n\x17ValidationConfiguration\x12-\n\x0btableSchema\x18\x01 \x01(\x0b\x32\x18.compute_sql.TableSchema\"=\n\x0bTableSchema\x12.\n\x0cnamedColumns\x18\x01 \x03(\x0b\x32\x18.compute_sql.NamedColumn\"V\n\x0bNamedColumn\x12\x11\n\x04name\x18\x01 \x01(\tH\x00\x88\x01\x01\x12+\n\ncolumnType\x18\x02 \x01(\x0b\x32\x17.compute_sql.ColumnTypeB\x07\n\x05_name\"Q\n\nColumnType\x12\x31\n\rprimitiveType\x18\x01 \x01(\x0e\x32\x1a.compute_sql.PrimitiveType\x12\x10\n\x08nullable\x18\x02 \x01(\x08\";\n\x16TableDependencyMapping\x12\r\n\x05table\x18\x01 \x01(\t\x12\x12\n\ndependency\x18\x02 \x01(\t\"\xdb\x01\n\x18\x43omputationConfiguration\x12\x14\n\x0csqlStatement\x18\x01 \x01(\t\x12\x35\n\x0fprivacySettings\x18\x02 \x01(\x0b\x32\x1c.compute_sql.PrivacySettings\x12,\n\x0b\x63onstraints\x18\x03 \x03(\x0b\x32\x17.compute_sql.Constraint\x12\x44\n\x17tableDependencyMappings\x18\x04 \x03(\x0b\x32#.compute_sql.TableDependencyMapping\"2\n\x0fPrivacySettings\x12\x1f\n\x17minAggregationGroupSize\x18\x01 \x01(\x03\"!\n\nConstraint\x12\x13\n\x0b\x64\x65scription\x18\x01 \x01(\t*3\n\rPrimitiveType\x12\t\n\x05INT64\x10\x00\x12\n\n\x06STRING\x10\x01\x12\x0b\n\x07\x46LOAT64\x10\x02\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'compute_sql_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  DESCRIPTOR._options = None
  _globals['_PRIMITIVETYPE']._serialized_start=878
  _globals['_PRIMITIVETYPE']._serialized_end=929
  _globals['_SQLWORKERCONFIGURATION']._serialized_start=35
  _globals['_SQLWORKERCONFIGURATION']._serialized_end=198
  _globals['_VALIDATIONCONFIGURATION']._serialized_start=200
  _globals['_VALIDATIONCONFIGURATION']._serialized_end=272
  _globals['_TABLESCHEMA']._serialized_start=274
  _globals['_TABLESCHEMA']._serialized_end=335
  _globals['_NAMEDCOLUMN']._serialized_start=337
  _globals['_NAMEDCOLUMN']._serialized_end=423
  _globals['_COLUMNTYPE']._serialized_start=425
  _globals['_COLUMNTYPE']._serialized_end=506
  _globals['_TABLEDEPENDENCYMAPPING']._serialized_start=508
  _globals['_TABLEDEPENDENCYMAPPING']._serialized_end=567
  _globals['_COMPUTATIONCONFIGURATION']._serialized_start=570
  _globals['_COMPUTATIONCONFIGURATION']._serialized_end=789
  _globals['_PRIVACYSETTINGS']._serialized_start=791
  _globals['_PRIVACYSETTINGS']._serialized_end=841
  _globals['_CONSTRAINT']._serialized_start=843
  _globals['_CONSTRAINT']._serialized_end=876
# @@protoc_insertion_point(module_scope)
