"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""
import builtins
import collections.abc
import google.protobuf.descriptor
import google.protobuf.internal.containers
import google.protobuf.internal.enum_type_wrapper
import google.protobuf.message
import sys
import typing

if sys.version_info >= (3, 10):
    import typing as typing_extensions
else:
    import typing_extensions

DESCRIPTOR: google.protobuf.descriptor.FileDescriptor

class _PrimitiveType:
    ValueType = typing.NewType("ValueType", builtins.int)
    V: typing_extensions.TypeAlias = ValueType

class _PrimitiveTypeEnumTypeWrapper(google.protobuf.internal.enum_type_wrapper._EnumTypeWrapper[_PrimitiveType.ValueType], builtins.type):
    DESCRIPTOR: google.protobuf.descriptor.EnumDescriptor
    INT64: _PrimitiveType.ValueType  # 0
    STRING: _PrimitiveType.ValueType  # 1
    FLOAT64: _PrimitiveType.ValueType  # 2

class PrimitiveType(_PrimitiveType, metaclass=_PrimitiveTypeEnumTypeWrapper): ...

INT64: PrimitiveType.ValueType  # 0
STRING: PrimitiveType.ValueType  # 1
FLOAT64: PrimitiveType.ValueType  # 2
global___PrimitiveType = PrimitiveType

@typing_extensions.final
class SqlWorkerConfiguration(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    VALIDATION_FIELD_NUMBER: builtins.int
    COMPUTATION_FIELD_NUMBER: builtins.int
    @property
    def validation(self) -> global___ValidationConfiguration: ...
    @property
    def computation(self) -> global___ComputationConfiguration: ...
    def __init__(
        self,
        *,
        validation: global___ValidationConfiguration | None = ...,
        computation: global___ComputationConfiguration | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["computation", b"computation", "configuration", b"configuration", "validation", b"validation"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["computation", b"computation", "configuration", b"configuration", "validation", b"validation"]) -> None: ...
    def WhichOneof(self, oneof_group: typing_extensions.Literal["configuration", b"configuration"]) -> typing_extensions.Literal["validation", "computation"] | None: ...

global___SqlWorkerConfiguration = SqlWorkerConfiguration

@typing_extensions.final
class ValidationConfiguration(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    TABLESCHEMA_FIELD_NUMBER: builtins.int
    @property
    def tableSchema(self) -> global___TableSchema: ...
    def __init__(
        self,
        *,
        tableSchema: global___TableSchema | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["tableSchema", b"tableSchema"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["tableSchema", b"tableSchema"]) -> None: ...

global___ValidationConfiguration = ValidationConfiguration

@typing_extensions.final
class TableSchema(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    NAMEDCOLUMNS_FIELD_NUMBER: builtins.int
    @property
    def namedColumns(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___NamedColumn]: ...
    def __init__(
        self,
        *,
        namedColumns: collections.abc.Iterable[global___NamedColumn] | None = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["namedColumns", b"namedColumns"]) -> None: ...

global___TableSchema = TableSchema

@typing_extensions.final
class NamedColumn(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    NAME_FIELD_NUMBER: builtins.int
    COLUMNTYPE_FIELD_NUMBER: builtins.int
    name: builtins.str
    @property
    def columnType(self) -> global___ColumnType: ...
    def __init__(
        self,
        *,
        name: builtins.str | None = ...,
        columnType: global___ColumnType | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["_name", b"_name", "columnType", b"columnType", "name", b"name"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["_name", b"_name", "columnType", b"columnType", "name", b"name"]) -> None: ...
    def WhichOneof(self, oneof_group: typing_extensions.Literal["_name", b"_name"]) -> typing_extensions.Literal["name"] | None: ...

global___NamedColumn = NamedColumn

@typing_extensions.final
class ColumnType(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    PRIMITIVETYPE_FIELD_NUMBER: builtins.int
    NULLABLE_FIELD_NUMBER: builtins.int
    primitiveType: global___PrimitiveType.ValueType
    nullable: builtins.bool
    def __init__(
        self,
        *,
        primitiveType: global___PrimitiveType.ValueType = ...,
        nullable: builtins.bool = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["nullable", b"nullable", "primitiveType", b"primitiveType"]) -> None: ...

global___ColumnType = ColumnType

@typing_extensions.final
class TableDependencyMapping(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    TABLE_FIELD_NUMBER: builtins.int
    DEPENDENCY_FIELD_NUMBER: builtins.int
    table: builtins.str
    """Name of the table as it appears in the SQL query string"""
    dependency: builtins.str
    """ID of the compute/data node that provides data for this table"""
    def __init__(
        self,
        *,
        table: builtins.str = ...,
        dependency: builtins.str = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["dependency", b"dependency", "table", b"table"]) -> None: ...

global___TableDependencyMapping = TableDependencyMapping

@typing_extensions.final
class ComputationConfiguration(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    SQLSTATEMENT_FIELD_NUMBER: builtins.int
    PRIVACYSETTINGS_FIELD_NUMBER: builtins.int
    CONSTRAINTS_FIELD_NUMBER: builtins.int
    TABLEDEPENDENCYMAPPINGS_FIELD_NUMBER: builtins.int
    sqlStatement: builtins.str
    @property
    def privacySettings(self) -> global___PrivacySettings: ...
    @property
    def constraints(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___Constraint]: ...
    @property
    def tableDependencyMappings(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___TableDependencyMapping]: ...
    def __init__(
        self,
        *,
        sqlStatement: builtins.str = ...,
        privacySettings: global___PrivacySettings | None = ...,
        constraints: collections.abc.Iterable[global___Constraint] | None = ...,
        tableDependencyMappings: collections.abc.Iterable[global___TableDependencyMapping] | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["privacySettings", b"privacySettings"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["constraints", b"constraints", "privacySettings", b"privacySettings", "sqlStatement", b"sqlStatement", "tableDependencyMappings", b"tableDependencyMappings"]) -> None: ...

global___ComputationConfiguration = ComputationConfiguration

@typing_extensions.final
class PrivacySettings(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    MINAGGREGATIONGROUPSIZE_FIELD_NUMBER: builtins.int
    minAggregationGroupSize: builtins.int
    def __init__(
        self,
        *,
        minAggregationGroupSize: builtins.int = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["minAggregationGroupSize", b"minAggregationGroupSize"]) -> None: ...

global___PrivacySettings = PrivacySettings

@typing_extensions.final
class Constraint(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    DESCRIPTION_FIELD_NUMBER: builtins.int
    description: builtins.str
    def __init__(
        self,
        *,
        description: builtins.str = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["description", b"description"]) -> None: ...

global___Constraint = Constraint