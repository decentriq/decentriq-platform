"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""
import builtins
import compute_sql_pb2
import google.protobuf.descriptor
import google.protobuf.internal.containers
import google.protobuf.internal.enum_type_wrapper
import google.protobuf.message
import typing
import typing_extensions

DESCRIPTOR: google.protobuf.descriptor.FileDescriptor

class SyntheticDataConf(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    COLUMNS_FIELD_NUMBER: builtins.int
    OUTPUTORIGINALDATASTATS_FIELD_NUMBER: builtins.int
    EPSILON_FIELD_NUMBER: builtins.int
    @property
    def columns(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___Column]: ...
    outputOriginalDataStats: builtins.bool
    epsilon: builtins.float
    def __init__(self,
        *,
        columns: typing.Optional[typing.Iterable[global___Column]] = ...,
        outputOriginalDataStats: builtins.bool = ...,
        epsilon: builtins.float = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["columns",b"columns","epsilon",b"epsilon","outputOriginalDataStats",b"outputOriginalDataStats"]) -> None: ...
global___SyntheticDataConf = SyntheticDataConf

class Mask(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    class _MaskFormat:
        ValueType = typing.NewType('ValueType', builtins.int)
        V: typing_extensions.TypeAlias = ValueType
    class _MaskFormatEnumTypeWrapper(google.protobuf.internal.enum_type_wrapper._EnumTypeWrapper[Mask._MaskFormat.ValueType], builtins.type):
        DESCRIPTOR: google.protobuf.descriptor.EnumDescriptor
        GENERIC_STRING: Mask._MaskFormat.ValueType  # 0
        GENERIC_NUMBER: Mask._MaskFormat.ValueType  # 1
        NAME: Mask._MaskFormat.ValueType  # 2
        ADDRESS: Mask._MaskFormat.ValueType  # 3
        POSTCODE: Mask._MaskFormat.ValueType  # 4
        PHONE_NUMBER: Mask._MaskFormat.ValueType  # 5
        SOCIAL_SECURITY_NUMBER: Mask._MaskFormat.ValueType  # 6
        EMAIL: Mask._MaskFormat.ValueType  # 7
        DATE: Mask._MaskFormat.ValueType  # 8
        TIMESTAMP: Mask._MaskFormat.ValueType  # 9
        IBAN: Mask._MaskFormat.ValueType  # 10
    class MaskFormat(_MaskFormat, metaclass=_MaskFormatEnumTypeWrapper):
        pass

    GENERIC_STRING: Mask.MaskFormat.ValueType  # 0
    GENERIC_NUMBER: Mask.MaskFormat.ValueType  # 1
    NAME: Mask.MaskFormat.ValueType  # 2
    ADDRESS: Mask.MaskFormat.ValueType  # 3
    POSTCODE: Mask.MaskFormat.ValueType  # 4
    PHONE_NUMBER: Mask.MaskFormat.ValueType  # 5
    SOCIAL_SECURITY_NUMBER: Mask.MaskFormat.ValueType  # 6
    EMAIL: Mask.MaskFormat.ValueType  # 7
    DATE: Mask.MaskFormat.ValueType  # 8
    TIMESTAMP: Mask.MaskFormat.ValueType  # 9
    IBAN: Mask.MaskFormat.ValueType  # 10

    FORMAT_FIELD_NUMBER: builtins.int
    format: global___Mask.MaskFormat.ValueType
    def __init__(self,
        *,
        format: global___Mask.MaskFormat.ValueType = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["format",b"format"]) -> None: ...
global___Mask = Mask

class Column(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    INDEX_FIELD_NUMBER: builtins.int
    TYPE_FIELD_NUMBER: builtins.int
    MASK_FIELD_NUMBER: builtins.int
    index: builtins.int
    @property
    def type(self) -> compute_sql_pb2.ColumnType: ...
    @property
    def mask(self) -> global___Mask: ...
    def __init__(self,
        *,
        index: builtins.int = ...,
        type: typing.Optional[compute_sql_pb2.ColumnType] = ...,
        mask: typing.Optional[global___Mask] = ...,
        ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["mask",b"mask","type",b"type"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["index",b"index","mask",b"mask","type",b"type"]) -> None: ...
global___Column = Column
