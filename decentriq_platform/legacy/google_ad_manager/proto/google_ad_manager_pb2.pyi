"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""
import builtins
import google.protobuf.descriptor
import google.protobuf.message
import sys

if sys.version_info >= (3, 8):
    import typing as typing_extensions
else:
    import typing_extensions

DESCRIPTOR: google.protobuf.descriptor.FileDescriptor

@typing_extensions.final
class SingleFile(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    NAME_FIELD_NUMBER: builtins.int
    name: builtins.str
    def __init__(
        self,
        *,
        name: builtins.str = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["name", b"name"]) -> None: ...

global___SingleFile = SingleFile

@typing_extensions.final
class RawFile(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    def __init__(
        self,
    ) -> None: ...

global___RawFile = RawFile

@typing_extensions.final
class ZipFile(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    SINGLEFILE_FIELD_NUMBER: builtins.int
    @property
    def singleFile(self) -> global___SingleFile: ...
    def __init__(
        self,
        *,
        singleFile: global___SingleFile | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["selection", b"selection", "singleFile", b"singleFile"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["selection", b"selection", "singleFile", b"singleFile"]) -> None: ...
    def WhichOneof(self, oneof_group: typing_extensions.Literal["selection", b"selection"]) -> typing_extensions.Literal["singleFile"] | None: ...

global___ZipFile = ZipFile

@typing_extensions.final
class SinkInput(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    DEPENDENCY_FIELD_NUMBER: builtins.int
    NAME_FIELD_NUMBER: builtins.int
    RAW_FIELD_NUMBER: builtins.int
    ZIP_FIELD_NUMBER: builtins.int
    dependency: builtins.str
    name: builtins.str
    @property
    def raw(self) -> global___RawFile: ...
    @property
    def zip(self) -> global___ZipFile: ...
    def __init__(
        self,
        *,
        dependency: builtins.str = ...,
        name: builtins.str = ...,
        raw: global___RawFile | None = ...,
        zip: global___ZipFile | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["file", b"file", "raw", b"raw", "zip", b"zip"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["dependency", b"dependency", "file", b"file", "name", b"name", "raw", b"raw", "zip", b"zip"]) -> None: ...
    def WhichOneof(self, oneof_group: typing_extensions.Literal["file", b"file"]) -> typing_extensions.Literal["raw", "zip"] | None: ...

global___SinkInput = SinkInput

@typing_extensions.final
class GoogleAdManagerWorkerConfiguration(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    INPUT_FIELD_NUMBER: builtins.int
    CREDENTIALSDEPENDENCY_FIELD_NUMBER: builtins.int
    IDENTIFIERKIND_FIELD_NUMBER: builtins.int
    LISTID_FIELD_NUMBER: builtins.int
    INPUTHASHEADERS_FIELD_NUMBER: builtins.int
    BUCKET_FIELD_NUMBER: builtins.int
    OBJECTNAME_FIELD_NUMBER: builtins.int
    @property
    def input(self) -> global___SinkInput: ...
    credentialsDependency: builtins.str
    identifierKind: builtins.str
    listId: builtins.str
    inputHasHeaders: builtins.bool
    bucket: builtins.str
    """Google Cloud Storage configuration"""
    objectName: builtins.str
    def __init__(
        self,
        *,
        input: global___SinkInput | None = ...,
        credentialsDependency: builtins.str = ...,
        identifierKind: builtins.str = ...,
        listId: builtins.str = ...,
        inputHasHeaders: builtins.bool = ...,
        bucket: builtins.str = ...,
        objectName: builtins.str = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["input", b"input"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["bucket", b"bucket", "credentialsDependency", b"credentialsDependency", "identifierKind", b"identifierKind", "input", b"input", "inputHasHeaders", b"inputHasHeaders", "listId", b"listId", "objectName", b"objectName"]) -> None: ...

global___GoogleAdManagerWorkerConfiguration = GoogleAdManagerWorkerConfiguration
