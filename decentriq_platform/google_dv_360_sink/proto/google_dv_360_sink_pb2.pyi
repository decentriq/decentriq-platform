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

class RawFile(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    def __init__(
        self,
    ) -> None: ...

global___RawFile = RawFile

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

class GoogleDv360SinkWorkerConfiguration(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    INPUT_FIELD_NUMBER: builtins.int
    CREDENTIALSDEPENDENCY_FIELD_NUMBER: builtins.int
    ADVERTISERID_FIELD_NUMBER: builtins.int
    DISPLAYNAME_FIELD_NUMBER: builtins.int
    DESCRIPTION_FIELD_NUMBER: builtins.int
    MEMBERSHIPDURATIONDAYS_FIELD_NUMBER: builtins.int
    @property
    def input(self) -> global___SinkInput: ...
    credentialsDependency: builtins.str
    advertiserId: builtins.str
    displayName: builtins.str
    description: builtins.str
    membershipDurationDays: builtins.str
    def __init__(
        self,
        *,
        input: global___SinkInput | None = ...,
        credentialsDependency: builtins.str = ...,
        advertiserId: builtins.str = ...,
        displayName: builtins.str = ...,
        description: builtins.str = ...,
        membershipDurationDays: builtins.str = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["input", b"input"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["advertiserId", b"advertiserId", "credentialsDependency", b"credentialsDependency", "description", b"description", "displayName", b"displayName", "input", b"input", "membershipDurationDays", b"membershipDurationDays"]) -> None: ...

global___GoogleDv360SinkWorkerConfiguration = GoogleDv360SinkWorkerConfiguration
