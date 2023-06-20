"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""
import builtins
import collections.abc
import google.protobuf.descriptor
import google.protobuf.internal.containers
import google.protobuf.message
import sys

if sys.version_info >= (3, 8):
    import typing as typing_extensions
else:
    import typing_extensions

DESCRIPTOR: google.protobuf.descriptor.FileDescriptor

class RawFile(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    def __init__(
        self,
    ) -> None: ...

global___RawFile = RawFile

class AllFiles(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    def __init__(
        self,
    ) -> None: ...

global___AllFiles = AllFiles

class SingleFile(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    NAME_FIELD_NUMBER: builtins.int
    RENAMEAS_FIELD_NUMBER: builtins.int
    name: builtins.str
    renameAs: builtins.str
    def __init__(
        self,
        *,
        name: builtins.str = ...,
        renameAs: builtins.str | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["_renameAs", b"_renameAs", "renameAs", b"renameAs"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["_renameAs", b"_renameAs", "name", b"name", "renameAs", b"renameAs"]) -> None: ...
    def WhichOneof(self, oneof_group: typing_extensions.Literal["_renameAs", b"_renameAs"]) -> typing_extensions.Literal["renameAs"] | None: ...

global___SingleFile = SingleFile

class FileSelection(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    NAMES_FIELD_NUMBER: builtins.int
    @property
    def names(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___SingleFile]: ...
    def __init__(
        self,
        *,
        names: collections.abc.Iterable[global___SingleFile] | None = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["names", b"names"]) -> None: ...

global___FileSelection = FileSelection

class ZipFile(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    ALL_FIELD_NUMBER: builtins.int
    FILES_FIELD_NUMBER: builtins.int
    @property
    def all(self) -> global___AllFiles: ...
    @property
    def files(self) -> global___FileSelection: ...
    def __init__(
        self,
        *,
        all: global___AllFiles | None = ...,
        files: global___FileSelection | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["all", b"all", "files", b"files", "selection", b"selection"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["all", b"all", "files", b"files", "selection", b"selection"]) -> None: ...
    def WhichOneof(self, oneof_group: typing_extensions.Literal["selection", b"selection"]) -> typing_extensions.Literal["all", "files"] | None: ...

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

class DatasetSinkWorkerConfiguration(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    INPUTS_FIELD_NUMBER: builtins.int
    ENCRYPTIONKEYDEPENDENCY_FIELD_NUMBER: builtins.int
    DATASETIMPORTID_FIELD_NUMBER: builtins.int
    ISKEYHEXENCODED_FIELD_NUMBER: builtins.int
    @property
    def inputs(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___SinkInput]: ...
    encryptionKeyDependency: builtins.str
    """The id of the leaf node that contains the encryption key"""
    datasetImportId: builtins.str
    isKeyHexEncoded: builtins.bool
    """Whether the key provided in `encryptionKeyDependency` is hex encoded or binary"""
    def __init__(
        self,
        *,
        inputs: collections.abc.Iterable[global___SinkInput] | None = ...,
        encryptionKeyDependency: builtins.str = ...,
        datasetImportId: builtins.str | None = ...,
        isKeyHexEncoded: builtins.bool = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["_datasetImportId", b"_datasetImportId", "datasetImportId", b"datasetImportId"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["_datasetImportId", b"_datasetImportId", "datasetImportId", b"datasetImportId", "encryptionKeyDependency", b"encryptionKeyDependency", "inputs", b"inputs", "isKeyHexEncoded", b"isKeyHexEncoded"]) -> None: ...
    def WhichOneof(self, oneof_group: typing_extensions.Literal["_datasetImportId", b"_datasetImportId"]) -> typing_extensions.Literal["datasetImportId"] | None: ...

global___DatasetSinkWorkerConfiguration = DatasetSinkWorkerConfiguration
