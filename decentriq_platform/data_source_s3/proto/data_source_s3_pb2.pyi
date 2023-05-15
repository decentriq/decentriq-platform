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

class S3Source(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    BUCKET_FIELD_NUMBER: builtins.int
    REGION_FIELD_NUMBER: builtins.int
    OBJECTKEY_FIELD_NUMBER: builtins.int
    bucket: builtins.str
    region: builtins.str
    objectKey: builtins.str
    def __init__(
        self,
        *,
        bucket: builtins.str = ...,
        region: builtins.str = ...,
        objectKey: builtins.str = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["bucket", b"bucket", "objectKey", b"objectKey", "region", b"region"]) -> None: ...

global___S3Source = S3Source

class DataSourceS3WorkerConfiguration(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    SOURCE_FIELD_NUMBER: builtins.int
    CREDENTIALSDEPENDENCY_FIELD_NUMBER: builtins.int
    @property
    def source(self) -> global___S3Source: ...
    credentialsDependency: builtins.str
    def __init__(
        self,
        *,
        source: global___S3Source | None = ...,
        credentialsDependency: builtins.str = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["source", b"source"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["credentialsDependency", b"credentialsDependency", "source", b"source"]) -> None: ...

global___DataSourceS3WorkerConfiguration = DataSourceS3WorkerConfiguration
