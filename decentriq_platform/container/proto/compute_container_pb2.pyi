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
import typing

if sys.version_info >= (3, 8):
    import typing as typing_extensions
else:
    import typing_extensions

DESCRIPTOR: google.protobuf.descriptor.FileDescriptor

class ContainerWorkerConfiguration(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    STATIC_FIELD_NUMBER: builtins.int
    @property
    def static(self) -> global___StaticImage: ...
    def __init__(
        self,
        *,
        static: global___StaticImage | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["configuration", b"configuration", "static", b"static"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["configuration", b"configuration", "static", b"static"]) -> None: ...
    def WhichOneof(self, oneof_group: typing_extensions.Literal["configuration", b"configuration"]) -> typing_extensions.Literal["static"] | None: ...

global___ContainerWorkerConfiguration = ContainerWorkerConfiguration

class StaticImage(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    COMMAND_FIELD_NUMBER: builtins.int
    MOUNTPOINTS_FIELD_NUMBER: builtins.int
    OUTPUTPATH_FIELD_NUMBER: builtins.int
    INCLUDECONTAINERLOGSONERROR_FIELD_NUMBER: builtins.int
    INCLUDECONTAINERLOGSONSUCCESS_FIELD_NUMBER: builtins.int
    MINIMUMCONTAINERMEMORYSIZE_FIELD_NUMBER: builtins.int
    EXTRACHUNKCACHESIZETOAVAILABLEMEMORYRATIO_FIELD_NUMBER: builtins.int
    @property
    def command(self) -> google.protobuf.internal.containers.RepeatedScalarFieldContainer[builtins.str]: ...
    @property
    def mountPoints(self) -> google.protobuf.internal.containers.RepeatedCompositeFieldContainer[global___MountPoint]: ...
    outputPath: builtins.str
    includeContainerLogsOnError: builtins.bool
    includeContainerLogsOnSuccess: builtins.bool
    minimumContainerMemorySize: builtins.int
    """When executing a computation, the available VM memory is split into two:
    1. One part given to the in-memory chunk cache (this is backing the /input and /output filesystems, analogous to
        the kernel's pagecache).
    2. The second part is given to the container itself.
    The sizes are controlled by minimumContainerMemorySize and extraChunkCacheSizeToAvailableMemoryRatio.
    First minimumContainerMemorySize and a hardcoded minimum chunk cache size is subtracted from the available memory,
    then the rest is split according to extraChunkCacheSizeToAvailableMemoryRatio.
    For example, given a 64G VM with 62G available memory for compute:
    * minimumContainerMemorySize by default is 2G
    * minimum chunk cache size is 256M
    * extraChunkCacheSizeToAvailableMemoryRatio by default is 0.0625
    * therefore 0.0625 * (62G - 2G - 256M) =~ 3730M further memory is given to the chunk cache
    * so we end up with chunk_cache_size ~= 4G, container_memory ~=58G
    Generally speaking the split should be determined by the computation itself:
    * Example SQLite: SQLite is memory-bound generally speaking and does a lot of back-and-forth between its
        in-memory cache and the db file. This means that high extraChunkCacheSizeToAvailableMemoryRatio(1.0) and low
        minimumContainerMemorySize should be used because this will speed up the file backing, and SQLite doesn't use
        the extra container memory efficiently.
    * Example CHUV pipeline: this computation accesses sparse static input genome data in a fairly random manner,
        meaning that the best course of action is to read all data into memory first instead of relying on the chunk
        cache backed filesystem. This means low extraChunkCacheSizeToAvailableMemoryRatio(1.0) should be used.
        A setting of 1.0 means that all available extra memory (aside from the minimum chunk cache size) will be
        given to the container.
    * Example default settings: by default most but not all of the memory is given to the container, assuming that
        most applications tend to read the input files into memory as a first step instead of streaming through.
    default 2G
    """
    extraChunkCacheSizeToAvailableMemoryRatio: builtins.float
    """default 0.0625"""
    def __init__(
        self,
        *,
        command: collections.abc.Iterable[builtins.str] | None = ...,
        mountPoints: collections.abc.Iterable[global___MountPoint] | None = ...,
        outputPath: builtins.str = ...,
        includeContainerLogsOnError: builtins.bool = ...,
        includeContainerLogsOnSuccess: builtins.bool = ...,
        minimumContainerMemorySize: builtins.int | None = ...,
        extraChunkCacheSizeToAvailableMemoryRatio: builtins.float | None = ...,
    ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["_extraChunkCacheSizeToAvailableMemoryRatio", b"_extraChunkCacheSizeToAvailableMemoryRatio", "_minimumContainerMemorySize", b"_minimumContainerMemorySize", "extraChunkCacheSizeToAvailableMemoryRatio", b"extraChunkCacheSizeToAvailableMemoryRatio", "minimumContainerMemorySize", b"minimumContainerMemorySize"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["_extraChunkCacheSizeToAvailableMemoryRatio", b"_extraChunkCacheSizeToAvailableMemoryRatio", "_minimumContainerMemorySize", b"_minimumContainerMemorySize", "command", b"command", "extraChunkCacheSizeToAvailableMemoryRatio", b"extraChunkCacheSizeToAvailableMemoryRatio", "includeContainerLogsOnError", b"includeContainerLogsOnError", "includeContainerLogsOnSuccess", b"includeContainerLogsOnSuccess", "minimumContainerMemorySize", b"minimumContainerMemorySize", "mountPoints", b"mountPoints", "outputPath", b"outputPath"]) -> None: ...
    @typing.overload
    def WhichOneof(self, oneof_group: typing_extensions.Literal["_extraChunkCacheSizeToAvailableMemoryRatio", b"_extraChunkCacheSizeToAvailableMemoryRatio"]) -> typing_extensions.Literal["extraChunkCacheSizeToAvailableMemoryRatio"] | None: ...
    @typing.overload
    def WhichOneof(self, oneof_group: typing_extensions.Literal["_minimumContainerMemorySize", b"_minimumContainerMemorySize"]) -> typing_extensions.Literal["minimumContainerMemorySize"] | None: ...

global___StaticImage = StaticImage

class MountPoint(google.protobuf.message.Message):
    """Dependencies are mounted under the `/input` directory
    For example for a mount point entry { path: "/data", dependency: "dep" }
    the worker will mount the dependency `dep` at path `/input/data`
    """

    DESCRIPTOR: google.protobuf.descriptor.Descriptor

    PATH_FIELD_NUMBER: builtins.int
    DEPENDENCY_FIELD_NUMBER: builtins.int
    path: builtins.str
    dependency: builtins.str
    def __init__(
        self,
        *,
        path: builtins.str = ...,
        dependency: builtins.str = ...,
    ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["dependency", b"dependency", "path", b"path"]) -> None: ...

global___MountPoint = MountPoint
