from enum import Enum
from abc import abstractmethod
from collections.abc import Iterator
from typing import List, Tuple

import chily
from typing_extensions import TypedDict
from Crypto.Hash import SHA256

MAX_CHUNK_SIZE = 8*1024*1024  # 1MB
CHARSET = "utf-8"


class FileManifestMetadata(TypedDict):
    name: str
    manifestHash: str
    format: str
    encrypted: bool
    chunks: List[str]


class FileManifest:
    def __init__(self, chunks: List[str]):
        self.content = '\n'.join(chunks).encode(CHARSET)
        manifest_hasher = SHA256.new()
        manifest_hasher.update(self.content)
        manifest_hash = manifest_hasher.hexdigest()
        self.hash = manifest_hash


class FileFormat(Enum):
    CSV = "CSV"


class FileManifestBuilder:
    def __init__(self, file_name: str, data_format: FileFormat, is_data_encrypted: bool):
        self.name: str = file_name
        self.format: FileFormat = data_format
        self.encrypted: bool = is_data_encrypted
        self.chunks: List[str] = list()

    def add_chunk(self, chunk: str):
        self.chunks.append(chunk)

    def build(self) -> Tuple[FileManifest, FileManifestMetadata]:
        manifest = FileManifest(self.chunks)
        manifest_metadata = FileManifestMetadata(
                name=self.name,
                manifestHash=manifest.hash,
                format=self.format.value,
                encrypted=self.encrypted,
                chunks=self.chunks
            )
        return manifest, manifest_metadata


class ChunkDescription(TypedDict):
    chunkHash: str
    uploaded: bool


class FileDescription(TypedDict):
    id: str
    manifestHash: str
    filename: str
    chunks: List[ChunkDescription]


class Chunker(Iterator):
    class CannotChunkFileError(Exception):
        """Raised when the input file is not chunk-able"""
        pass

    @abstractmethod
    def open(self):
        pass

    @abstractmethod
    def close(self):
        pass

    @abstractmethod
    def reset(self):
        pass


class CsvChunker(Chunker):
    NEWLINE_BC = len('\n'.encode(CHARSET))  # Newline Byte Count (should always be 1)

    class CannotChunkError(Exception):
        """Raised when the input file is not chunk-able"""
        pass

    def __init__(self, csv_file_path: str, chunk_size: int):
        self.chunk_size = chunk_size
        self.csv_file_path = csv_file_path
        self.csv_file_handle = None

    def open(self):
        self.csv_file_handle = open(self.csv_file_path)

    def close(self):
        self.csv_file_handle.close()

    def reset(self):
        self.csv_file_handle.seek(0)

    def __next__(self) -> Tuple[str, bytes]:
        current_chunk_size = 0
        chunk = []
        if self.csv_file_handle is None:
            raise CsvChunker.CannotChunkError
        for line in self.csv_file_handle:
            line_bytes = line.encode(CHARSET)
            if current_chunk_size + len(line_bytes) + CsvChunker.NEWLINE_BC > self.chunk_size:
                break
            current_chunk_size += len(line_bytes)
            chunk.append(line)
        else:
            if current_chunk_size == 0:
                raise StopIteration
        if current_chunk_size == 0:
            raise self.CannotChunkFileError
        chunk = ''.join(chunk).encode(CHARSET)
        chunk_hash = SHA256.new(chunk)
        return chunk_hash.hexdigest(), chunk


class ChunkerBuilder:
    class CannotBuildChunkerError(Exception):
        """Raised when the input file is not chunk-able"""
        pass
    def __init__(
        self,
        file_path: str,
        file_format: FileFormat,
        chunk_size: int = MAX_CHUNK_SIZE
    ):
        if file_format == FileFormat.CSV:
            self.chunker = CsvChunker(file_path, chunk_size)
        else:
            raise ChunkerBuilder.CannotBuildChunkerError

    def __enter__(
        self,
    ) -> Chunker:
        self.chunker.open()
        return self.chunker

    def __exit__(self, exception_type, exception_value, traceback):
        self.chunker.close()


class StorageCipher:
    def __init__(self, symmetric_key):
        self.enc_key = symmetric_key
        self.enc_key_hash = SHA256.new(symmetric_key).digest()
        self.cipher: chily.Cipher = chily.Cipher.from_symmetric(self.enc_key)

    def encrypt(self, data: bytes):
        nonce = chily.Nonce.from_random()
        enc_data = self.cipher.encrypt(data, nonce)
        return bytes(list(self.enc_key_hash)+nonce.bytes+enc_data)
