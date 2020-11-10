import json
from enum import Enum
from abc import abstractmethod
from collections.abc import Iterator
from typing import List, Tuple, Any
import os
import logging
from .proto.avato_enclave_pb2 import EncryptionHeader, VersionHeader, ChunkHeader
from .proto.csv_table_format_pb2 import CsvTableFormat
from .proto.column_type_pb2 import ColumnType
from .proto.length_delimited import serialize_length_delimited

import chily
from typing_extensions import TypedDict
from hashlib import sha256

MAX_CHUNK_SIZE = 8 * 1024 * 1024
CHARSET = "utf-8"


class DatasetManifestMetadata(TypedDict):
    name: str
    manifestHash: str
    format: str
    encrypted: bool
    chunks: List[str]


class DatasetManifest(TypedDict):
    digestHash: str
    schema: List[Tuple[str, int]]


def create_csv_chunk_header(extra_entropy: bytes) -> bytes:
    chunk_header = ChunkHeader()
    chunk_header.extraEntropy = extra_entropy
    chunk_header.formatIdentifier = "CsvTable"

    chunk_header_bytes = serialize_length_delimited(chunk_header)
    return chunk_header_bytes


def create_version_header() -> bytes:
    version_header = VersionHeader()
    version_header.version = 0
    return serialize_length_delimited(version_header)


def create_json_chunk_header(extra_entropy: bytes) -> bytes:
    chunk_header = ChunkHeader()
    chunk_header.extraEntropy = extra_entropy
    chunk_header.formatIdentifier = "JsonObject"
    chunk_header_bytes = serialize_length_delimited(chunk_header)

    return chunk_header_bytes


# Returns (integrity hash, encrypted blob)
def create_encrypted_json_object_chunk(key: bytes, extra_entropy: bytes, object: Any) -> Tuple[str, bytes]:
    chunk_bytes = []

    version_header = create_version_header()
    chunk_bytes.append(version_header)

    chunk_header = create_json_chunk_header(extra_entropy)
    chunk_bytes.append(chunk_header)

    object_json = json.dumps(object).encode("utf-8")
    chunk_bytes.append(object_json)

    chunk = b''.join(chunk_bytes)
    chunk_hasher = sha256()
    chunk_hasher.update(chunk)
    chunk_hash = chunk_hasher.hexdigest()

    cipher = StorageCipher(key)
    encrypted_chunk = cipher.encrypt(chunk)

    return chunk_hash, encrypted_chunk


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
    class CannotChunkError(Exception):
        """Raised when the input file is not chunk-able"""
        pass

    def __init__(self, csv_file_path: str, csv_column_types: List[int], extra_entropy: bytes, chunk_size: int):
        self.chunk_size = chunk_size
        self.csv_file_path = csv_file_path
        self.csv_column_types = csv_column_types
        self.extra_entropy = extra_entropy
        self.csv_file_handle = None
        self.offset_to_chunk_hash_map = dict()
        self.current_offset = 0
        self.file_size = 0

    def open(self):
        self.csv_file_handle = open(self.csv_file_path, "r", buffering=8*1024**2)
        self.file_size = os.path.getsize(self.csv_file_path)
        self.current_offset = 0

    def close(self):
        self.csv_file_handle.close()
        self.current_offset = 0

    def reset(self):
        self.csv_file_handle.seek(0)
        self.current_offset = 0

    def __next__(self) -> Tuple[str, bytes]:
        logging.debug("[", 100 * self.current_offset / self.file_size, "]")
        version_header_bytes = create_version_header()
        chunk_header_bytes = create_csv_chunk_header(self.extra_entropy)

        csv_table_format = CsvTableFormat()
        csv_table_format.columnTypes.extend(self.csv_column_types)
        csv_table_format_bytes = serialize_length_delimited(csv_table_format)

        if self.current_offset in self.offset_to_chunk_hash_map:
            chunk_size = self.offset_to_chunk_hash_map[self.current_offset][0]
            chunk_data = b''.join([
                version_header_bytes,
                chunk_header_bytes,
                csv_table_format_bytes,
                self.csv_file_handle.read(chunk_size).encode(CHARSET),
            ])
            chunk_hash = self.offset_to_chunk_hash_map[self.current_offset][1]
            self.current_offset += chunk_size
            return chunk_hash, chunk_data
        if self.csv_file_handle is None:
            raise CsvChunker.CannotChunkError

        # Does not account for header size
        current_chunk_size = 0
        starting_offset = self.current_offset
        chunk_bytes = [version_header_bytes, chunk_header_bytes, csv_table_format_bytes]

        for line in self.csv_file_handle:
            line_bytes = line.encode(CHARSET)
            current_chunk_size += len(line_bytes)
            self.current_offset += len(line)
            chunk_bytes.append(line_bytes)
            if current_chunk_size > self.chunk_size:
                break
        else:
            if current_chunk_size == 0:
                raise StopIteration
        if current_chunk_size == 0:
            raise self.CannotChunkFileError
        chunk = b''.join(chunk_bytes)
        chunk_hasher = sha256()
        chunk_hasher.update(chunk)
        chunk_hash = chunk_hasher.hexdigest()
        self.offset_to_chunk_hash_map[starting_offset]=(self.current_offset-starting_offset, chunk_hash)
        return chunk_hash, chunk


class CsvChunkerBuilder:
    class CannotBuildChunkerError(Exception):
        """Raised when the input file is not chunk-able"""
        pass

    def __init__(
            self,
            file_path: str,
            column_types: List[int],
            extra_entropy: bytes,
            chunk_size: int,
    ):
        self.chunker = CsvChunker(file_path, column_types, extra_entropy, chunk_size)

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
        self.enc_key_hash = sha256(symmetric_key).digest()
        self.cipher: chily.Cipher = chily.Cipher.from_symmetric(self.enc_key)

    def encrypt(self, data: bytes):
        nonce = chily.Nonce.from_random()
        encrypted_data = self.cipher.encrypt(data, nonce)

        encryption_header = EncryptionHeader()
        encryption_header.chily_key.key_sha256 = self.enc_key_hash
        encryption_header.chily_key.encryption_nonce = bytes(nonce.bytes)

        serialized_encryption_header = serialize_length_delimited(encryption_header)
        encrypted_data_with_header = bytes(list(serialized_encryption_header) + encrypted_data)
        return encrypted_data_with_header
