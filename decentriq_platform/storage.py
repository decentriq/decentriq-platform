import json
import chily
import argon2
import os
from collections.abc import Iterator
from typing import List, Tuple, Any, Union
from decentriq_platform.proto.column_type_pb2 import ColumnType, PrimitiveType
from google.protobuf.message import Message
from .proto.avato_enclave_pb2 import EncryptionHeader, VersionHeader, ChunkHeader
from .proto.length_delimited import serialize_length_delimited
from .proto.csv_table_format_pb2 import CsvTableFormat
from .proto.waterfront_pb2 import NamedColumn, TableSchema
from io import TextIOBase
from typing_extensions import TypedDict
from hashlib import sha256
from sqloxide import parse_sql # type: ignore

MAX_CHUNK_SIZE = 8 * 1024 * 1024
CHARSET = "utf-8"
KEY_LEN = 32
SALT_LEN = 16

class ChunkWrapper(TypedDict):
    hash: str
    data: str

class Key():
    def __init__(self, material: Union[bytes, None] = None, salt: Union[bytes, None] = None):
        if material == None:
            key_bytes = os.urandom(KEY_LEN)
        else:
            if len(material) != KEY_LEN:
                raise Exception("Invalid key length, must be 32 bytes")
            key_bytes = material

        if salt == None:
            salt_bytes = os.urandom(SALT_LEN)
        else:
            if len(salt) != SALT_LEN:
                raise Exception("Invalid salt length, must be 16 bytes")
            salt_bytes = salt

        self.id: bytes = argon2.low_level.hash_secret_raw(
                secret=key_bytes,
                salt=salt_bytes,
                time_cost=2,
                memory_cost=15360,
                parallelism=1,
                hash_len=32,
                type=argon2.low_level.Type.ID
        )
        self.material: bytes = key_bytes
        self.salt: bytes = salt_bytes

def sql_data_type_to_column_type(column_type: Union[str, dict], options) -> ColumnType:
    type = ColumnType()
    is_not_null = False
    for option in options:
        option_value = option["option"]
        if option_value == "NotNull":
            is_not_null = True
        else:
            raise Exception(f"Column option {option_value} not supported")

    type.nullable = not is_not_null

    if isinstance(column_type, str):
        if column_type == "Text":
            type.primitiveType =  PrimitiveType.STRING
        elif column_type == "Real" or column_type == "Double":
            type.primitiveType = PrimitiveType.FLOAT64 # type: ignore
        elif column_type == "SmallInt" or column_type == "Int" or column_type == "BigInt":
            type.primitiveType = PrimitiveType.INT64
    elif isinstance(column_type, dict):
        if "Char" in column_type or "Varchar" in column_type:
            type.primitiveType =  PrimitiveType.STRING
        elif "Float" in column_type:
            type.primitiveType = PrimitiveType.FLOAT64
    else:
        raise Exception(f"Unsupported data type {column_type}")

    return type


class Schema():
    def __init__(self, create_table_statement: str):
        statements = parse_sql(create_table_statement, dialect="generic")
        if len(statements) == 0:
            raise Exception("No CREATE TABLE statements found")
        if len(statements) > 1:
            raise Exception("Single CREATE TABLE statement expected")
        statement = statements[0]
        if "CreateTable" in statement:
            create_table = statement["CreateTable"]
            table_names = create_table["name"]
            if len(table_names) != 1:
                raise Exception("Table name must be a single SQL identifier")
            table_name = table_names[0]["value"]
            used_column_names = set()
            named_columns: List[NamedColumn] = list()
            for column in create_table["columns"]:
                column_name = column["name"]["value"]
                if column_name in used_column_names:
                    raise Exception(f"Multiple definitions of column {column.name.value}")
                named_column = NamedColumn(
                        name=column_name,
                        columnType=sql_data_type_to_column_type(column["data_type"], column["options"])
                )
                named_columns.append(named_column)
            self.proto_schema: TableSchema = TableSchema(
                    namedColumns=named_columns
            )
            self.table_name: str = table_name
        else:
            raise Exception("CREATE TABLE statement expected");

class DatasetManifestMetadata(TypedDict):
    name: str
    manifestHash: str
    chunks: List[str]


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


def create_protobuf_chunk_header(extra_entropy: bytes) -> bytes:
    chunk_header = ChunkHeader()
    chunk_header.extraEntropy = extra_entropy
    chunk_header.formatIdentifier = "ProtobufObject"
    chunk_header_bytes = serialize_length_delimited(chunk_header)

    return chunk_header_bytes


# Returns (integrity hash, encrypted blob)
def create_encrypted_json_object_chunk(
        key_id: bytes,
        key: bytes,
        extra_entropy: bytes,
        object: Any
) -> Tuple[bytes, bytes]:
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
    chunk_hash = chunk_hasher.digest()

    cipher = StorageCipher(key, key_id)
    encrypted_chunk = cipher.encrypt(chunk)

    return chunk_hash, encrypted_chunk


# Returns (integrity hash, encrypted blob)
def create_encrypted_protobuf_object_chunk(
        key_id: bytes,
        key: bytes,
        extra_entropy: bytes,
        object: Message
) -> Tuple[bytes, bytes]:
    chunk_bytes = []

    version_header = create_version_header()
    chunk_bytes.append(version_header)

    chunk_header = create_protobuf_chunk_header(extra_entropy)
    chunk_bytes.append(chunk_header)

    object_protobuf = serialize_length_delimited(object)
    chunk_bytes.append(object_protobuf)

    chunk = b''.join(chunk_bytes)
    chunk_hasher = sha256()
    chunk_hasher.update(chunk)
    chunk_hash = chunk_hasher.digest()

    cipher = StorageCipher(key, key_id)
    encrypted_chunk = cipher.encrypt(chunk)

    return chunk_hash, encrypted_chunk


class UploadDescription(TypedDict):
    uploadId: str

class ChunkDescription(TypedDict):
    chunkHash: str

class FileDescription(TypedDict):
    manifestHash: str
    filename: str
    chunks: List[ChunkDescription]


class CsvChunker(Iterator):
    def __init__(self, input_stream: TextIOBase, csv_column_types: List[int], chunk_size: int):
        self.chunk_size = chunk_size
        self.input_stream = input_stream
        self.csv_column_types = csv_column_types
        self.beginning_stream_offset = input_stream.tell()

    def reset(self):
        self.input_stream.seek(self.beginning_stream_offset)

    # returns (hash, chunk)
    def __next__(self) -> Tuple[bytes, bytes]:
        version_header_bytes = create_version_header()
        chunk_header_bytes = create_csv_chunk_header(os.urandom(16))

        csv_table_format = CsvTableFormat()
        csv_table_format.columnTypes.extend(self.csv_column_types)
        csv_table_format_bytes = serialize_length_delimited(csv_table_format)

        # Does not account for header size
        current_chunk_size = 0
        starting_offset = self.input_stream.tell()
        chunk_bytes = [version_header_bytes, chunk_header_bytes, csv_table_format_bytes]

        line = self.input_stream.readline()
        while line:
            line_bytes = line.encode(CHARSET)
            current_chunk_size = self.input_stream.tell() - starting_offset
            chunk_bytes.append(line_bytes)
            if current_chunk_size > self.chunk_size:
                break
            line = self.input_stream.readline()
        else:
            if current_chunk_size == 0:
                raise StopIteration

        chunk = b''.join(chunk_bytes)
        chunk_hasher = sha256()
        chunk_hasher.update(chunk)
        chunk_hash = chunk_hasher.digest()
        return chunk_hash, chunk


class StorageCipher:
    def __init__(self, symmetric_key: bytes, key_id: bytes):
        self.enc_key = symmetric_key
        self.enc_key_id = key_id
        self.cipher: chily.Cipher = chily.Cipher.from_symmetric(self.enc_key)

    def encrypt(self, data: bytes) -> bytes:
        nonce = chily.Nonce.from_random()
        encrypted_data = self.cipher.encrypt(data, nonce)

        encryption_header = EncryptionHeader()
        encryption_header.chilyKey.keyId = self.enc_key_id
        encryption_header.chilyKey.encryptionNonce = bytes(nonce.bytes)

        serialized_encryption_header = serialize_length_delimited(encryption_header)
        encrypted_data_with_header = bytes(list(serialized_encryption_header) + encrypted_data)
        return encrypted_data_with_header
