#!/usr/bin/env bash
set -xeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

(
    cd "${SCRIPT_DIR}"
    protoc -I=proto --python_out=avato/proto proto/avato_enclave.proto
    protoc -I=proto --python_out=avato/proto proto/csv_table_format.proto
    protoc -I=proto --python_out=avato/proto proto/json_object_format.proto
    protoc -I=proto --python_out=avato/proto proto/column_type.proto

    # See https://github.com/protocolbuffers/protobuf/issues/1491
    sed -i -E 's/^import.*_pb2/from . \0/' avato/proto/*_pb2*.py
)
