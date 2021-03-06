#!/usr/bin/env bash
set -xeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

function correct_pb() {
  python3 -c $'import re\nimport sys\nfor line in sys.stdin.readlines():\n  print(re.sub(r"(^import.*_pb2)", r"from . \\1", line),end="")'
}

PROTO_PATH=

function compile_pb() {
    local OUTPUT_DIR=$1
    shift
    local FILES=("$@")
    for proto_file in "${FILES[@]}"; do
        protoc -I=proto \
        --python_out=$OUTPUT_DIR\
        --mypy_out=$OUTPUT_DIR\
        $proto_file
    done
    # See https://github.com/protocolbuffers/protobuf/issues/1491
    for pb in $OUTPUT_DIR/*_pb2*.py; do
        correct_pb < "$pb" > "$pb.replaced" && mv "$pb.replaced" "$pb"
    done
}

MAIN_PACKAGE_PROTO=(gcg.proto data_room.proto attestation.proto delta_enclave_api.proto synth_data.proto compute_sql.proto)
SQL_PACKAGE_PROTO=(compute_sql.proto)
CONTAINER_PACKAGE_PROTO=(compute_container.proto)

compile_pb "decentriq_platform/proto" "${MAIN_PACKAGE_PROTO[@]}"
compile_pb "decentriq_platform/sql/proto" "${SQL_PACKAGE_PROTO[@]}"
compile_pb "decentriq_platform/container/proto" "${CONTAINER_PACKAGE_PROTO[@]}"
