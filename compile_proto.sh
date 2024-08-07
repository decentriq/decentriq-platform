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
        --experimental_allow_proto3_optional\
        $proto_file
    done
    # See https://github.com/protocolbuffers/protobuf/issues/1491
    for pb in $OUTPUT_DIR/*_pb2*.py; do
        correct_pb < "$pb" > "$pb.replaced" && mv "$pb.replaced" "$pb"
    done
}

MAIN_PACKAGE_PROTO=(gcg.proto data_room.proto attestation.proto delta_enclave_api.proto synth_data.proto compute_sql.proto metering.proto identity_endorsement.proto)
SQL_PACKAGE_PROTO=(compute_sql.proto)
CONTAINER_PACKAGE_PROTO=(compute_container.proto)
S3_SINK_PACKAGE_PROTO=(compute_s3_sink.proto)
DATA_SOURCE_S3_PACKAGE_PROTO=(data_source_s3.proto)
DATASET_SINK_PACKAGE_PROTO=(dataset_sink.proto)
META_SINK_PACKAGE_PROTO=(meta_sink.proto)
POST_PACKAGE_PROTO=(compute_post.proto)
DATA_SOURCE_SNOWFLAKE_PACKAGE_PROTO=(data_source_snowflake.proto)
GOOGLE_DV_360_SINK_PACKAGE_PROTO=(google_dv_360_sink.proto)
AZURE_BLOB_STORAGE_PACKAGE_PROTO=(azure_blob_storage.proto)
GOOGLE_AD_MANAGER_PACKAGE_PROTO=(google_ad_manager.proto)
SALESFORCE_PACKAGE_PROTO=(salesforce.proto)
PERMUTIVE_PACKAGE_PROTO=(permutive.proto)
MICROSOFT_DSP_PACKAGE_PROTO=(microsoft_dsp.proto)
ADFORM_DSP_PACKAGE_PROTO=(adform_dsp.proto)

compile_pb "decentriq_platform/proto" "${MAIN_PACKAGE_PROTO[@]}"
compile_pb "decentriq_platform/proto" "${SQL_PACKAGE_PROTO[@]}"
compile_pb "decentriq_platform/proto" "${CONTAINER_PACKAGE_PROTO[@]}"
compile_pb "decentriq_platform/proto" "${S3_SINK_PACKAGE_PROTO[@]}"
compile_pb "decentriq_platform/proto" "${DATA_SOURCE_S3_PACKAGE_PROTO[@]}"
compile_pb "decentriq_platform/proto" "${DATASET_SINK_PACKAGE_PROTO[@]}"
compile_pb "decentriq_platform/proto" "${META_SINK_PACKAGE_PROTO[@]}"
compile_pb "decentriq_platform/proto" "${POST_PACKAGE_PROTO[@]}"
compile_pb "decentriq_platform/proto" "${DATA_SOURCE_SNOWFLAKE_PACKAGE_PROTO[@]}"
compile_pb "decentriq_platform/proto" "${GOOGLE_DV_360_SINK_PACKAGE_PROTO[@]}"
compile_pb "decentriq_platform/proto" "${AZURE_BLOB_STORAGE_PACKAGE_PROTO[@]}"
compile_pb "decentriq_platform/proto" "${GOOGLE_AD_MANAGER_PACKAGE_PROTO[@]}"
compile_pb "decentriq_platform/proto" "${SALESFORCE_PACKAGE_PROTO[@]}"
compile_pb "decentriq_platform/proto" "${PERMUTIVE_PACKAGE_PROTO[@]}"
compile_pb "decentriq_platform/proto" "${MICROSOFT_DSP_PACKAGE_PROTO[@]}"
compile_pb "decentriq_platform/proto" "${ADFORM_DSP_PACKAGE_PROTO[@]}"
