#!/usr/bin/env bash
set -xeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
OUTPUT_DIR="$SCRIPT_DIR/decentriq_platform/proto"

function correct_pb() {
  python3 -c $'import re\nimport sys\nfor line in sys.stdin.readlines():\n  print(re.sub(r"(^import.*_pb2)", r"from . \\1", line),end="")'
}

for proto_file in proto/*.proto; do
    protoc -I=proto --python_out=$OUTPUT_DIR --mypy_out=$OUTPUT_DIR $proto_file 
done

# See https://github.com/protocolbuffers/protobuf/issues/1491
for pb in $OUTPUT_DIR/*_pb2*.py; do
    correct_pb < "$pb" > "$pb.replaced" && mv "$pb.replaced" "$pb"
done
