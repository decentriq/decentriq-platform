#!/usr/bin/env bash
set -xeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

(
    cd "${SCRIPT_DIR}"
    protoc -I=proto --python_out=avato/proto proto/avato_enclave.proto
)
