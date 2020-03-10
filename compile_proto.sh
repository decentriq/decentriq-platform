#!/bin/bash

protoc -I=proto --python_out=avato/proto proto/avato_enclave.proto
