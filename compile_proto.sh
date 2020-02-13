#!/bin/bash

protoc -I=proto --python_out=avato/proto proto/proto_util.proto
