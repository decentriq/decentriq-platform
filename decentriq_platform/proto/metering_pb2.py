# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: metering.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from . import attestation_pb2 as attestation__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0emetering.proto\x12\x08metering\x1a\x11\x61ttestation.proto\"\xf8\x03\n\x0fMeteringRequest\x12/\n\tcreateDcr\x18\x01 \x01(\x0b\x32\x1a.metering.CreateDcrRequestH\x00\x12;\n\x0f\x63reateDcrCommit\x18\x02 \x01(\x0b\x32 .metering.CreateDcrCommitRequestH\x00\x12+\n\x07stopDcr\x18\x03 \x01(\x0b\x32\x18.metering.StopDcrRequestH\x00\x12\x39\n\x0epublishDataset\x18\x04 \x01(\x0b\x32\x1f.metering.PublishDatasetRequestH\x00\x12=\n\x10unpublishDataset\x18\x05 \x01(\x0b\x32!.metering.UnpublishDatasetRequestH\x00\x12\x39\n\x0eworkerMetadata\x18\x06 \x01(\x0b\x32\x1f.metering.WorkerMetadataRequestH\x00\x12O\n\x19submitWorkerExecutionTime\x18\x07 \x01(\x0b\x32*.metering.SubmitWorkerExecutionTimeRequestH\x00\x12\x39\n\x0e\x64\x63rInteraction\x18\x08 \x01(\x0b\x32\x1f.metering.DcrInteractionRequestH\x00\x42\t\n\x07request\"\x89\x04\n\x17MeteringSuccessResponse\x12\x30\n\tcreateDcr\x18\x01 \x01(\x0b\x32\x1b.metering.CreateDcrResponseH\x00\x12<\n\x0f\x63reateDcrCommit\x18\x02 \x01(\x0b\x32!.metering.CreateDcrCommitResponseH\x00\x12,\n\x07stopDcr\x18\x03 \x01(\x0b\x32\x19.metering.StopDcrResponseH\x00\x12:\n\x0epublishDataset\x18\x04 \x01(\x0b\x32 .metering.PublishDatasetResponseH\x00\x12>\n\x10unpublishDataset\x18\x05 \x01(\x0b\x32\".metering.UnpublishDatasetResponseH\x00\x12:\n\x0eworkerMetadata\x18\x06 \x01(\x0b\x32 .metering.WorkerMetadataResponseH\x00\x12P\n\x19submitWorkerExecutionTime\x18\x07 \x01(\x0b\x32+.metering.SubmitWorkerExecutionTimeResponseH\x00\x12:\n\x0e\x64\x63rInteraction\x18\x08 \x01(\x0b\x32 .metering.DcrInteractionResponseH\x00\x42\n\n\x08response\"g\n\x10MeteringResponse\x12\x34\n\x07success\x18\x01 \x01(\x0b\x32!.metering.MeteringSuccessResponseH\x00\x12\x11\n\x07\x66\x61ilure\x18\x02 \x01(\tH\x00\x42\n\n\x08response\"q\n\x0b\x44\x63rMetadata\x12+\n\x07purpose\x18\x01 \x01(\x0e\x32\x1a.metering.CreateDcrPurpose\x12\x1c\n\x14showOrganizationLogo\x18\x02 \x01(\x08\x12\x17\n\x0frequirePassword\x18\x03 \x01(\x08\"\x8b\x01\n\x10\x43reateDcrRequest\x12\n\n\x02id\x18\x01 \x02(\t\x12\x0c\n\x04name\x18\x02 \x02(\t\x12\x11\n\tenclaveId\x18\x03 \x02(\t\x12\x1d\n\x15\x64riverAttestationHash\x18\x04 \x02(\t\x12\x19\n\x11participantEmails\x18\x05 \x03(\t\x12\x10\n\x08metadata\x18\x06 \x01(\x0c\"]\n\x15\x44\x63rInteractionRequest\x12\x14\n\x0c\x64\x61taRoomHash\x18\x01 \x02(\t\x12\x1d\n\x15\x64riverAttestationHash\x18\x02 \x02(\t\x12\x0f\n\x07scopeId\x18\x03 \x02(\t\"y\n\x15PublishDatasetRequest\x12\x15\n\rcomputeNodeId\x18\x01 \x02(\t\x12\x14\n\x0cmanifestHash\x18\x02 \x02(\t\x12\x14\n\x0c\x64\x61taRoomHash\x18\x03 \x02(\t\x12\x1d\n\x15\x64riverAttestationHash\x18\x04 \x02(\t\"e\n\x17UnpublishDatasetRequest\x12\x15\n\rcomputeNodeId\x18\x01 \x02(\t\x12\x14\n\x0c\x64\x61taRoomHash\x18\x02 \x02(\t\x12\x1d\n\x15\x64riverAttestationHash\x18\x03 \x02(\t\"E\n\x0eStopDcrRequest\x12\x14\n\x0c\x64\x61taRoomHash\x18\x01 \x02(\t\x12\x1d\n\x15\x64riverAttestationHash\x18\x02 \x02(\t\"$\n\x16\x43reateDcrCommitRequest\x12\n\n\x02id\x18\x01 \x02(\t\"\x13\n\x11\x43reateDcrResponse\"\x18\n\x16\x44\x63rInteractionResponse\"\x19\n\x17\x43reateDcrCommitResponse\"\x11\n\x0fStopDcrResponse\"\x18\n\x16PublishDatasetResponse\"\x1a\n\x18UnpublishDatasetResponse\"h\n\x15WorkerMetadataRequest\x12>\n\x0f\x61ttestationSpec\x18\x01 \x02(\x0b\x32%.attestation.AttestationSpecification\x12\x0f\n\x07scopeId\x18\x02 \x02(\t\"5\n\x16WorkerMetadataResponse\x12\x1b\n\x13maxExecutionSeconds\x18\x01 \x01(\x04\"\x91\x01\n SubmitWorkerExecutionTimeRequest\x12\x1c\n\x14\x65xecutionTimeSeconds\x18\x01 \x02(\r\x12>\n\x0f\x61ttestationSpec\x18\x02 \x02(\x0b\x32%.attestation.AttestationSpecification\x12\x0f\n\x07scopeId\x18\x03 \x02(\t\"#\n!SubmitWorkerExecutionTimeResponse*0\n\x10\x43reateDcrPurpose\x12\x0c\n\x08STANDARD\x10\x00\x12\x0e\n\nVALIDATION\x10\x01')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'metering_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _CREATEDCRPURPOSE._serialized_start=2363
  _CREATEDCRPURPOSE._serialized_end=2411
  _METERINGREQUEST._serialized_start=48
  _METERINGREQUEST._serialized_end=552
  _METERINGSUCCESSRESPONSE._serialized_start=555
  _METERINGSUCCESSRESPONSE._serialized_end=1076
  _METERINGRESPONSE._serialized_start=1078
  _METERINGRESPONSE._serialized_end=1181
  _DCRMETADATA._serialized_start=1183
  _DCRMETADATA._serialized_end=1296
  _CREATEDCRREQUEST._serialized_start=1299
  _CREATEDCRREQUEST._serialized_end=1438
  _DCRINTERACTIONREQUEST._serialized_start=1440
  _DCRINTERACTIONREQUEST._serialized_end=1533
  _PUBLISHDATASETREQUEST._serialized_start=1535
  _PUBLISHDATASETREQUEST._serialized_end=1656
  _UNPUBLISHDATASETREQUEST._serialized_start=1658
  _UNPUBLISHDATASETREQUEST._serialized_end=1759
  _STOPDCRREQUEST._serialized_start=1761
  _STOPDCRREQUEST._serialized_end=1830
  _CREATEDCRCOMMITREQUEST._serialized_start=1832
  _CREATEDCRCOMMITREQUEST._serialized_end=1868
  _CREATEDCRRESPONSE._serialized_start=1870
  _CREATEDCRRESPONSE._serialized_end=1889
  _DCRINTERACTIONRESPONSE._serialized_start=1891
  _DCRINTERACTIONRESPONSE._serialized_end=1915
  _CREATEDCRCOMMITRESPONSE._serialized_start=1917
  _CREATEDCRCOMMITRESPONSE._serialized_end=1942
  _STOPDCRRESPONSE._serialized_start=1944
  _STOPDCRRESPONSE._serialized_end=1961
  _PUBLISHDATASETRESPONSE._serialized_start=1963
  _PUBLISHDATASETRESPONSE._serialized_end=1987
  _UNPUBLISHDATASETRESPONSE._serialized_start=1989
  _UNPUBLISHDATASETRESPONSE._serialized_end=2015
  _WORKERMETADATAREQUEST._serialized_start=2017
  _WORKERMETADATAREQUEST._serialized_end=2121
  _WORKERMETADATARESPONSE._serialized_start=2123
  _WORKERMETADATARESPONSE._serialized_end=2176
  _SUBMITWORKEREXECUTIONTIMEREQUEST._serialized_start=2179
  _SUBMITWORKEREXECUTIONTIMEREQUEST._serialized_end=2324
  _SUBMITWORKEREXECUTIONTIMERESPONSE._serialized_start=2326
  _SUBMITWORKEREXECUTIONTIMERESPONSE._serialized_end=2361
# @@protoc_insertion_point(module_scope)
