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


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x0emetering.proto\x12\x08metering\x1a\x11\x61ttestation.proto\"\xfe\x04\n\x0fMeteringRequest\x12/\n\tcreateDcr\x18\x01 \x01(\x0b\x32\x1a.metering.CreateDcrRequestH\x00\x12;\n\x0f\x63reateDcrCommit\x18\x02 \x01(\x0b\x32 .metering.CreateDcrCommitRequestH\x00\x12+\n\x07stopDcr\x18\x03 \x01(\x0b\x32\x18.metering.StopDcrRequestH\x00\x12\x39\n\x0epublishDataset\x18\x04 \x01(\x0b\x32\x1f.metering.PublishDatasetRequestH\x00\x12=\n\x10unpublishDataset\x18\x05 \x01(\x0b\x32!.metering.UnpublishDatasetRequestH\x00\x12\x39\n\x0eworkerMetadata\x18\x06 \x01(\x0b\x32\x1f.metering.WorkerMetadataRequestH\x00\x12O\n\x19submitWorkerExecutionTime\x18\x07 \x01(\x0b\x32*.metering.SubmitWorkerExecutionTimeRequestH\x00\x12\x39\n\x0e\x64\x63rInteraction\x18\x08 \x01(\x0b\x32\x1f.metering.DcrInteractionRequestH\x00\x12\x37\n\rcreateDataset\x18\t \x01(\x0b\x32\x1e.metering.CreateDatasetRequestH\x00\x12K\n\x17getOrCreateDatasetScope\x18\n \x01(\x0b\x32(.metering.GetOrCreateDatasetScopeRequestH\x00\x42\t\n\x07request\"\x91\x05\n\x17MeteringSuccessResponse\x12\x30\n\tcreateDcr\x18\x01 \x01(\x0b\x32\x1b.metering.CreateDcrResponseH\x00\x12<\n\x0f\x63reateDcrCommit\x18\x02 \x01(\x0b\x32!.metering.CreateDcrCommitResponseH\x00\x12,\n\x07stopDcr\x18\x03 \x01(\x0b\x32\x19.metering.StopDcrResponseH\x00\x12:\n\x0epublishDataset\x18\x04 \x01(\x0b\x32 .metering.PublishDatasetResponseH\x00\x12>\n\x10unpublishDataset\x18\x05 \x01(\x0b\x32\".metering.UnpublishDatasetResponseH\x00\x12:\n\x0eworkerMetadata\x18\x06 \x01(\x0b\x32 .metering.WorkerMetadataResponseH\x00\x12P\n\x19submitWorkerExecutionTime\x18\x07 \x01(\x0b\x32+.metering.SubmitWorkerExecutionTimeResponseH\x00\x12:\n\x0e\x64\x63rInteraction\x18\x08 \x01(\x0b\x32 .metering.DcrInteractionResponseH\x00\x12\x38\n\rcreateDataset\x18\t \x01(\x0b\x32\x1f.metering.CreateDatasetResponseH\x00\x12L\n\x17getOrCreateDatasetScope\x18\n \x01(\x0b\x32).metering.GetOrCreateDatasetScopeResponseH\x00\x42\n\n\x08response\"g\n\x10MeteringResponse\x12\x34\n\x07success\x18\x01 \x01(\x0b\x32!.metering.MeteringSuccessResponseH\x00\x12\x11\n\x07\x66\x61ilure\x18\x02 \x01(\tH\x00\x42\n\n\x08response\"\x98\x01\n\x0b\x44\x63rMetadata\x12+\n\x07purpose\x18\x01 \x01(\x0e\x32\x1a.metering.CreateDcrPurpose\x12\x1c\n\x14showOrganizationLogo\x18\x02 \x01(\x08\x12\x17\n\x0frequirePassword\x18\x03 \x01(\x08\x12%\n\x04kind\x18\x04 \x01(\x0e\x32\x17.metering.CreateDcrKind\"\x8d\x01\n\x10\x43reateDcrRequest\x12\r\n\x05idHex\x18\x01 \x01(\t\x12\x0c\n\x04name\x18\x02 \x01(\t\x12\x1d\n\x15\x64riverAttestationHash\x18\x03 \x01(\t\x12\x19\n\x11participantEmails\x18\x04 \x03(\t\x12\x15\n\x08metadata\x18\x05 \x01(\x0cH\x00\x88\x01\x01\x42\x0b\n\t_metadata\"]\n\x15\x44\x63rInteractionRequest\x12\x14\n\x0c\x64\x61taRoomHash\x18\x01 \x01(\t\x12\x1d\n\x15\x64riverAttestationHash\x18\x02 \x01(\t\x12\x0f\n\x07scopeId\x18\x03 \x01(\t\"y\n\x15PublishDatasetRequest\x12\x15\n\rcomputeNodeId\x18\x01 \x01(\t\x12\x14\n\x0cmanifestHash\x18\x02 \x01(\t\x12\x14\n\x0c\x64\x61taRoomHash\x18\x03 \x01(\t\x12\x1d\n\x15\x64riverAttestationHash\x18\x04 \x01(\t\"\x99\x02\n\x14\x43reateDatasetRequest\x12\x14\n\x0cmanifestHash\x18\x01 \x01(\t\x12\x15\n\x08manifest\x18\x02 \x01(\tH\x00\x88\x01\x01\x12\x0f\n\x07scopeId\x18\x03 \x01(\t\x12\x0c\n\x04name\x18\x04 \x01(\t\x12\x18\n\x0b\x64\x65scription\x18\x05 \x01(\tH\x01\x88\x01\x01\x12\x16\n\tsizeBytes\x18\x06 \x01(\x04H\x02\x88\x01\x01\x12\x17\n\nstatistics\x18\x07 \x01(\tH\x03\x88\x01\x01\x12\x1c\n\x0f\x64\x61tasetImportId\x18\x08 \x01(\tH\x04\x88\x01\x01\x42\x0b\n\t_manifestB\x0e\n\x0c_descriptionB\x0c\n\n_sizeBytesB\r\n\x0b_statisticsB\x12\n\x10_datasetImportId\"L\n\x1eGetOrCreateDatasetScopeRequest\x12\x19\n\x0cmanifestHash\x18\x01 \x01(\tH\x00\x88\x01\x01\x42\x0f\n\r_manifestHash\"e\n\x17UnpublishDatasetRequest\x12\x15\n\rcomputeNodeId\x18\x01 \x01(\t\x12\x14\n\x0c\x64\x61taRoomHash\x18\x02 \x01(\t\x12\x1d\n\x15\x64riverAttestationHash\x18\x03 \x01(\t\"E\n\x0eStopDcrRequest\x12\x14\n\x0c\x64\x61taRoomHash\x18\x01 \x01(\t\x12\x1d\n\x15\x64riverAttestationHash\x18\x02 \x01(\t\"U\n\x16\x43reateDcrCommitRequest\x12\n\n\x02id\x18\x01 \x01(\t\x12\x10\n\x08\x64\x63rIdHex\x18\x02 \x01(\t\x12\x1d\n\x15\x64riverAttestationHash\x18\x03 \x01(\t\"\x13\n\x11\x43reateDcrResponse\"-\n\x1fGetOrCreateDatasetScopeResponse\x12\n\n\x02id\x18\x01 \x01(\t\"\x18\n\x16\x44\x63rInteractionResponse\"\x19\n\x17\x43reateDcrCommitResponse\"\x11\n\x0fStopDcrResponse\"\x18\n\x16PublishDatasetResponse\"#\n\x15\x43reateDatasetResponse\x12\n\n\x02id\x18\x01 \x01(\t\"\x1a\n\x18UnpublishDatasetResponse\"h\n\x15WorkerMetadataRequest\x12>\n\x0f\x61ttestationSpec\x18\x01 \x01(\x0b\x32%.attestation.AttestationSpecification\x12\x0f\n\x07scopeId\x18\x02 \x01(\t\"5\n\x16WorkerMetadataResponse\x12\x1b\n\x13maxExecutionSeconds\x18\x01 \x01(\x04\"\x91\x01\n SubmitWorkerExecutionTimeRequest\x12\x1c\n\x14\x65xecutionTimeSeconds\x18\x01 \x01(\r\x12>\n\x0f\x61ttestationSpec\x18\x02 \x01(\x0b\x32%.attestation.AttestationSpecification\x12\x0f\n\x07scopeId\x18\x03 \x01(\t\"#\n!SubmitWorkerExecutionTimeResponse*R\n\x10\x43reateDcrPurpose\x12\x0c\n\x08STANDARD\x10\x00\x12\x0e\n\nVALIDATION\x10\x01\x12\x0f\n\x0b\x44\x41TA_IMPORT\x10\x02\x12\x0f\n\x0b\x44\x41TA_EXPORT\x10\x03*7\n\rCreateDcrKind\x12\n\n\x06\x45XPERT\x10\x00\x12\x0f\n\x0b\x44\x41TASCIENCE\x10\x01\x12\t\n\x05MEDIA\x10\x02\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'metering_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _CREATEDCRPURPOSE._serialized_start=3170
  _CREATEDCRPURPOSE._serialized_end=3252
  _CREATEDCRKIND._serialized_start=3254
  _CREATEDCRKIND._serialized_end=3309
  _METERINGREQUEST._serialized_start=48
  _METERINGREQUEST._serialized_end=686
  _METERINGSUCCESSRESPONSE._serialized_start=689
  _METERINGSUCCESSRESPONSE._serialized_end=1346
  _METERINGRESPONSE._serialized_start=1348
  _METERINGRESPONSE._serialized_end=1451
  _DCRMETADATA._serialized_start=1454
  _DCRMETADATA._serialized_end=1606
  _CREATEDCRREQUEST._serialized_start=1609
  _CREATEDCRREQUEST._serialized_end=1750
  _DCRINTERACTIONREQUEST._serialized_start=1752
  _DCRINTERACTIONREQUEST._serialized_end=1845
  _PUBLISHDATASETREQUEST._serialized_start=1847
  _PUBLISHDATASETREQUEST._serialized_end=1968
  _CREATEDATASETREQUEST._serialized_start=1971
  _CREATEDATASETREQUEST._serialized_end=2252
  _GETORCREATEDATASETSCOPEREQUEST._serialized_start=2254
  _GETORCREATEDATASETSCOPEREQUEST._serialized_end=2330
  _UNPUBLISHDATASETREQUEST._serialized_start=2332
  _UNPUBLISHDATASETREQUEST._serialized_end=2433
  _STOPDCRREQUEST._serialized_start=2435
  _STOPDCRREQUEST._serialized_end=2504
  _CREATEDCRCOMMITREQUEST._serialized_start=2506
  _CREATEDCRCOMMITREQUEST._serialized_end=2591
  _CREATEDCRRESPONSE._serialized_start=2593
  _CREATEDCRRESPONSE._serialized_end=2612
  _GETORCREATEDATASETSCOPERESPONSE._serialized_start=2614
  _GETORCREATEDATASETSCOPERESPONSE._serialized_end=2659
  _DCRINTERACTIONRESPONSE._serialized_start=2661
  _DCRINTERACTIONRESPONSE._serialized_end=2685
  _CREATEDCRCOMMITRESPONSE._serialized_start=2687
  _CREATEDCRCOMMITRESPONSE._serialized_end=2712
  _STOPDCRRESPONSE._serialized_start=2714
  _STOPDCRRESPONSE._serialized_end=2731
  _PUBLISHDATASETRESPONSE._serialized_start=2733
  _PUBLISHDATASETRESPONSE._serialized_end=2757
  _CREATEDATASETRESPONSE._serialized_start=2759
  _CREATEDATASETRESPONSE._serialized_end=2794
  _UNPUBLISHDATASETRESPONSE._serialized_start=2796
  _UNPUBLISHDATASETRESPONSE._serialized_end=2822
  _WORKERMETADATAREQUEST._serialized_start=2824
  _WORKERMETADATAREQUEST._serialized_end=2928
  _WORKERMETADATARESPONSE._serialized_start=2930
  _WORKERMETADATARESPONSE._serialized_end=2983
  _SUBMITWORKEREXECUTIONTIMEREQUEST._serialized_start=2986
  _SUBMITWORKEREXECUTIONTIMEREQUEST._serialized_end=3131
  _SUBMITWORKEREXECUTIONTIMERESPONSE._serialized_start=3133
  _SUBMITWORKEREXECUTIONTIMERESPONSE._serialized_end=3168
# @@protoc_insertion_point(module_scope)
