# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: gcg.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from . import data_room_pb2 as data__room__pb2
from . import identity_endorsement_pb2 as identity__endorsement__pb2


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\tgcg.proto\x12\x03gcg\x1a\x0f\x64\x61ta_room.proto\x1a\x1aidentity_endorsement.proto\"\x82\x0e\n\nGcgRequest\x12\x1f\n\x08userAuth\x18\x01 \x01(\x0b\x32\r.gcg.UserAuth\x12;\n\x15\x63reateDataRoomRequest\x18\x02 \x01(\x0b\x32\x1a.gcg.CreateDataRoomRequestH\x00\x12?\n\x17retrieveDataRoomRequest\x18\x03 \x01(\x0b\x32\x1c.gcg.RetrieveDataRoomRequestH\x00\x12g\n+retrieveCurrentDataRoomConfigurationRequest\x18\x04 \x01(\x0b\x32\x30.gcg.RetrieveCurrentDataRoomConfigurationRequestH\x00\x12K\n\x1dretrieveDataRoomStatusRequest\x18\x05 \x01(\x0b\x32\".gcg.RetrieveDataRoomStatusRequestH\x00\x12G\n\x1bupdateDataRoomStatusRequest\x18\x06 \x01(\x0b\x32 .gcg.UpdateDataRoomStatusRequestH\x00\x12?\n\x17retrieveAuditLogRequest\x18\x07 \x01(\x0b\x32\x1c.gcg.RetrieveAuditLogRequestH\x00\x12O\n\x1fpublishDatasetToDataRoomRequest\x18\x08 \x01(\x0b\x32$.gcg.PublishDatasetToDataRoomRequestH\x00\x12Q\n retrievePublishedDatasetsRequest\x18\t \x01(\x0b\x32%.gcg.RetrievePublishedDatasetsRequestH\x00\x12K\n\x1dremovePublishedDatasetRequest\x18\n \x01(\x0b\x32\".gcg.RemovePublishedDatasetRequestH\x00\x12;\n\x15\x65xecuteComputeRequest\x18\x0b \x01(\x0b\x32\x1a.gcg.ExecuteComputeRequestH\x00\x12\x31\n\x10jobStatusRequest\x18\x0c \x01(\x0b\x32\x15.gcg.JobStatusRequestH\x00\x12\x33\n\x11getResultsRequest\x18\r \x01(\x0b\x32\x16.gcg.GetResultsRequestH\x00\x12Q\n createConfigurationCommitRequest\x18\x0e \x01(\x0b\x32%.gcg.CreateConfigurationCommitRequestH\x00\x12U\n\"retrieveConfigurationCommitRequest\x18\x0f \x01(\x0b\x32\'.gcg.RetrieveConfigurationCommitRequestH\x00\x12Q\n executeDevelopmentComputeRequest\x18\x10 \x01(\x0b\x32%.gcg.ExecuteDevelopmentComputeRequestH\x00\x12[\n%generateMergeApprovalSignatureRequest\x18\x11 \x01(\x0b\x32*.gcg.GenerateMergeApprovalSignatureRequestH\x00\x12O\n\x1fmergeConfigurationCommitRequest\x18\x12 \x01(\x0b\x32$.gcg.MergeConfigurationCommitRequestH\x00\x12g\n+retrieveConfigurationCommitApproversRequest\x18\x13 \x01(\x0b\x32\x30.gcg.RetrieveConfigurationCommitApproversRequestH\x00\x12\x41\n\x18\x63\x61sAuxiliaryStateRequest\x18\x14 \x01(\x0b\x32\x1d.gcg.CasAuxiliaryStateRequestH\x00\x12\x43\n\x19readAuxiliaryStateRequest\x18\x15 \x01(\x0b\x32\x1e.gcg.ReadAuxiliaryStateRequestH\x00\x12O\n\x1fretrieveUsedAirlockQuotaRequest\x18\x16 \x01(\x0b\x32$.gcg.RetrieveUsedAirlockQuotaRequestH\x00\x12;\n\x15getResultsSizeRequest\x18\x17 \x01(\x0b\x32\x1a.gcg.GetResultsSizeRequestH\x00\x12\x46\n\x12\x65ndorsementRequest\x18\x65 \x01(\x0b\x32(.identity_endorsement.EndorsementRequestH\x00\x42\r\n\x0bgcg_request\"\x9c\x0e\n\x0bGcgResponse\x12\x11\n\x07\x66\x61ilure\x18\x01 \x01(\tH\x00\x12=\n\x16\x63reateDataRoomResponse\x18\x02 \x01(\x0b\x32\x1b.gcg.CreateDataRoomResponseH\x00\x12\x41\n\x18retrieveDataRoomResponse\x18\x03 \x01(\x0b\x32\x1d.gcg.RetrieveDataRoomResponseH\x00\x12i\n,retrieveCurrentDataRoomConfigurationResponse\x18\x04 \x01(\x0b\x32\x31.gcg.RetrieveCurrentDataRoomConfigurationResponseH\x00\x12M\n\x1eretrieveDataRoomStatusResponse\x18\x05 \x01(\x0b\x32#.gcg.RetrieveDataRoomStatusResponseH\x00\x12I\n\x1cupdateDataRoomStatusResponse\x18\x06 \x01(\x0b\x32!.gcg.UpdateDataRoomStatusResponseH\x00\x12\x41\n\x18retrieveAuditLogResponse\x18\x07 \x01(\x0b\x32\x1d.gcg.RetrieveAuditLogResponseH\x00\x12Q\n publishDatasetToDataRoomResponse\x18\x08 \x01(\x0b\x32%.gcg.PublishDatasetToDataRoomResponseH\x00\x12S\n!retrievePublishedDatasetsResponse\x18\t \x01(\x0b\x32&.gcg.RetrievePublishedDatasetsResponseH\x00\x12M\n\x1eremovePublishedDatasetResponse\x18\n \x01(\x0b\x32#.gcg.RemovePublishedDatasetResponseH\x00\x12=\n\x16\x65xecuteComputeResponse\x18\x0b \x01(\x0b\x32\x1b.gcg.ExecuteComputeResponseH\x00\x12\x33\n\x11jobStatusResponse\x18\x0c \x01(\x0b\x32\x16.gcg.JobStatusResponseH\x00\x12?\n\x17getResultsResponseChunk\x18\r \x01(\x0b\x32\x1c.gcg.GetResultsResponseChunkH\x00\x12\x41\n\x18getResultsResponseFooter\x18\x0e \x01(\x0b\x32\x1d.gcg.GetResultsResponseFooterH\x00\x12S\n!createConfigurationCommitResponse\x18\x0f \x01(\x0b\x32&.gcg.CreateConfigurationCommitResponseH\x00\x12W\n#retrieveConfigurationCommitResponse\x18\x10 \x01(\x0b\x32(.gcg.RetrieveConfigurationCommitResponseH\x00\x12]\n&generateMergeApprovalSignatureResponse\x18\x11 \x01(\x0b\x32+.gcg.GenerateMergeApprovalSignatureResponseH\x00\x12Q\n mergeConfigurationCommitResponse\x18\x12 \x01(\x0b\x32%.gcg.MergeConfigurationCommitResponseH\x00\x12i\n,retrieveConfigurationCommitApproversResponse\x18\x13 \x01(\x0b\x32\x31.gcg.RetrieveConfigurationCommitApproversResponseH\x00\x12\x43\n\x19\x63\x61sAuxiliaryStateResponse\x18\x14 \x01(\x0b\x32\x1e.gcg.CasAuxiliaryStateResponseH\x00\x12\x45\n\x1areadAuxiliaryStateResponse\x18\x15 \x01(\x0b\x32\x1f.gcg.ReadAuxiliaryStateResponseH\x00\x12Q\n retrieveUsedAirlockQuotaResponse\x18\x16 \x01(\x0b\x32%.gcg.RetrieveUsedAirlockQuotaResponseH\x00\x12=\n\x16getResultsSizeResponse\x18\x17 \x01(\x0b\x32\x1b.gcg.GetResultsSizeResponseH\x00\x12H\n\x13\x65ndorsementResponse\x18\x65 \x01(\x0b\x32).identity_endorsement.EndorsementResponseH\x00\x42\x0e\n\x0cgcg_response\"i\n\x08UserAuth\x12\x15\n\x03pki\x18\x01 \x01(\x0b\x32\x08.gcg.Pki\x12\x46\n\x13\x65nclaveEndorsements\x18\x02 \x01(\x0b\x32).identity_endorsement.EnclaveEndorsements\"=\n\x03Pki\x12\x14\n\x0c\x63\x65rtChainPem\x18\x01 \x01(\x0c\x12\x11\n\tsignature\x18\x02 \x01(\x0c\x12\r\n\x05idMac\x18\x03 \x01(\x0c\"\xb4\x01\n\x15\x43reateDataRoomRequest\x12%\n\x08\x64\x61taRoom\x18\x01 \x01(\x0b\x32\x13.data_room.DataRoom\x12$\n\x17highLevelRepresentation\x18\x02 \x01(\x0cH\x00\x88\x01\x01\x12\x1d\n\x10\x64\x61taRoomMetadata\x18\x03 \x01(\x0cH\x01\x88\x01\x01\x42\x1a\n\x18_highLevelRepresentationB\x13\n\x11_dataRoomMetadata\"\x8c\x01\n\x16\x43reateDataRoomResponse\x12\x14\n\ndataRoomId\x18\x01 \x01(\x0cH\x00\x12?\n\x17\x64\x61taRoomValidationError\x18\x02 \x01(\x0b\x32\x1c.gcg.DataRoomValidationErrorH\x00\x42\x1b\n\x19\x63reate_data_room_response\"\xc6\x02\n\x17\x44\x61taRoomValidationError\x12\x0f\n\x07message\x18\x01 \x01(\t\x12\x1c\n\x0fpermissionIndex\x18\x02 \x01(\x04H\x00\x88\x01\x01\x12\x1a\n\rcomputeNodeId\x18\x03 \x01(\tH\x01\x88\x01\x01\x12\x1d\n\x10userPermissionId\x18\x04 \x01(\tH\x02\x88\x01\x01\x12\'\n\x1a\x61ttestationSpecificationId\x18\x05 \x01(\tH\x03\x88\x01\x01\x12#\n\x16\x61uthenticationMethodId\x18\x06 \x01(\tH\x04\x88\x01\x01\x42\x12\n\x10_permissionIndexB\x10\n\x0e_computeNodeIdB\x13\n\x11_userPermissionIdB\x1d\n\x1b_attestationSpecificationIdB\x19\n\x17_authenticationMethodId\"\x80\x01\n\x1fPublishDatasetToDataRoomRequest\x12\x13\n\x0b\x64\x61tasetHash\x18\x01 \x01(\x0c\x12\x12\n\ndataRoomId\x18\x02 \x01(\x0c\x12\x0e\n\x06leafId\x18\x03 \x01(\t\x12\x15\n\rencryptionKey\x18\x04 \x01(\x0c\x12\r\n\x05scope\x18\x05 \x01(\x0c\"\"\n PublishDatasetToDataRoomResponse\"\xe2\x02\n\x15\x45xecuteComputeRequest\x12\x12\n\ndataRoomId\x18\x01 \x01(\x0c\x12\x16\n\x0e\x63omputeNodeIds\x18\x02 \x03(\t\x12\x10\n\x08isDryRun\x18\x03 \x01(\x08\x12\r\n\x05scope\x18\x04 \x01(\x0c\x12>\n\nparameters\x18\x05 \x03(\x0b\x32*.gcg.ExecuteComputeRequest.ParametersEntry\x12\x42\n\x0ctestDatasets\x18\x06 \x03(\x0b\x32,.gcg.ExecuteComputeRequest.TestDatasetsEntry\x1a\x31\n\x0fParametersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x45\n\x11TestDatasetsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\x1f\n\x05value\x18\x02 \x01(\x0b\x32\x10.gcg.TestDataset:\x02\x38\x01\"\x8e\x03\n ExecuteDevelopmentComputeRequest\x12\x1d\n\x15\x63onfigurationCommitId\x18\x01 \x01(\x0c\x12\x16\n\x0e\x63omputeNodeIds\x18\x02 \x03(\t\x12\x10\n\x08isDryRun\x18\x03 \x01(\x08\x12\r\n\x05scope\x18\x04 \x01(\x0c\x12I\n\nparameters\x18\x05 \x03(\x0b\x32\x35.gcg.ExecuteDevelopmentComputeRequest.ParametersEntry\x12M\n\x0ctestDatasets\x18\x06 \x03(\x0b\x32\x37.gcg.ExecuteDevelopmentComputeRequest.TestDatasetsEntry\x1a\x31\n\x0fParametersEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\x45\n\x11TestDatasetsEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\x1f\n\x05value\x18\x02 \x01(\x0b\x32\x10.gcg.TestDataset:\x02\x38\x01\":\n\x0bTestDataset\x12\x15\n\rencryptionKey\x18\x01 \x01(\x0c\x12\x14\n\x0cmanifestHash\x18\x02 \x01(\x0c\"\'\n\x16\x45xecuteComputeResponse\x12\r\n\x05jobId\x18\x01 \x01(\x0c\"!\n\x10JobStatusRequest\x12\r\n\x05jobId\x18\x01 \x01(\x0c\"3\n\x11JobStatusResponse\x12\x1e\n\x16\x63ompleteComputeNodeIds\x18\x01 \x03(\t\"9\n\x11GetResultsRequest\x12\r\n\x05jobId\x18\x01 \x01(\x0c\x12\x15\n\rcomputeNodeId\x18\x02 \x01(\t\"=\n\x15GetResultsSizeRequest\x12\r\n\x05jobId\x18\x01 \x01(\x0c\x12\x15\n\rcomputeNodeId\x18\x02 \x01(\t\"\'\n\x17GetResultsResponseChunk\x12\x0c\n\x04\x64\x61ta\x18\x01 \x01(\x0c\"\x1a\n\x18GetResultsResponseFooter\"-\n\x17RetrieveDataRoomRequest\x12\x12\n\ndataRoomId\x18\x01 \x01(\x0c\"\xb4\x01\n\x18RetrieveDataRoomResponse\x12%\n\x08\x64\x61taRoom\x18\x01 \x01(\x0b\x32\x13.data_room.DataRoom\x12/\n\x07\x63ommits\x18\x02 \x03(\x0b\x32\x1e.data_room.ConfigurationCommit\x12$\n\x17highLevelRepresentation\x18\x03 \x01(\x0cH\x00\x88\x01\x01\x42\x1a\n\x18_highLevelRepresentation\"-\n\x17RetrieveAuditLogRequest\x12\x12\n\ndataRoomId\x18\x01 \x01(\x0c\"\'\n\x18RetrieveAuditLogResponse\x12\x0b\n\x03log\x18\x01 \x01(\x0c\"3\n\x1dRetrieveDataRoomStatusRequest\x12\x12\n\ndataRoomId\x18\x01 \x01(\x0c\"E\n\x1eRetrieveDataRoomStatusResponse\x12#\n\x06status\x18\x01 \x01(\x0e\x32\x13.gcg.DataRoomStatus\"V\n\x1bUpdateDataRoomStatusRequest\x12\x12\n\ndataRoomId\x18\x01 \x01(\x0c\x12#\n\x06status\x18\x02 \x01(\x0e\x32\x13.gcg.DataRoomStatus\"\x1e\n\x1cUpdateDataRoomStatusResponse\"6\n RetrievePublishedDatasetsRequest\x12\x12\n\ndataRoomId\x18\x01 \x01(\x0c\"X\n\x10PublishedDataset\x12\x0e\n\x06leafId\x18\x01 \x01(\t\x12\x0c\n\x04user\x18\x02 \x01(\t\x12\x11\n\ttimestamp\x18\x03 \x01(\x04\x12\x13\n\x0b\x64\x61tasetHash\x18\x04 \x01(\x0c\"U\n!RetrievePublishedDatasetsResponse\x12\x30\n\x11publishedDatasets\x18\x01 \x03(\x0b\x32\x15.gcg.PublishedDataset\"C\n\x1dRemovePublishedDatasetRequest\x12\x12\n\ndataRoomId\x18\x01 \x01(\x0c\x12\x0e\n\x06leafId\x18\x02 \x01(\t\" \n\x1eRemovePublishedDatasetResponse\"\x94\x01\n CreateConfigurationCommitRequest\x12.\n\x06\x63ommit\x18\x01 \x01(\x0b\x32\x1e.data_room.ConfigurationCommit\x12$\n\x17highLevelRepresentation\x18\x02 \x01(\x0cH\x00\x88\x01\x01\x42\x1a\n\x18_highLevelRepresentation\"5\n!CreateConfigurationCommitResponse\x12\x10\n\x08\x63ommitId\x18\x01 \x01(\x0c\"9\n%GenerateMergeApprovalSignatureRequest\x12\x10\n\x08\x63ommitId\x18\x01 \x01(\x0c\";\n&GenerateMergeApprovalSignatureResponse\x12\x11\n\tsignature\x18\x01 \x01(\x0c\"\xa0\x02\n\x1fMergeConfigurationCommitRequest\x12\x10\n\x08\x63ommitId\x18\x01 \x01(\x0c\x12X\n\x12\x61pprovalSignatures\x18\x02 \x03(\x0b\x32<.gcg.MergeConfigurationCommitRequest.ApprovalSignaturesEntry\x12/\n\"newDataRoomHighLevelRepresentation\x18\x03 \x01(\x0cH\x00\x88\x01\x01\x1a\x39\n\x17\x41pprovalSignaturesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x0c:\x02\x38\x01\x42%\n#_newDataRoomHighLevelRepresentation\"A\n+RetrieveCurrentDataRoomConfigurationRequest\x12\x12\n\ndataRoomId\x18\x01 \x01(\x0c\"t\n,RetrieveCurrentDataRoomConfigurationResponse\x12\x37\n\rconfiguration\x18\x01 \x01(\x0b\x32 .data_room.DataRoomConfiguration\x12\x0b\n\x03pin\x18\x02 \x01(\x0c\"?\n+RetrieveConfigurationCommitApproversRequest\x12\x10\n\x08\x63ommitId\x18\x01 \x01(\x0c\"A\n,RetrieveConfigurationCommitApproversResponse\x12\x11\n\tapprovers\x18\x01 \x03(\t\"6\n\"RetrieveConfigurationCommitRequest\x12\x10\n\x08\x63ommitId\x18\x01 \x01(\x0c\"\x97\x01\n#RetrieveConfigurationCommitResponse\x12.\n\x06\x63ommit\x18\x01 \x01(\x0b\x32\x1e.data_room.ConfigurationCommit\x12$\n\x17highLevelRepresentation\x18\x02 \x01(\x0cH\x00\x88\x01\x01\x42\x1a\n\x18_highLevelRepresentation\"[\n\x18\x43\x61sAuxiliaryStateRequest\x12\x12\n\ndataRoomId\x18\x01 \x01(\x0c\x12\r\n\x05index\x18\x02 \x01(\x04\x12\x12\n\x05value\x18\x03 \x01(\x0cH\x00\x88\x01\x01\x42\x08\n\x06_value\"Y\n\x19\x43\x61sAuxiliaryStateResponse\x12\x0f\n\x07success\x18\x01 \x01(\x08\x12\r\n\x05index\x18\x02 \x01(\x04\x12\x12\n\x05value\x18\x03 \x01(\x0cH\x00\x88\x01\x01\x42\x08\n\x06_value\"/\n\x19ReadAuxiliaryStateRequest\x12\x12\n\ndataRoomId\x18\x01 \x01(\x0c\"F\n\x1aReadAuxiliaryStateResponse\x12(\n\x06values\x18\x02 \x03(\x0b\x32\x18.gcg.AuxiliaryStateValue\"A\n\x13\x41uxiliaryStateValue\x12\x0c\n\x04user\x18\x01 \x01(\t\x12\r\n\x05index\x18\x02 \x01(\x04\x12\r\n\x05value\x18\x03 \x01(\x0c\"\"\n MergeConfigurationCommitResponse\"|\n\x10\x44riverTaskConfig\x12\x1f\n\x04noop\x18\x01 \x01(\x0b\x32\x0f.gcg.NoopConfigH\x00\x12\x31\n\rstaticContent\x18\x02 \x01(\x0b\x32\x18.gcg.StaticContentConfigH\x00\x42\x14\n\x12\x64river_task_config\"\x0c\n\nNoopConfig\"&\n\x13StaticContentConfig\x12\x0f\n\x07\x63ontent\x18\x01 \x01(\x0c\"5\n\x1fRetrieveUsedAirlockQuotaRequest\x12\x12\n\ndataRoomId\x18\x01 \x01(\x0c\"P\n RetrieveUsedAirlockQuotaResponse\x12,\n\rairlockQuotas\x18\x01 \x03(\x0b\x32\x15.gcg.AirlockQuotaInfo\"U\n\x10\x41irlockQuotaInfo\x12\x15\n\rairlockNodeId\x18\x01 \x01(\t\x12\x12\n\nquotaBytes\x18\x02 \x01(\x04\x12\x16\n\x0eusedQuotaBytes\x18\x03 \x01(\x04\"+\n\x16GetResultsSizeResponse\x12\x11\n\tsizeBytes\x18\x01 \x01(\x04*)\n\x0e\x44\x61taRoomStatus\x12\n\n\x06\x41\x63tive\x10\x00\x12\x0b\n\x07Stopped\x10\x01\x62\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'gcg_pb2', _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
  DESCRIPTOR._options = None
  _globals['_EXECUTECOMPUTEREQUEST_PARAMETERSENTRY']._options = None
  _globals['_EXECUTECOMPUTEREQUEST_PARAMETERSENTRY']._serialized_options = b'8\001'
  _globals['_EXECUTECOMPUTEREQUEST_TESTDATASETSENTRY']._options = None
  _globals['_EXECUTECOMPUTEREQUEST_TESTDATASETSENTRY']._serialized_options = b'8\001'
  _globals['_EXECUTEDEVELOPMENTCOMPUTEREQUEST_PARAMETERSENTRY']._options = None
  _globals['_EXECUTEDEVELOPMENTCOMPUTEREQUEST_PARAMETERSENTRY']._serialized_options = b'8\001'
  _globals['_EXECUTEDEVELOPMENTCOMPUTEREQUEST_TESTDATASETSENTRY']._options = None
  _globals['_EXECUTEDEVELOPMENTCOMPUTEREQUEST_TESTDATASETSENTRY']._serialized_options = b'8\001'
  _globals['_MERGECONFIGURATIONCOMMITREQUEST_APPROVALSIGNATURESENTRY']._options = None
  _globals['_MERGECONFIGURATIONCOMMITREQUEST_APPROVALSIGNATURESENTRY']._serialized_options = b'8\001'
  _globals['_DATAROOMSTATUS']._serialized_start=8712
  _globals['_DATAROOMSTATUS']._serialized_end=8753
  _globals['_GCGREQUEST']._serialized_start=64
  _globals['_GCGREQUEST']._serialized_end=1858
  _globals['_GCGRESPONSE']._serialized_start=1861
  _globals['_GCGRESPONSE']._serialized_end=3681
  _globals['_USERAUTH']._serialized_start=3683
  _globals['_USERAUTH']._serialized_end=3788
  _globals['_PKI']._serialized_start=3790
  _globals['_PKI']._serialized_end=3851
  _globals['_CREATEDATAROOMREQUEST']._serialized_start=3854
  _globals['_CREATEDATAROOMREQUEST']._serialized_end=4034
  _globals['_CREATEDATAROOMRESPONSE']._serialized_start=4037
  _globals['_CREATEDATAROOMRESPONSE']._serialized_end=4177
  _globals['_DATAROOMVALIDATIONERROR']._serialized_start=4180
  _globals['_DATAROOMVALIDATIONERROR']._serialized_end=4506
  _globals['_PUBLISHDATASETTODATAROOMREQUEST']._serialized_start=4509
  _globals['_PUBLISHDATASETTODATAROOMREQUEST']._serialized_end=4637
  _globals['_PUBLISHDATASETTODATAROOMRESPONSE']._serialized_start=4639
  _globals['_PUBLISHDATASETTODATAROOMRESPONSE']._serialized_end=4673
  _globals['_EXECUTECOMPUTEREQUEST']._serialized_start=4676
  _globals['_EXECUTECOMPUTEREQUEST']._serialized_end=5030
  _globals['_EXECUTECOMPUTEREQUEST_PARAMETERSENTRY']._serialized_start=4910
  _globals['_EXECUTECOMPUTEREQUEST_PARAMETERSENTRY']._serialized_end=4959
  _globals['_EXECUTECOMPUTEREQUEST_TESTDATASETSENTRY']._serialized_start=4961
  _globals['_EXECUTECOMPUTEREQUEST_TESTDATASETSENTRY']._serialized_end=5030
  _globals['_EXECUTEDEVELOPMENTCOMPUTEREQUEST']._serialized_start=5033
  _globals['_EXECUTEDEVELOPMENTCOMPUTEREQUEST']._serialized_end=5431
  _globals['_EXECUTEDEVELOPMENTCOMPUTEREQUEST_PARAMETERSENTRY']._serialized_start=4910
  _globals['_EXECUTEDEVELOPMENTCOMPUTEREQUEST_PARAMETERSENTRY']._serialized_end=4959
  _globals['_EXECUTEDEVELOPMENTCOMPUTEREQUEST_TESTDATASETSENTRY']._serialized_start=4961
  _globals['_EXECUTEDEVELOPMENTCOMPUTEREQUEST_TESTDATASETSENTRY']._serialized_end=5030
  _globals['_TESTDATASET']._serialized_start=5433
  _globals['_TESTDATASET']._serialized_end=5491
  _globals['_EXECUTECOMPUTERESPONSE']._serialized_start=5493
  _globals['_EXECUTECOMPUTERESPONSE']._serialized_end=5532
  _globals['_JOBSTATUSREQUEST']._serialized_start=5534
  _globals['_JOBSTATUSREQUEST']._serialized_end=5567
  _globals['_JOBSTATUSRESPONSE']._serialized_start=5569
  _globals['_JOBSTATUSRESPONSE']._serialized_end=5620
  _globals['_GETRESULTSREQUEST']._serialized_start=5622
  _globals['_GETRESULTSREQUEST']._serialized_end=5679
  _globals['_GETRESULTSSIZEREQUEST']._serialized_start=5681
  _globals['_GETRESULTSSIZEREQUEST']._serialized_end=5742
  _globals['_GETRESULTSRESPONSECHUNK']._serialized_start=5744
  _globals['_GETRESULTSRESPONSECHUNK']._serialized_end=5783
  _globals['_GETRESULTSRESPONSEFOOTER']._serialized_start=5785
  _globals['_GETRESULTSRESPONSEFOOTER']._serialized_end=5811
  _globals['_RETRIEVEDATAROOMREQUEST']._serialized_start=5813
  _globals['_RETRIEVEDATAROOMREQUEST']._serialized_end=5858
  _globals['_RETRIEVEDATAROOMRESPONSE']._serialized_start=5861
  _globals['_RETRIEVEDATAROOMRESPONSE']._serialized_end=6041
  _globals['_RETRIEVEAUDITLOGREQUEST']._serialized_start=6043
  _globals['_RETRIEVEAUDITLOGREQUEST']._serialized_end=6088
  _globals['_RETRIEVEAUDITLOGRESPONSE']._serialized_start=6090
  _globals['_RETRIEVEAUDITLOGRESPONSE']._serialized_end=6129
  _globals['_RETRIEVEDATAROOMSTATUSREQUEST']._serialized_start=6131
  _globals['_RETRIEVEDATAROOMSTATUSREQUEST']._serialized_end=6182
  _globals['_RETRIEVEDATAROOMSTATUSRESPONSE']._serialized_start=6184
  _globals['_RETRIEVEDATAROOMSTATUSRESPONSE']._serialized_end=6253
  _globals['_UPDATEDATAROOMSTATUSREQUEST']._serialized_start=6255
  _globals['_UPDATEDATAROOMSTATUSREQUEST']._serialized_end=6341
  _globals['_UPDATEDATAROOMSTATUSRESPONSE']._serialized_start=6343
  _globals['_UPDATEDATAROOMSTATUSRESPONSE']._serialized_end=6373
  _globals['_RETRIEVEPUBLISHEDDATASETSREQUEST']._serialized_start=6375
  _globals['_RETRIEVEPUBLISHEDDATASETSREQUEST']._serialized_end=6429
  _globals['_PUBLISHEDDATASET']._serialized_start=6431
  _globals['_PUBLISHEDDATASET']._serialized_end=6519
  _globals['_RETRIEVEPUBLISHEDDATASETSRESPONSE']._serialized_start=6521
  _globals['_RETRIEVEPUBLISHEDDATASETSRESPONSE']._serialized_end=6606
  _globals['_REMOVEPUBLISHEDDATASETREQUEST']._serialized_start=6608
  _globals['_REMOVEPUBLISHEDDATASETREQUEST']._serialized_end=6675
  _globals['_REMOVEPUBLISHEDDATASETRESPONSE']._serialized_start=6677
  _globals['_REMOVEPUBLISHEDDATASETRESPONSE']._serialized_end=6709
  _globals['_CREATECONFIGURATIONCOMMITREQUEST']._serialized_start=6712
  _globals['_CREATECONFIGURATIONCOMMITREQUEST']._serialized_end=6860
  _globals['_CREATECONFIGURATIONCOMMITRESPONSE']._serialized_start=6862
  _globals['_CREATECONFIGURATIONCOMMITRESPONSE']._serialized_end=6915
  _globals['_GENERATEMERGEAPPROVALSIGNATUREREQUEST']._serialized_start=6917
  _globals['_GENERATEMERGEAPPROVALSIGNATUREREQUEST']._serialized_end=6974
  _globals['_GENERATEMERGEAPPROVALSIGNATURERESPONSE']._serialized_start=6976
  _globals['_GENERATEMERGEAPPROVALSIGNATURERESPONSE']._serialized_end=7035
  _globals['_MERGECONFIGURATIONCOMMITREQUEST']._serialized_start=7038
  _globals['_MERGECONFIGURATIONCOMMITREQUEST']._serialized_end=7326
  _globals['_MERGECONFIGURATIONCOMMITREQUEST_APPROVALSIGNATURESENTRY']._serialized_start=7230
  _globals['_MERGECONFIGURATIONCOMMITREQUEST_APPROVALSIGNATURESENTRY']._serialized_end=7287
  _globals['_RETRIEVECURRENTDATAROOMCONFIGURATIONREQUEST']._serialized_start=7328
  _globals['_RETRIEVECURRENTDATAROOMCONFIGURATIONREQUEST']._serialized_end=7393
  _globals['_RETRIEVECURRENTDATAROOMCONFIGURATIONRESPONSE']._serialized_start=7395
  _globals['_RETRIEVECURRENTDATAROOMCONFIGURATIONRESPONSE']._serialized_end=7511
  _globals['_RETRIEVECONFIGURATIONCOMMITAPPROVERSREQUEST']._serialized_start=7513
  _globals['_RETRIEVECONFIGURATIONCOMMITAPPROVERSREQUEST']._serialized_end=7576
  _globals['_RETRIEVECONFIGURATIONCOMMITAPPROVERSRESPONSE']._serialized_start=7578
  _globals['_RETRIEVECONFIGURATIONCOMMITAPPROVERSRESPONSE']._serialized_end=7643
  _globals['_RETRIEVECONFIGURATIONCOMMITREQUEST']._serialized_start=7645
  _globals['_RETRIEVECONFIGURATIONCOMMITREQUEST']._serialized_end=7699
  _globals['_RETRIEVECONFIGURATIONCOMMITRESPONSE']._serialized_start=7702
  _globals['_RETRIEVECONFIGURATIONCOMMITRESPONSE']._serialized_end=7853
  _globals['_CASAUXILIARYSTATEREQUEST']._serialized_start=7855
  _globals['_CASAUXILIARYSTATEREQUEST']._serialized_end=7946
  _globals['_CASAUXILIARYSTATERESPONSE']._serialized_start=7948
  _globals['_CASAUXILIARYSTATERESPONSE']._serialized_end=8037
  _globals['_READAUXILIARYSTATEREQUEST']._serialized_start=8039
  _globals['_READAUXILIARYSTATEREQUEST']._serialized_end=8086
  _globals['_READAUXILIARYSTATERESPONSE']._serialized_start=8088
  _globals['_READAUXILIARYSTATERESPONSE']._serialized_end=8158
  _globals['_AUXILIARYSTATEVALUE']._serialized_start=8160
  _globals['_AUXILIARYSTATEVALUE']._serialized_end=8225
  _globals['_MERGECONFIGURATIONCOMMITRESPONSE']._serialized_start=8227
  _globals['_MERGECONFIGURATIONCOMMITRESPONSE']._serialized_end=8261
  _globals['_DRIVERTASKCONFIG']._serialized_start=8263
  _globals['_DRIVERTASKCONFIG']._serialized_end=8387
  _globals['_NOOPCONFIG']._serialized_start=8389
  _globals['_NOOPCONFIG']._serialized_end=8401
  _globals['_STATICCONTENTCONFIG']._serialized_start=8403
  _globals['_STATICCONTENTCONFIG']._serialized_end=8441
  _globals['_RETRIEVEUSEDAIRLOCKQUOTAREQUEST']._serialized_start=8443
  _globals['_RETRIEVEUSEDAIRLOCKQUOTAREQUEST']._serialized_end=8496
  _globals['_RETRIEVEUSEDAIRLOCKQUOTARESPONSE']._serialized_start=8498
  _globals['_RETRIEVEUSEDAIRLOCKQUOTARESPONSE']._serialized_end=8578
  _globals['_AIRLOCKQUOTAINFO']._serialized_start=8580
  _globals['_AIRLOCKQUOTAINFO']._serialized_end=8665
  _globals['_GETRESULTSSIZERESPONSE']._serialized_start=8667
  _globals['_GETRESULTSSIZERESPONSE']._serialized_end=8710
# @@protoc_insertion_point(module_scope)
