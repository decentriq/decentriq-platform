from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from time import sleep
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Mapping,
    Optional,
    Text,
    Tuple,
)

import chily
from decentriq_dcr_compiler import compiler


from .authentication import Auth
from .connection import Connection
from .channel import Channel, CompilerRequest, CompilerResponse
from .proto import (
    ConfigurationCommit,
    CreateConfigurationCommitRequest,
    CreateDataRoomRequest,
    CreateDataRoomResponse,
    CreateDcrKind,
    CreateDcrPurpose,
    DataRoom,
    DataRoomConfiguration,
    DataRoomStatus,
    DcrMetadata,
    DcrSecretEndorsementRequest,
    DcrSecretEndorsementResponse,
    EndorsementRequest,
    EndorsementResponse,
    ExecuteComputeRequest,
    ExecuteComputeResponse,
    ExecuteDevelopmentComputeRequest,
    GcgRequest,
    GcgResponse,
    GenerateMergeApprovalSignatureRequest,
    GetResultsRequest,
    GetResultsResponseChunk,
    GetResultsSizeRequest,
    JobStatusRequest,
    JobStatusResponse,
    MergeConfigurationCommitRequest,
    MergeConfigurationCommitResponse,
    PkiEndorsementRequest,
    PkiEndorsementResponse,
    PublishDatasetToDataRoomRequest,
    PublishDatasetToDataRoomResponse,
    RemovePublishedDatasetRequest,
    RemovePublishedDatasetResponse,
    RetrieveAuditLogRequest,
    RetrieveAuditLogResponse,
    RetrieveConfigurationCommitApproversRequest,
    RetrieveConfigurationCommitRequest,
    RetrieveConfigurationCommitResponse,
    RetrieveCurrentDataRoomConfigurationRequest,
    RetrieveDataRoomRequest,
    RetrieveDataRoomResponse,
    RetrieveDataRoomStatusRequest,
    RetrievePublishedDatasetsRequest,
    RetrievePublishedDatasetsResponse,
    RetrieveUsedAirlockQuotaRequest,
    TestDataset as TestDatasetProto,
    UpdateDataRoomStatusRequest,
    UpdateDataRoomStatusResponse,
)
from .proto.length_delimited import serialize_length_delimited
from .storage import Key
from .types import DataRoomKind, DryRunOptions, JobId

if TYPE_CHECKING:
    from .client import Client


__all__ = [
    "Session",
    "LATEST_GCG_PROTOCOL_VERSION",
    "LATEST_WORKER_PROTOCOL_VERSION",
]


LATEST_GCG_PROTOCOL_VERSION = 6
LATEST_WORKER_PROTOCOL_VERSION = 1


@dataclass
class AirlockQuotaInfo:
    limit: int
    used: int


def _get_data_room_id(create_data_room_response: CreateDataRoomResponse) -> bytes:
    response_type = create_data_room_response.WhichOneof("create_data_room_response")
    if response_type is None:
        raise Exception("Empty CreateDataRoomResponse")
    elif response_type == "dataRoomId":
        return create_data_room_response.dataRoomId
    elif response_type == "dataRoomValidationError":
        raise Exception(
            "DataRoom creation failed",
            create_data_room_response.dataRoomValidationError,
        )
    else:
        raise Exception(
            "Unknown response type for CreateDataRoomResponse", response_type
        )


class Session:
    """
    Class for managing the communication with an enclave.
    """

    client: Client
    connection: Connection
    auth: Auth
    keypair: Any
    client_protocols: List[int]

    def __init__(
        self,
        client: Client,
        connection: Connection,
        client_protocols: List[int],
        auth: Auth,
    ):
        """
        `Session` instances should not be instantiated directly but rather
         be created using a `Client` object using  `decentriq_platform.Client.create_session`.
        """
        self.client = client
        self.connection = connection
        self.auth = auth
        self.keypair = chily.Keypair.from_random()
        self.client_protocols = client_protocols

    def _get_client_protocol(self, endpoint_protocols: List[int]) -> int:
        try:
            protocol = max(set(self.client_protocols) & set(endpoint_protocols))
            return protocol
        except ValueError:
            min_enclave_version = min(self.client_protocols)
            max_endpoint_version = min(endpoint_protocols)
            exception_message = "Endpoint is only available with protocol versions {} but the enclave only supports {}\n".format(
                endpoint_protocols, self.client_protocols
            )
            if min_enclave_version > max_endpoint_version:
                exception_message += "Try upgrading to a newer version of the SDK"
            else:
                exception_message += "Try using an older version of the SDK"
            raise Exception(exception_message)

    def _send_endorsement_request(
        self,
        request: EndorsementRequest,
        protocol: int,
    ) -> EndorsementResponse:
        responses = self.send_request(GcgRequest(endorsementRequest=request), protocol)
        if len(responses) != 1:
            raise Exception("Malformed response")

        response = responses[0]

        if not response.HasField("endorsementResponse"):
            raise Exception(
                "Expected endorsementResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )
        return response.endorsementResponse

    def pki_endorsement(
        self,
        certificate_chain_pem: bytes,
    ) -> PkiEndorsementResponse:
        endpoint_protocols = [3, 4, 5, 6]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = PkiEndorsementRequest(certificateChainPem=certificate_chain_pem)
        response = self._send_endorsement_request(
            EndorsementRequest(pkiEndorsementRequest=request), protocol
        )

        if not response.HasField("pkiEndorsementResponse"):
            raise Exception(
                "Expected pkiEndorsementResponse, got "
                + str(response.WhichOneof("endorsementResponse"))
            )
        return response.pkiEndorsementResponse

    def dcr_secret_endorsement(
        self,
        dcr_secret: str,
    ) -> DcrSecretEndorsementResponse:
        endpoint_protocols = [3, 4, 5, 6]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = DcrSecretEndorsementRequest(
            dcrSecret=dcr_secret,
        )
        response = self._send_endorsement_request(
            EndorsementRequest(dcrSecretEndorsementRequest=request), protocol
        )

        if not response.HasField("dcrSecretEndorsementResponse"):
            raise Exception(
                "Expected dcrSecretEndorsementResponse, got "
                + str(response.WhichOneof("endorsementResponse"))
            )
        return response.dcrSecretEndorsementResponse

    def send_request(
        self,
        request: GcgRequest,
        protocol: int,
    ) -> List[GcgResponse]:
        """
        Low-level method for sending a raw `GcgRequest` to the enclave.
        Use this method if any of the convenience methods (such as `run_computation`) don't perform
        the exact task you want.
        """
        responses = self.connection.send_request(request, protocol, self.auth)
        return responses

    def send_request_raw(
        self,
        request: bytes,
        protocol: int,
    ) -> List[bytes]:
        """
        Low-level method for sending a raw `GcgRequest` to the enclave.
        Use this method if any of the convenience methods (such as `run_computation`) don't perform
        the exact task you want.
        """
        responses = self.connection.send_request_raw(request, protocol, self.auth)
        return responses

    def send_compilable_request(
        self,
        compile_request: Callable[[CompilerRequest, Channel], bytes],
        request: CompilerRequest,
        decompile_response: Callable[[List[bytes]], CompilerResponse],
        protocol: int,
    ) -> CompilerResponse:
        response = self.connection.send_compilable_request(
            compile_request, request, decompile_response, protocol, self.auth
        )
        return response

    def _publish_data_room(
        self,
        data_room_definition: DataRoom,
        purpose: CreateDcrPurpose.V = CreateDcrPurpose.STANDARD,
        kind: CreateDcrKind.V = CreateDcrKind.EXPERT,
        show_organization_logo: bool = False,
        require_password: bool = False,
        high_level_representation: Optional[bytes] = None,
    ) -> CreateDataRoomResponse:
        endpoint_protocols = [3, 4, 5, 6]
        protocol = self._get_client_protocol(endpoint_protocols)

        metadata = DcrMetadata(
            showOrganizationLogo=show_organization_logo,
            requirePassword=require_password,
            purpose=purpose,
            kind=kind,
        )
        request = CreateDataRoomRequest(
            dataRoom=data_room_definition,
            highLevelRepresentation=high_level_representation,
            dataRoomMetadata=serialize_length_delimited(metadata),
        )
        responses = self.send_request(
            GcgRequest(createDataRoomRequest=request), protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")

        response = responses[0]

        if response.HasField("createDataRoomResponse"):
            if response.createDataRoomResponse.HasField("dataRoomValidationError"):
                raise Exception(
                    "Error when validating data room: {} (compute node id '{}')".format(
                        response.createDataRoomResponse.dataRoomValidationError.message,
                        response.createDataRoomResponse.dataRoomValidationError.computeNodeId,
                    )
                )
        else:
            raise Exception(
                "Expected createDataRoomResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )

        return response.createDataRoomResponse

    def publish_data_room(
        self,
        data_room_definition: DataRoom,
        /,
        *,
        show_organization_logo: bool = False,
        require_password: bool = False,
        purpose: CreateDcrPurpose.V = CreateDcrPurpose.STANDARD,
        kind: CreateDcrKind.V = CreateDcrKind.EXPERT,
        high_level_representation: Optional[bytes] = None,
    ) -> str:
        """
        Create a data room with the provided protobuf configuration object
        and have the enclave apply the given list of modifications to the data
        room configuration.

        The id returned from this method will be used when interacting with the
        published data room (for example when running computations or publishing
        datasets).
        """
        response = self._publish_data_room(
            data_room_definition,
            purpose,
            kind,
            show_organization_logo,
            require_password,
            high_level_representation,
        )
        return _get_data_room_id(response).hex()

    def publish_data_room_configuration_commit(
        self, configuration_commit: ConfigurationCommit
    ) -> str:
        """
        Publish the given data room configuration commit.

        Configuration commits can be built using a `DataRoomCommitBuilder` object.

        The id returned from this method will be used when running development
        computations or when trying to merge this commit into the main
        data room configuration.
        """
        endpoint_protocols = [3, 4, 5, 6]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = CreateConfigurationCommitRequest(
            commit=configuration_commit,
        )
        responses = self.send_request(
            GcgRequest(createConfigurationCommitRequest=request), protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")

        response = responses[0]
        if not response.HasField("createConfigurationCommitResponse"):
            raise Exception(
                "Expected createConfigurationCommitResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )

        return response.createConfigurationCommitResponse.commitId.hex()

    def retrieve_configuration_commit(
        self,
        configuration_commit_id: str,
    ) -> RetrieveConfigurationCommitResponse:
        """
        Retrieve the content of given configuration commit id.

        **Returns**:
        A `ConfigurationCommit`.
        """
        endpoint_protocols = [3, 4, 5, 6]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = RetrieveConfigurationCommitRequest(
            commitId=bytes.fromhex(configuration_commit_id),
        )
        responses = self.send_request(
            GcgRequest(retrieveConfigurationCommitRequest=request), protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")

        response = responses[0]
        if not response.HasField("retrieveConfigurationCommitResponse"):
            raise Exception(
                "Expected retrieveConfigurationCommitResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )

        return response.retrieveConfigurationCommitResponse

    def retrieve_configuration_commit_approvers(
        self,
        configuration_commit_id: str,
    ) -> List[str]:
        """
        Retrieve the list of users who need to approve the merger of a given
        configuration commit.

        **Returns**:
        A list of ids belonging to the users that need to approve the
        configuration commit.
        """
        endpoint_protocols = [3, 4, 5, 6]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = RetrieveConfigurationCommitApproversRequest(
            commitId=bytes.fromhex(configuration_commit_id),
        )
        responses = self.send_request(
            GcgRequest(retrieveConfigurationCommitApproversRequest=request), protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")

        response = responses[0]
        if not response.HasField("retrieveConfigurationCommitApproversResponse"):
            raise Exception(
                "Expected retrieveConfigurationCommitApproversResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )

        return list(response.retrieveConfigurationCommitApproversResponse.approvers)

    def generate_merge_approval_signature(self, configuration_commit_id: str) -> bytes:
        """
        Generate an approval signature required for merging a configuration
        commit.

        To merge a specific configuration commit, each user referenced in the list
        of ids returned by `retrieveConfigurationCommitApprovers` needs to
        generate an approval signature using this method.
        """
        endpoint_protocols = [3, 4, 5, 6]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = GenerateMergeApprovalSignatureRequest(
            commitId=bytes.fromhex(configuration_commit_id),
        )
        responses = self.send_request(
            GcgRequest(generateMergeApprovalSignatureRequest=request), protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")

        response = responses[0]
        if not response.HasField("generateMergeApprovalSignatureResponse"):
            raise Exception(
                "Expected generateMergeApprovalSignatureResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )

        return response.generateMergeApprovalSignatureResponse.signature

    def merge_configuration_commit(
        self,
        configuration_commit_id: str,
        approval_signatures: Dict[str, bytes],
    ) -> MergeConfigurationCommitResponse:
        """
        Request the enclave to merge the given configuration commit into the
        main data room configuration.

        **Parameters**:
        - `configuration_commit_id`: The id of the commit to be merged.
        - `approval_signatures`: A dictionary containing the approval signature for
            each of the required approvers, e.g. `{ "some@email.com": signature }`.
        """
        endpoint_protocols = [3, 4, 5, 6]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = MergeConfigurationCommitRequest(
            commitId=bytes.fromhex(configuration_commit_id),
            approvalSignatures=approval_signatures,
        )
        responses = self.send_request(
            GcgRequest(mergeConfigurationCommitRequest=request), protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")

        response = responses[0]
        if not response.HasField("mergeConfigurationCommitResponse"):
            raise Exception(
                "Expected mergeConfigurationCommitResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )

        return response.mergeConfigurationCommitResponse

    def retrieve_current_data_room_configuration(
        self, data_room_id: str
    ) -> Tuple[DataRoomConfiguration, str]:
        """
        Retrieve the current data room confguration, as well as the current "history pin".

        A history pin is the hash of all the ids of configuration commits that
        make up the structure of a data room. This pin therefore uniquely identifies
        a data room's structure at a certain point in time.
        A data room configuration, as well as its associated history pin, can be used
        to extend an existing data room (for example by adding new compute nodes).
        Extending an existing data room is done using the `DataRoomCommitBuilder` class.
        """
        endpoint_protocols = [3, 4, 5, 6]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = RetrieveCurrentDataRoomConfigurationRequest(
            dataRoomId=bytes.fromhex(data_room_id),
        )
        responses = self.send_request(
            GcgRequest(retrieveCurrentDataRoomConfigurationRequest=request), protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")
        gcg_response = responses[0]
        if not gcg_response.HasField("retrieveCurrentDataRoomConfigurationResponse"):
            raise Exception(
                "Expected retrieveCurrentDataRoomConfigurationResponse, got "
                + str(gcg_response.WhichOneof("gcg_response"))
            )

        response = gcg_response.retrieveCurrentDataRoomConfigurationResponse
        return (response.configuration, response.pin.hex())

    def stop_data_room(self, data_room_id: str):
        """
        Stop the data room with the given id, making it impossible to run new
        computations.
        """
        self._update_data_room_status(data_room_id, DataRoomStatus.Value("Stopped"))

    def _update_data_room_status(
        self, data_room_id: str, status  # type: DataRoomStatus.V
    ) -> UpdateDataRoomStatusResponse:
        """
        Update the status of the data room.

        For the special case of stopping a data room, the method
        `stop_data_room` can be used.
        """
        endpoint_protocols = [3, 4, 5, 6]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = UpdateDataRoomStatusRequest(
            dataRoomId=bytes.fromhex(data_room_id),
            status=status,
        )
        responses = self.send_request(
            GcgRequest(updateDataRoomStatusRequest=request), protocol
        )

        if len(responses) != 1:
            raise Exception("Malformed response")

        response = responses[0]
        if not response.HasField("updateDataRoomStatusResponse"):
            raise Exception(
                "Expected updateDataRoomStatusResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )

        return response.updateDataRoomStatusResponse

    def retrieve_data_room_status(self, data_room_id: str) -> str:
        """
        Returns the status of the data room. Valid values are `"Active"` or `"Stopped"`.
        """
        endpoint_protocols = [3, 4, 5, 6]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = RetrieveDataRoomStatusRequest(
            dataRoomId=bytes.fromhex(data_room_id),
        )
        responses = self.send_request(
            GcgRequest(retrieveDataRoomStatusRequest=request), protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")
        response = responses[0]
        if not response.HasField("retrieveDataRoomStatusResponse"):
            raise Exception(
                "Expected retrieveDataRoomStatusResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )

        return DataRoomStatus.Name(response.retrieveDataRoomStatusResponse.status)

    def retrieve_data_room(self, data_room_id: str) -> RetrieveDataRoomResponse:
        """
        Returns the underlying protobuf object for the data room.
        """
        endpoint_protocols = [3, 4, 5, 6]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = RetrieveDataRoomRequest(
            dataRoomId=bytes.fromhex(data_room_id),
        )
        responses = self.send_request(
            GcgRequest(retrieveDataRoomRequest=request), protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")
        response = responses[0]
        if not response.HasField("retrieveDataRoomResponse"):
            raise Exception(
                "Expected retrieveDataRoomResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )
        return response.retrieveDataRoomResponse

    def retrieve_audit_log(self, data_room_id: str) -> RetrieveAuditLogResponse:
        """
        Returns the audit log for the data room.
        """
        endpoint_protocols = [3, 4, 5, 6]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = RetrieveAuditLogRequest(
            dataRoomId=bytes.fromhex(data_room_id),
        )
        responses = self.send_request(
            GcgRequest(retrieveAuditLogRequest=request), protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")
        response = responses[0]
        if not response.HasField("retrieveAuditLogResponse"):
            raise Exception(
                "Expected retrieveAuditLogResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )
        return response.retrieveAuditLogResponse

    def retrieve_data_room_json(self, data_room_id: str) -> str:
        """
        Get the JSON configuration file for the data room with the given ID.
        Returns a JSON string representing the configuration.
        """
        dcr_kind = self.client._get_data_room_kind(data_room_id)
        if dcr_kind == DataRoomKind.DATA_SCIENCE:
            dcr = self.retrieve_data_room(data_room_id)
            commits = [serialize_length_delimited(c) for c in dcr.commits]
            verified_dcr = compiler.verify_data_room(
                serialize_length_delimited(dcr.dataRoom),
                commits,
                dcr.highLevelRepresentation,
            )
            latest_dcr = compiler.upgrade_data_science_data_room_to_latest(verified_dcr)
            output = {
                # Format timestamp as ISO standard UTC time.
                "createdAt": str(datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f"))[:-3]
                + "Z",
                "dataScienceDataRoom": json.loads(latest_dcr.json()),
            }
            return json.dumps(output, indent=2)
        else:
            raise Exception(f"Cannot retrieve JSON for data room kind {dcr_kind}")

    def publish_dataset(
        self,
        data_room_id: str,
        manifest_hash: str,
        leaf_id: str,
        key: Key,
        *,
        force: bool = False,
    ) -> PublishDatasetToDataRoomResponse:
        """
        Publishes a file and its encryption key to a data room.
        Neither the file or the encryption key will ever be stored in
        unencrypted form.

        This method will check whether the to-be-published file exists.
        If this is not the case, an exception will be raised.
        This behavior can be disabled by setting the `force` flag.

        In case the original client was created with platform integration
        enabled, the method will further check whether there already
        is a dataset published for the given data room.
        In this case, an exception will be thrown and the dataset
        will need to be unpublished first.

        A special note for when the referenced data room was created using the Decentriq UI:
        In this case, the `leaf_id` argument will have the format `{NODE_ID}_leaf`,
        where `{NODE_ID}` corresponds to the value that you see when hovering your mouse pointer over
        the name of the data node.
        """

        endpoint_protocols = [3, 4, 5, 6]
        protocol = self._get_client_protocol(endpoint_protocols)
        dataset = self.client.get_dataset(manifest_hash)
        if not dataset and not force:
            raise Exception("The dataset you are trying to publish does not exist")

        scope_id = self.client._ensure_dcr_data_scope(
            data_room_id,
        )
        scope_id_bytes = bytes.fromhex(scope_id)
        request = PublishDatasetToDataRoomRequest(
            dataRoomId=bytes.fromhex(data_room_id),
            datasetHash=bytes.fromhex(manifest_hash),
            leafId=leaf_id,
            encryptionKey=key.material,
            scope=scope_id_bytes,
        )
        responses = self.send_request(
            GcgRequest(publishDatasetToDataRoomRequest=request), protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")
        response = responses[0]
        if not response.HasField("publishDatasetToDataRoomResponse"):
            raise Exception(
                "Expected publishDatasetToDataRoomResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )

        return response.publishDatasetToDataRoomResponse

    def remove_published_dataset(
        self,
        data_room_id: str,
        leaf_id: str,
    ) -> RemovePublishedDatasetResponse:
        """
        Removes a published dataset from the data room.

        **Parameters**:
        - `data_room_id`: The ID of the data room that contains the given data set.
        - `leaf_id`: The ID of the data node from which the dataset should be removed.
            In case the referenced data room was created using the Decentriq UI,
            the `leaf_id` argument will have the special format `@table/UUID/dataset`
            (where `UUID` corresponds to the value that you see when hovering your mouse pointer over
            the name of the data node).
        """
        endpoint_protocols = [3, 4, 5, 6]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = RemovePublishedDatasetRequest(
            dataRoomId=bytes.fromhex(data_room_id),
            leafId=leaf_id,
        )
        responses = self.send_request(
            GcgRequest(removePublishedDatasetRequest=request), protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")
        response = responses[0]
        if not response.HasField("removePublishedDatasetResponse"):
            raise Exception(
                "Expected removePublishedDatasetResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )

        return response.removePublishedDatasetResponse

    def retrieve_published_datasets(
        self,
        data_room_id: str,
    ) -> RetrievePublishedDatasetsResponse:
        """
        Returns the datasets published to the given data room.
        """
        endpoint_protocols = [3, 4, 5, 6]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = RetrievePublishedDatasetsRequest(
            dataRoomId=bytes.fromhex(data_room_id),
        )
        responses = self.send_request(
            GcgRequest(retrievePublishedDatasetsRequest=request), protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")
        response = responses[0]
        if not response.HasField("retrievePublishedDatasetsResponse"):
            raise Exception(
                "Expected retrievePublishedDatasetResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )
        return response.retrievePublishedDatasetsResponse

    def _submit_dev_compute(
        self,
        data_room_id: str,
        configuration_commit_id: str,
        compute_node_ids: List[str],
        /,
        *,
        dry_run: Optional[DryRunOptions] = None,
        parameters: Optional[Mapping[Text, Text]] = None,
    ) -> ExecuteComputeResponse:
        """
        Submits a computation request which will generate an execution plan to
        perform the computation of the goal nodes
        """
        endpoint_protocols = [5, 6]
        if (
            not dry_run
            or not "test_datasets" in dry_run
            or not dry_run["test_datasets"]
        ):
            endpoint_protocols.append(3)
            endpoint_protocols.append(4)

        protocol = self._get_client_protocol(endpoint_protocols)
        scope_id = self.client._ensure_dcr_data_scope(
            data_room_id,
        )
        scope_id_bytes = bytes.fromhex(scope_id)

        is_dry_run = dry_run is not None
        test_datasets_map = (
            dry_run["test_datasets"] if dry_run and "test_datasets" in dry_run else {}
        )
        test_datasets = {
            k: TestDatasetProto(
                manifestHash=bytes.fromhex(v["manifest_hash"]),
                encryptionKey=v["key"].material,
            )
            for k, v in test_datasets_map.items()
        }

        request = ExecuteDevelopmentComputeRequest(
            configurationCommitId=bytes.fromhex(configuration_commit_id),
            computeNodeIds=compute_node_ids,
            isDryRun=is_dry_run,
            scope=scope_id_bytes,
            testDatasets=test_datasets,
            parameters=parameters,
        )
        responses = self.send_request(
            GcgRequest(executeDevelopmentComputeRequest=request), protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")
        response = responses[0]
        if not response.HasField("executeComputeResponse"):
            raise Exception(
                "Expected executeComputeResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )
        return response.executeComputeResponse

    def _submit_compute(
        self,
        data_room_id: str,
        compute_node_ids: List[str],
        /,
        *,
        dry_run: Optional[DryRunOptions] = None,
        parameters: Optional[Mapping[Text, Text]] = None,
    ) -> ExecuteComputeResponse:
        """
        Submits a computation request which will generate an execution plan to
        perform the computation of the goal nodes
        """
        endpoint_protocols = [5, 6]
        if (
            not dry_run
            or not "test_datasets" in dry_run
            or not dry_run["test_datasets"]
        ):
            endpoint_protocols.append(3)
            endpoint_protocols.append(4)

        protocol = self._get_client_protocol(endpoint_protocols)
        scope_id = self.client._ensure_dcr_data_scope(
            data_room_id,
        )
        scope_id_bytes = bytes.fromhex(scope_id)

        is_dry_run = dry_run is not None
        test_datasets_map = (
            dry_run["test_datasets"] if dry_run and "test_datasets" in dry_run else {}
        )
        test_datasets = {
            k: TestDatasetProto(
                manifestHash=bytes.fromhex(v["manifest_hash"]),
                encryptionKey=v["key"].material,
            )
            for k, v in test_datasets_map.items()
        }
        request = ExecuteComputeRequest(
            dataRoomId=bytes.fromhex(data_room_id),
            computeNodeIds=compute_node_ids,
            isDryRun=is_dry_run,
            scope=scope_id_bytes,
            testDatasets=test_datasets,
            parameters=parameters,
        )
        responses = self.send_request(
            GcgRequest(executeComputeRequest=request), protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")
        response = responses[0]
        if not response.HasField("executeComputeResponse"):
            raise Exception(
                "Expected executeComputeResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )
        return response.executeComputeResponse

    def get_computation_status(self, job_id: str) -> JobStatusResponse:
        """
        Returns the status of the provided `job_id` which will include the names
        of the nodes that completed their execution
        """
        endpoint_protocols = [3, 4, 5, 6]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = JobStatusRequest(
            jobId=bytes.fromhex(job_id),
        )
        responses = self.send_request(GcgRequest(jobStatusRequest=request), protocol)
        if len(responses) != 1:
            raise Exception("Malformed response")
        response = responses[0]
        if not response.HasField("jobStatusResponse"):
            raise Exception(
                "Expected jobStatusResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )
        return response.jobStatusResponse

    def _stream_job_results(
        self,
        job_id: bytes,
        compute_node_id: str,
    ) -> Iterator[GetResultsResponseChunk]:
        """
        Streams the results of the provided `job_id`
        """
        endpoint_protocols = [3, 4, 5, 6]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = GetResultsRequest(
            jobId=job_id,
            computeNodeId=compute_node_id,
        )
        responses = self.send_request(GcgRequest(getResultsRequest=request), protocol)
        for response in responses:
            if response.HasField("getResultsResponseChunk"):
                yield response.getResultsResponseChunk
            elif response.HasField("getResultsResponseFooter"):
                return
            else:
                raise Exception(
                    "Expected getResultsResponseChunk or getResultsResponseFooter, got "
                    + str(response.WhichOneof("gcg_response"))
                )
        raise Exception("Enclave connection aborted while streaming results")

    def _get_job_results(
        self,
        job_id: bytes,
        compute_node_id: str,
    ) -> bytes:
        """
        Returns the results of the provided `job_id`
        """
        return b"".join(
            list(
                map(
                    lambda chunk: chunk.data,
                    self._stream_job_results(job_id, compute_node_id),
                )
            )
        )

    def run_computation(
        self,
        data_room_id: str,
        compute_node_id: str,
        /,
        *,
        dry_run: Optional[DryRunOptions] = None,
        parameters: Optional[Mapping[Text, Text]] = None,
    ) -> JobId:
        """
        Run a specific computation within the data room with the given id.

        The result will be an identifier object of the job executing the computation.
        This object is required for checking a job's status and retrieving its results.
        """
        response = self._submit_compute(
            data_room_id, [compute_node_id], dry_run=dry_run, parameters=parameters
        )
        return JobId(response.jobId.hex(), compute_node_id)

    def wait_until_computation_has_finished(
        self, job_id: JobId, /, *, interval: int = 5, timeout: Optional[int] = None
    ):
        """
        Wait for the given job to complete.

        The method will check for the job's completeness every `interval` seconds and up to
        an optional `timeout` seconds after which the method will raise an exception.
        """
        elapsed = 0
        while True:
            if timeout is not None and elapsed > timeout:
                raise Exception(
                    f"Timeout when trying to get result for job {job_id.id} of"
                    f" {job_id.compute_node_id} (waited {timeout} seconds)"
                )
            elif (
                job_id.compute_node_id
                in self.get_computation_status(job_id.id).completeComputeNodeIds
            ):
                break
            else:
                sleep(interval)
                elapsed += interval

    def wait_until_computation_has_finished_for_all_compute_nodes(
        self,
        job_id: str,
        compute_node_ids: List[str],
        /,
        *,
        interval: int = 5,
        timeout: Optional[int] = None,
    ):
        """
        Wait for the given job to complete for all of the given compute nodes.

        The method will check for the job's completeness every `interval` seconds and up to
        an optional `timeout` seconds after which the method will raise an exception.
        """
        elapsed = 0
        while True:
            if timeout is not None and elapsed > timeout:
                raise Exception(
                    f"Timeout when trying to get result for job {job_id} (waited {timeout} seconds)"
                )
            elif set(compute_node_ids).issubset(
                self.get_computation_status(job_id).completeComputeNodeIds
            ):
                break
            else:
                sleep(interval)
                elapsed += interval

    def run_dev_computation(
        self,
        data_room_id: str,
        configuration_commit_id: str,
        compute_node_id: str,
        /,
        *,
        dry_run: Optional[DryRunOptions] = None,
        parameters: Optional[Mapping[Text, Text]] = None,
    ) -> JobId:
        """
        Run a specific computation within the context of the data room configuration
        defined by the given commit id.
        Such "development" computations can also be run for configuration commits
        that have not yet been merged.

        The result will be an identifier object of the job executing the computation.
        This object is required for checking a job's status and retrieving its results.
        """
        response = self._submit_dev_compute(
            data_room_id,
            configuration_commit_id,
            [compute_node_id],
            dry_run=dry_run,
            parameters=parameters,
        )
        return JobId(response.jobId.hex(), compute_node_id)

    def get_computation_result(
        self,
        job_id: JobId,
        /,
        *,
        interval: int = 5,
        timeout: Optional[int] = None,
    ) -> bytes:
        """
        Wait for the given job to complete and retrieve its results as a raw byte string.

        The method will check for the job's completeness every `interval` seconds and up to
        an optional `timeout` seconds after which the method will raise an exception.
        If the job completes and the results can be retrieved successfully, a raw byte string
        will be returned. The bytes string can be transformed into a more useful object using
        a variety of helper methods. These helper methods are specific for the type of computation
        you ran and can be found in the corresponding packages.
        """
        job_id_bytes = bytes.fromhex(job_id.id)
        self.wait_until_computation_has_finished(
            job_id, interval=interval, timeout=timeout
        )
        results = self._get_job_results(job_id_bytes, job_id.compute_node_id)
        return results

    def get_computation_result_size(
        self,
        job_id: JobId,
        /,
        *,
        interval: int = 5,
        timeout: Optional[int] = None,
    ) -> int:
        """
        Wait for the given job to complete and retrieve its results size.

        The method will check for the job's completeness every `interval` seconds and up to
        an optional `timeout` seconds after which the method will raise an exception.
        If the job completes and the results can be retrieved successfully, an int containing
        the raw result size is returned.
        """
        endpoint_protocols = [6]
        protocol = self._get_client_protocol(endpoint_protocols)
        job_id_bytes = bytes.fromhex(job_id.id)
        self.wait_until_computation_has_finished(
            job_id, interval=interval, timeout=timeout
        )
        request = GetResultsSizeRequest(
            jobId=job_id_bytes,
            computeNodeId=job_id.compute_node_id,
        )
        responses = self.send_request(
            GcgRequest(getResultsSizeRequest=request), protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")
        response = responses[0]
        if not response.HasField("getResultsSizeResponse"):
            raise Exception(
                "Expected getResultsSizeResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )
        return response.getResultsSizeResponse.sizeBytes

    def run_computation_and_get_results(
        self,
        data_room_id: str,
        compute_node_id: str,
        /,
        *,
        interval: int = 5,
        timeout: Optional[int] = None,
        parameters: Optional[Mapping[Text, Text]] = None,
    ) -> Optional[bytes]:
        """
        Run a specific computation and return its results.

        This method is simply a wrapper for running `run_computation` and
        `get_computation_result` directly after each other
        """
        job_id = self.run_computation(
            data_room_id, compute_node_id, parameters=parameters
        )
        return self.get_computation_result(job_id, interval=interval, timeout=timeout)

    def retrieve_used_airlock_quotas(
        self,
        data_room_id: str,
    ) -> Dict[str, AirlockQuotaInfo]:
        """
        Retrieves the limit and used airlock quota for the current user.
        """
        endpoint_protocols = [6]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = RetrieveUsedAirlockQuotaRequest(
            dataRoomId=bytes.fromhex(data_room_id),
        )
        responses = self.send_request(
            GcgRequest(retrieveUsedAirlockQuotaRequest=request), protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")
        response = responses[0]
        if not response.HasField("retrieveUsedAirlockQuotaResponse"):
            raise Exception(
                "Expected retrieveUsedAirlockQuotaResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )
        return {
            airlock_quota.airlockNodeId: AirlockQuotaInfo(
                airlock_quota.quotaBytes, airlock_quota.usedQuotaBytes
            )
            for airlock_quota in response.retrieveUsedAirlockQuotaResponse.airlockQuotas
        }
