from __future__ import annotations
import chily
import re
import hashlib
import hmac
import json
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from typing import Any, List, Tuple, TYPE_CHECKING, Iterator, Optional, Dict
from time import sleep
from .platform import PlatformApi
from .api import Endpoints
from .authentication import Auth, Sigma
from .proto import (
    DataRoom, ComputeNodeProtocol, DataNoncePubkey, Request, Response,
    CreateDataRoomRequest, CreateDataRoomResponse,
    ExecuteComputeRequest, ExecuteComputeResponse, GcgRequest, GcgResponse, GetResultsRequest,
    GetResultsResponseChunk, JobStatusRequest, JobStatusResponse,
    PublishDatasetToDataRoomRequest, PublishDatasetToDataRoomResponse,
    RemovePublishedDatasetRequest, RemovePublishedDatasetResponse,
    RetrieveAuditLogRequest, RetrieveAuditLogResponse, RetrieveDataRoomRequest,
    RetrieveDataRoomResponse, RetrieveDataRoomStatusRequest,
    RetrievePublishedDatasetsRequest,
    RetrievePublishedDatasetsResponse, UpdateDataRoomStatusRequest,
    ExecuteDevelopmentComputeRequest, CreateConfigurationCommitRequest,
    GenerateMergeApprovalSignatureRequest, MergeConfigurationCommitRequest,
    RetrieveDataRoomConfigurationHistoryRequest, RetrieveDataRoomConfigurationHistoryResponse,
    UpdateDataRoomStatusResponse, DataRoomStatus, AttestationSpecification, Fatquote,
    CreateConfigurationCommitRequest, RetrieveConfigurationCommitApproversRequest,
    RetrieveConfigurationCommitRequest
)
from .proto.length_delimited import parse_length_delimited, serialize_length_delimited
from .storage import Key
from .types import FatquoteResBody, EnclaveMessage, ScopeTypes, JobId
from .verification import QuoteBody, Verification
from .platform import SessionPlatformFeatures
if TYPE_CHECKING:
    from .client import Client


__all__ = [ "Session", "LATEST_GCG_PROTOCOL_VERSION", "LATEST_WORKER_PROTOCOL_VERSION" ]


LATEST_GCG_PROTOCOL_VERSION = 1
LATEST_WORKER_PROTOCOL_VERSION = 0


def _get_data_room_id(create_data_room_response: CreateDataRoomResponse) -> bytes:
    response_type = create_data_room_response.WhichOneof("create_data_room_response")
    if response_type is None:
        raise Exception("Empty CreateDataRoomResponse")
    elif response_type == "dataRoomId":
        return create_data_room_response.dataRoomId
    elif response_type == "dataRoomValidationError":
        raise Exception(
            "DataRoom creation failed",
            create_data_room_response.dataRoomValidationError
        )
    else:
        raise Exception("Unknown response type for CreateDataRoomResponse", response_type)


def datanoncepubkey_to_message(
        encrypted_data: bytes,
        nonce: bytes,
        pubkey: bytes,
        sigma_auth: Sigma
) -> DataNoncePubkey:
    message = DataNoncePubkey()
    message.data = encrypted_data
    message.nonce = nonce
    message.pubkey = pubkey
    message.pki.certChainPem = sigma_auth.get_cert_chain()
    message.pki.signature = sigma_auth.get_signature()
    message.pki.idMac = sigma_auth.get_mac_tag()
    return message


def message_to_datanoncepubkey(message: bytes) -> Tuple[bytes, bytes, bytes]:
    parsed_msg = DataNoncePubkey()
    parse_length_delimited(message, parsed_msg)
    return (parsed_msg.data, parsed_msg.nonce, parsed_msg.pubkey)


class Session():
    """
    Class for managing the communication with an enclave.
    """
    client: Client
    session_id: str
    enclave_identifier: str
    auth: Auth
    email: str
    keypair: Any
    fatquote: Fatquote
    quote: QuoteBody
    driver_attestation_specification: AttestationSpecification
    client_protocols: List[int]

    def __init__(
            self,
            client: Client,
            session_id: str,
            driver_attestation_specification: AttestationSpecification,
            client_protocols: List[int],
            auth: Auth,
            platform_api: Optional[PlatformApi] = None,
   ):
        """
        `Session` instances should not be instantiated directly but rather
         be created using a `Client` object using  `decentriq_platform.Client.create_session`.
        """
        url = Endpoints.SESSION_FATQUOTE.replace(":sessionId", session_id)
        response: FatquoteResBody = client._api.get(url).json()
        fatquote_bytes = b64decode(response["fatquoteBase64"])
        fatquote = Fatquote()
        fatquote.ParseFromString(fatquote_bytes)
        verification = Verification(attestation_specification=driver_attestation_specification)
        report_data = verification.verify(fatquote)
        self.client = client
        self.session_id = session_id
        self.auth = auth
        self.email = auth.user_id
        self.keypair = chily.Keypair.from_random()
        self.fatquote = fatquote
        self.report_data = report_data
        self.driver_attestation_specification = driver_attestation_specification
        self.client_protocols = client_protocols

        if platform_api:
            self._platform = SessionPlatformFeatures(self, platform_api)
        else:
            self._platform = None

    def _get_client_protocol(self, endpoint_protocols: List[int]) -> int:
        try:
            protocol = max(set(self.client_protocols) & set(endpoint_protocols))
            return protocol
        except ValueError:
            min_enclave_version = min(self.client_protocols)
            max_endpoint_version = min(endpoint_protocols)
            exception_message = "Endpoint is only available with protocol versions {} but the enclave only supports {}\n".format(
                endpoint_protocols,
                self.client_protocols
            )
            if min_enclave_version > max_endpoint_version:
                exception_message += "Try upgrading to a newer version of the SDK"
            else:
                exception_message += "Try using an older version of the SDK"
            raise Exception(exception_message)

    def _get_enclave_pubkey(self):
        pub_keyB = bytearray(self.report_data[:32])
        return chily.PublicKey.from_bytes(pub_keyB)

    def _encrypt_and_encode_data(self, data: bytes, auth: Auth) -> bytes:
        nonce = chily.Nonce.from_random()
        cipher = chily.Cipher(
            self.keypair.secret, self._get_enclave_pubkey()
        )
        enc_data = cipher.encrypt("client sent session data", data, nonce)
        public_keys = bytes(self.keypair.public_key.bytes) + bytes(self._get_enclave_pubkey().bytes)
        signature = auth._sign(public_keys)
        shared_key = bytes(self.keypair.secret.diffie_hellman(self._get_enclave_pubkey()).bytes)
        hkdf = HKDF(algorithm=hashes.SHA512(), length=64, info=b"IdP KDF Context", salt=b"")
        mac_key = hkdf.derive(shared_key)
        mac_tag = hmac.digest(mac_key, auth._get_user_id().encode(), "sha512")
        sigma_auth = Sigma(signature, mac_tag, auth)
        return datanoncepubkey_to_message(
            bytes(enc_data),
            bytes(nonce.bytes),
            bytes(self.keypair.public_key.bytes),
            sigma_auth
        )

    def _decode_and_decrypt_data(self, data: bytes) -> bytes:
        dec_data, nonceB, _ = message_to_datanoncepubkey(data)
        cipher = chily.Cipher(
            self.keypair.secret, self._get_enclave_pubkey()
        )
        return cipher.decrypt("client received session data", dec_data, chily.Nonce.from_bytes(nonceB))

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
        gcg_protocol = serialize_length_delimited(
            ComputeNodeProtocol(
                version=protocol
            )
        )
        serialized_request = serialize_length_delimited(
            Request(
                deltaRequest= self._encrypt_and_encode_data(
                    gcg_protocol + serialize_length_delimited(request),
                    self.auth
                )
            )
        )
        url = Endpoints.SESSION_MESSAGES.replace(":sessionId", self.session_id)
        enclave_request = EnclaveMessage(data=b64encode(serialized_request).decode("ascii"))
        enclave_response: bytes = self.client._api.post(
            url, json.dumps(enclave_request), {"Content-type": "application/json", "Accept-Version": "2"}
        ).content

        responses: List[GcgResponse] = []
        offset = 0
        while offset < len(enclave_response):
            response_container = Response()
            offset += parse_length_delimited(enclave_response[offset:], response_container)
            if response_container.HasField("unsuccessfulResponse"):
                raise Exception(response_container.unsuccessfulResponse)
            else:
                response = GcgResponse()
                decrypted_response = self._decode_and_decrypt_data(
                    response_container.successfulResponse
                )
                response_protocol = ComputeNodeProtocol()
                response_offset = parse_length_delimited(
                        decrypted_response, response_protocol
                )
                if response_protocol.version != protocol:
                    raise Exception("Different response protocol version than requested")
                parse_length_delimited(decrypted_response[response_offset:], response)
                if response.HasField("failure"):
                    raise Exception(response.failure)
                responses.append(response)
        return responses

    def _publish_data_room(
            self,
            data_room_definition: Tuple[DataRoom, List[ConfigurationModification]],
    ) -> CreateDataRoomResponse:
        endpoint_protocols = [1]
        protocol = self._get_client_protocol(endpoint_protocols)
        data_room, conf_modifications = data_room_definition
        if not data_room.ownerEmail:
            data_room.ownerEmail = self.email
        request = CreateDataRoomRequest(
            dataRoom=data_room,
            initialConfiguration=conf_modifications,
        )
        responses = self.send_request(GcgRequest(createDataRoomRequest=request), protocol)
        if len(responses) != 1:
            raise Exception("Malformed response")

        response = responses[0]

        if response.HasField("createDataRoomResponse"):
            if response.createDataRoomResponse.HasField("dataRoomValidationError"):
                raise Exception(
                    "Error when validating data room: {} (compute node id '{}')".format(
                        response.createDataRoomResponse.dataRoomValidationError.message,
                        response.createDataRoomResponse.dataRoomValidationError.computeNodeId
                    )
                )
            else:
                if self.is_integrated_with_platform:
                    data_room_hash = response.createDataRoomResponse.dataRoomId
                    self._create_data_room_in_platform(data_room_definition, data_room_hash)
        else:
            raise Exception(
                "Expected createDataRoomResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )

        return response.createDataRoomResponse

    def publish_data_room(
            self,
            data_room_definition: Tuple[DataRoom, List[ConfigurationModification]]
    ) -> str:
        """
        Create a data room with the provided protobuf configuration object
        and have the enclave apply the given list of modifications to the data
        room configuration.

        The id returned from this method will be used when interacting with the
        published data room (for example when running computations or publishing
        datasets).
        """
        response = self._publish_data_room(data_room_definition)
        return _get_data_room_id(response).hex()

    def publish_data_room_configuration_commit(
            self,
            configuration_commit: ConfigurationCommit
    ) -> str:
        """
        Publish the given data room configuration commit.

        Configuration commits can be built using a `DataRoomCommitBuilder` object.

        The id returned from this method will be used when running development
        computations or when trying to merge this commit into the main
        data room configuration.
        """
        endpoint_protocols = [1]
        protocol = self._get_client_protocol(endpoint_protocols)
        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_INTERMEDIATE_DATA,
                "data_room_id": configuration_commit.dataRoomId.hex(),
            }
        )
        request = CreateConfigurationCommitRequest(
            commit=configuration_commit,
            scope=bytes.fromhex(scope_id)
        )
        responses = self.send_request(
            GcgRequest(createConfigurationCommitRequest=request),
            protocol
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
    ) -> ConfigurationCommit:
        """
        Retrieve the content of given configuration commit id.

        **Returns**:
        A `ConfigurationCommit`.
        """
        endpoint_protocols = [1]
        protocol = self._get_client_protocol(endpoint_protocols)
        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_COMMITS_DATA,
            }
        )
        request = RetrieveConfigurationCommitRequest(
            commitId=bytes.fromhex(configuration_commit_id),
            scope=bytes.fromhex(scope_id),
        )
        responses = self.send_request(
            GcgRequest(retrieveConfigurationCommitRequest=request),
            protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")

        response = responses[0]
        if not response.HasField("retrieveConfigurationCommitResponse"):
            raise Exception(
                "Expected retrieveConfigurationCommitResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )

        return response.retrieveConfigurationCommitResponse.commit

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
        endpoint_protocols = [1]
        protocol = self._get_client_protocol(endpoint_protocols)
        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_COMMITS_DATA,
            }
        )
        request = RetrieveConfigurationCommitApproversRequest(
            commitId=bytes.fromhex(configuration_commit_id),
            scope=bytes.fromhex(scope_id),
        )
        responses = self.send_request(
            GcgRequest(retrieveConfigurationCommitApproversRequest=request),
            protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")

        response = responses[0]
        if not response.HasField("retrieveConfigurationCommitApproversResponse"):
            raise Exception(
                "Expected retrieveConfigurationCommitApproversResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )

        return response.retrieveConfigurationCommitApproversResponse.approvers


    def generate_merge_approval_signature(
            self,
            configuration_commit_id: str
    ) -> bytes:
        """
        Generate an approval signature required for merging a configuration
        commit.

        To merge a specific configuration commit, each user referenced in the list
        of ids returned by `retrieveConfigurationCommitApprovers` needs to
        generate an approval signature using this method.
        """
        endpoint_protocols = [1]
        protocol = self._get_client_protocol(endpoint_protocols)
        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_COMMITS_DATA,
            }
        )
        request = GenerateMergeApprovalSignatureRequest(
            commitId=bytes.fromhex(configuration_commit_id),
            scope=bytes.fromhex(scope_id),
        )
        responses = self.send_request(
            GcgRequest(generateMergeApprovalSignatureRequest=request),
            protocol
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
        endpoint_protocols = [1]
        protocol = self._get_client_protocol(endpoint_protocols)
        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_COMMITS_DATA,
            }
        )
        request = MergeConfigurationCommitRequest(
            scope=bytes.fromhex(scope_id),
            commitId=bytes.fromhex(configuration_commit_id),
            approvalSignatures=approval_signatures,
        )
        responses = self.send_request(
            GcgRequest(mergeConfigurationCommitRequest=request),
            protocol
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

    def retrieve_data_room_configuration_history(
        self,
        data_room_id: str
    ) -> RetrieveDataRoomConfigurationHistoryResponse:
        """
        Retrieve the current merged data room configuration, as well as the
        history of configuration commits that have already been merged.
        """
        endpoint_protocols = [1]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = RetrieveDataRoomConfigurationHistoryRequest(
            dataRoomId=bytes.fromhex(data_room_id),
        )
        responses = self.send_request(
            GcgRequest(retrieveDataRoomConfigurationHistoryRequest=request),
            protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")
        response = responses[0]
        if not response.HasField("retrieveDataRoomConfigurationHistoryResponse"):
            raise Exception(
                "Expected retrieveDataRoomConfigurationHistoryResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )

        return response.retrieveDataRoomConfigurationHistoryResponse

    def retrieve_current_data_room_configuration(
            self,
            data_room_id: str
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
        response = self.retrieve_data_room_configuration_history(data_room_id)
        return (response.currentConfiguration, response.pin.hex())

    def stop_data_room(self, data_room_id: str):
        """
        Stop the data room with the given id, making it impossible to run new
        computations.
        """
        self._update_data_room_status(data_room_id, DataRoomStatus.Value("Stopped"))

    def _update_data_room_status(
            self,
            data_room_id: str,
            status # type: DataRoomStatus.V
    ) -> UpdateDataRoomStatusResponse:
        """
        Update the status of the data room.

        For the special case of stopping a data room, the method
        `stop_data_room` can be used.
        """
        endpoint_protocols = [0, 1]
        protocol = self._get_client_protocol(endpoint_protocols)
        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_INTERMEDIATE_DATA,
                "data_room_id": data_room_id,
            }
        )
        request = UpdateDataRoomStatusRequest(
            scope=bytes.fromhex(scope_id),
            dataRoomId=bytes.fromhex(data_room_id),
            status=status,
        )
        responses = self.send_request(
            GcgRequest(updateDataRoomStatusRequest=request),
            protocol
        )

        if len(responses) != 1:
            raise Exception("Malformed response")

        response = responses[0]
        if response.HasField("updateDataRoomStatusResponse"):
            if self.is_integrated_with_platform:
                self.platform._platform_api.update_data_room_status(data_room_id, status)
        else:
            raise Exception(
                "Expected updateDataRoomStatusResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )

        return response.updateDataRoomStatusResponse

    def retrieve_data_room_status(
            self,
            data_room_id: str
    ) -> str:
        """
        Returns the status of the data room. Valid values are `"Active"` or `"Stopped"`.
        """
        endpoint_protocols = [0, 1]
        protocol = self._get_client_protocol(endpoint_protocols)
        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_INTERMEDIATE_DATA,
                "data_room_id": data_room_id,
            }
        )
        request = RetrieveDataRoomStatusRequest(
            scope=bytes.fromhex(scope_id),
            dataRoomId=bytes.fromhex(data_room_id),
        )
        responses = self.send_request(
            GcgRequest(retrieveDataRoomStatusRequest=request),
            protocol
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

    def retrieve_data_room_definition(
            self,
            data_room_id: str
    ) -> RetrieveDataRoomResponse:
        """
        Returns the underlying protobuf object for the data room.
        """
        endpoint_protocols = [1]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = RetrieveDataRoomRequest(
            dataRoomId=bytes.fromhex(data_room_id),
        )
        responses = self.send_request(
            GcgRequest(retrieveDataRoomRequest=request),
            protocol
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

    def retrieve_audit_log(
            self,
            data_room_id: str
    ) -> RetrieveAuditLogResponse:
        """
        Returns the audit log for the data room.
        """
        endpoint_protocols = [0, 1]
        protocol = self._get_client_protocol(endpoint_protocols)
        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_INTERMEDIATE_DATA,
                "data_room_id": data_room_id,
            }
        )
        request = RetrieveAuditLogRequest(
            scope=bytes.fromhex(scope_id),
            dataRoomId=bytes.fromhex(data_room_id),
        )
        responses = self.send_request(
            GcgRequest(retrieveAuditLogRequest=request),
            protocol
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

    def publish_dataset(
            self,
            data_room_id: str,
            manifest_hash: str,
            leaf_id: str,
            key: Key,
            *,
            force: bool = False
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
        """

        endpoint_protocols = [0, 1]
        protocol = self._get_client_protocol(endpoint_protocols)
        dataset = self.client.get_dataset(manifest_hash)
        if not dataset and not force:
            raise Exception(
                "The dataset you are trying to publish does not exist"
            )

        should_create_dataset_links =\
            self.is_integrated_with_platform and \
            self._is_web_data_room(data_room_id)

        if should_create_dataset_links:
            existing_link = self.platform._platform_api.get_dataset_link(
                data_room_id,
                self._convert_data_node_name_to_verifier_node(leaf_id)
            )
            if existing_link:
                existing_dataset = existing_link["dataset"]["datasetId"]
                raise Exception(
                    "The following dataset has already been published for this node." +
                    " Please unpublish this dataset first." +
                    f" Dataset: '{existing_dataset}'"
                )

        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_INTERMEDIATE_DATA,
                "data_room_id": data_room_id,
            }
        )
        request = PublishDatasetToDataRoomRequest(
            dataRoomId=bytes.fromhex(data_room_id),
            datasetHash=bytes.fromhex(manifest_hash),
            leafName=leaf_id,
            encryptionKey=key.material,
            scope=bytes.fromhex(scope_id)
        )
        responses = self.send_request(
            GcgRequest(publishDatasetToDataRoomRequest=request),
            protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")
        response = responses[0]
        if not response.HasField("publishDatasetToDataRoomResponse"):
            raise Exception(
                "Expected publishDatasetToDataRoomResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )
        else:
            if should_create_dataset_links:
                self.platform._platform_api.create_dataset_link(
                    data_room_id,
                    manifest_hash,
                    self._convert_data_node_name_to_verifier_node(leaf_id)
                )

        return response.publishDatasetToDataRoomResponse

    def _convert_data_node_name_to_verifier_node(self, node_name: str) -> str:
        pattern = re.compile(r"@table/(.*)/dataset")
        match = pattern.match(node_name)
        if match:
            return match.group(1)
        else:
            return node_name

    def remove_published_dataset(
            self,
            data_room_id: str,
            leaf_id: str,
    ) -> RemovePublishedDatasetResponse:
        """
        Removes a published dataset from the data room.
        """
        endpoint_protocols = [0, 1]
        protocol = self._get_client_protocol(endpoint_protocols)
        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_INTERMEDIATE_DATA,
                "data_room_id": data_room_id,
            }
        )
        request = RemovePublishedDatasetRequest(
            scope=bytes.fromhex(scope_id),
            dataRoomId=bytes.fromhex(data_room_id),
            leafName=leaf_id,
        )
        responses = self.send_request(
            GcgRequest(removePublishedDatasetRequest=request),
            protocol
        )
        if len(responses) != 1:
            raise Exception("Malformed response")
        response = responses[0]
        if not response.HasField("removePublishedDatasetResponse"):
            raise Exception(
                "Expected removePublishedDatasetResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )
        else:
            if self.is_integrated_with_platform and self._is_web_data_room(data_room_id):
                try:
                    self.platform._platform_api.delete_dataset_link(
                        data_room_id,
                        self._convert_data_node_name_to_verifier_node(leaf_id)
                    )
                except Exception as error:
                    print(f"Error when deleting dataset link on platform: {error}")

        return response.removePublishedDatasetResponse

    def retrieve_published_datasets(
            self,
            data_room_id: str,
    ) -> RetrievePublishedDatasetsResponse:
        """
        Returns the datasets published to the given data room.
        """
        endpoint_protocols = [0, 1]
        protocol = self._get_client_protocol(endpoint_protocols)
        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_INTERMEDIATE_DATA,
                "data_room_id": data_room_id,
            }
        )
        request = RetrievePublishedDatasetsRequest(
            scope=bytes.fromhex(scope_id),
            dataRoomId=bytes.fromhex(data_room_id),
        )
        responses = self.send_request(
            GcgRequest(retrievePublishedDatasetsRequest=request),
            protocol
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
            configuration_commit_id: str,
            compute_node_ids: List[str],
            /, *,
            dry_run: bool = False,
    ) -> ExecuteComputeResponse:
        """
        Submits a computation request which will generate an execution plan to
        perform the computation of the goal nodes
        """
        endpoint_protocols = [1]
        protocol = self._get_client_protocol(endpoint_protocols)
        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_COMMITS_DATA,
            }
        )
        request = ExecuteDevelopmentComputeRequest(
            configurationCommitId=bytes.fromhex(configuration_commit_id),
            computeNodeNames=compute_node_ids,
            isDryRun=dry_run,
            scope=bytes.fromhex(scope_id)
        )
        responses = self.send_request(
            GcgRequest(executeDevelopmentComputeRequest=request),
            protocol
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
            /, *,
            dry_run: bool = False,
    ) -> ExecuteComputeResponse:
        """
        Submits a computation request which will generate an execution plan to
        perform the computation of the goal nodes
        """
        endpoint_protocols = [0, 1]
        protocol = self._get_client_protocol(endpoint_protocols)
        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_INTERMEDIATE_DATA,
                "data_room_id": data_room_id,
            }
        )
        request = ExecuteComputeRequest(
            dataRoomId=bytes.fromhex(data_room_id),
            computeNodeNames=compute_node_ids,
            isDryRun=dry_run,
            scope=bytes.fromhex(scope_id)
        )
        responses = self.send_request(
            GcgRequest(executeComputeRequest=request),
            protocol
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
        endpoint_protocols = [0, 1]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = JobStatusRequest(
            jobId=bytes.fromhex(job_id),
        )
        responses = self.send_request(
            GcgRequest(jobStatusRequest=request),
            protocol
        )
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
        endpoint_protocols = [0, 1]
        protocol = self._get_client_protocol(endpoint_protocols)
        request = GetResultsRequest(
            jobId=job_id,
            computeNodeName=compute_node_id,
        )
        responses = self.send_request(
            GcgRequest(getResultsRequest=request),
            protocol
        )
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
        return b"".join(list(map(lambda chunk: chunk.data, self._stream_job_results(job_id, compute_node_id))))

    def run_computation(
            self,
            data_room_id: str,
            compute_node_id: str,
            /, *,
            dry_run: bool = False,
    ) -> JobId:
        """
        Run a specific computation within the data room with the given id.

        The result will be an identifier object of the job executing the computation.
        This object is required for checking a job's status and retrieving its results.
        """
        response = self._submit_compute(data_room_id, [compute_node_id], dry_run=dry_run)
        return JobId(response.jobId.hex(), compute_node_id)

    def wait_until_computation_has_finished(
        self,
        job_id: JobId,
        /, *,
        interval: int = 5,
        timeout: int = None
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
            elif job_id.compute_node_id in self.get_computation_status(job_id.id).completeComputeNodeNames:
                break
            else:
                sleep(interval)
                elapsed += interval

    def run_dev_computation(
            self,
            configuration_commit_id: str,
            compute_node_id: str,
            /, *,
            dry_run: bool = False,
    ) -> JobId:
        """
        Run a specific computation within the context of the data room configuration
        defined by the given commit id.
        Such "development" computations can also be run for configuration commits
        that have not yet been merged.

        The result will be an identifier object of the job executing the computation.
        This object is required for checking a job's status and retrieving its results.
        """
        response = self._submit_dev_compute(configuration_commit_id, [compute_node_id], dry_run=dry_run)
        return JobId(response.jobId.hex(), compute_node_id)

    def get_computation_result(
            self,
            job_id: JobId,
            /, *,
            interval: int = 5,
            timeout: int = None
    ) -> bytes:
        """
        Wait for the given job to complete and retrieve its results as a raw byte string.

        The method will check for the job's completeness every `interval` seconds and up to
        an optional `timeout` seconds after which the method will raise an exception.
        If the job completes and the results can be retrieved successfully, a raw byte string
        will be returned. The bytes tring can be transformed into a more useful object using
        a variety of helper methods. These helper methods are specific for the type of computation
        you ran and can be found in the corresponding packages.
        """
        elapsed = 0
        job_id_bytes = bytes.fromhex(job_id.id)
        self.wait_until_computation_has_finished(
            job_id,
            interval=interval,
            timeout=timeout
        )
        results = self._get_job_results(job_id_bytes, job_id.compute_node_id)
        return results

    def run_computation_and_get_results(
            self,
            data_room_id: str,
            compute_node_id: str,
            /, *,
            interval: int = 5,
            timeout: int = None
    ) -> Optional[bytes]:
        """
        Run a specific computation and return its results.

        This method is simply a wrapper for running `run_computation` and `get_computation_result`
        directly after each other
        """
        job_id = self.run_computation(data_room_id, compute_node_id)
        return self.get_computation_result(
            job_id,
            interval=interval,
            timeout=timeout
        )

    def _create_data_room_in_platform(
            self,
            data_room_definition: DataRoom,
            data_room_hash: bytes
    ):
        attestation_spec_type =\
                self.driver_attestation_specification.WhichOneof("attestation_specification")

        if attestation_spec_type == "intelEpid":
            mrenclave = self.driver_attestation_specification.intelEpid.mrenclave
        elif attestation_spec_type == "intelDcap":
            mrenclave = self.driver_attestation_specification.intelDcap.mrenclave
        else:
            raise Exception("Unknown attestation specification type")

        attestation_specification_hash = hashlib.sha256(
            serialize_length_delimited(
                self.driver_attestation_specification
            )
        ).hexdigest()

        self.platform._platform_api.publish_data_room(
            data_room_definition,
            data_room_hash=data_room_hash.hex(),
            attestation_specification_hash=attestation_specification_hash
        )

    def _is_web_data_room(self, data_room_id: str) -> bool:
        data_room = self.platform._platform_api.get_data_room_by_hash(data_room_id)
        if data_room:
            return data_room["source"] == "WEB"
        else:
            raise Exception(f"Unable to find data room with id '{data_room_id}'")

    @property
    def platform(self) -> SessionPlatformFeatures:
        """
        Provider of a list of convenience methods to interact with the
        Decentriq platform.

        This field exposes an object that provides a set of convenience features
        known from the Decentriq web platform. These include, for example,
        getting the list of data sets that are also visible in the browser-based
        platform UI.
        """
        if self._platform:
            return self._platform
        else:
            raise Exception(
                "This field is not set as the client from wich this session has"
                " been derived has not been configured with integration to the web"
                " platform."
            )

    @property
    def is_integrated_with_platform(self):
        return self._platform is not None
