from __future__ import annotations
import chily
import hmac
import json
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from typing import Any, List, Tuple, TYPE_CHECKING, Iterator, Optional
from time import sleep
from .api import Endpoints
from .authentication import Auth, Sigma
from .proto import DataRoom
from .proto import (DataNoncePubkey, Request, Response)
from .proto import (
    CreateDataRoomRequest, CreateDataRoomResponse,
    ExecuteComputeRequest, ExecuteComputeResponse, GcgRequest, GcgResponse, GetResultsRequest,
    GetResultsResponseChunk, JobStatusRequest, JobStatusResponse,
    PublishDatasetToDataRoomRequest, PublishDatasetToDataRoomResponse,
    RemovePublishedDatasetRequest, RemovePublishedDatasetResponse,
    RetrieveAuditLogRequest, RetrieveAuditLogResponse, RetrieveDataRoomRequest,
    RetrieveDataRoomResponse, RetrieveDataRoomStatusRequest,
    RetrieveDataRoomStatusResponse, RetrievePublishedDatasetsRequest,
    RetrievePublishedDatasetsResponse, UpdateDataRoomStatusRequest,
    UpdateDataRoomStatusResponse, DataRoomStatus, AttestationSpecification, Fatquote
)
from .proto.length_delimited import parse_length_delimited, serialize_length_delimited
from .storage import Key
from .types import FatquoteResBody, EnclaveMessage, ScopeTypes, JobId
from .verification import QuoteBody, Verification
from .helpers import get_data_room_id


if TYPE_CHECKING:
    from .client import Client


def datanoncepubkey_to_message(
        encrypted_data: bytes,
        nonce: bytes,
        pubkey: bytes,
        sigma_auth: Sigma
) -> bytes:
    message = DataNoncePubkey()
    message.data = encrypted_data
    message.nonce = nonce
    message.pubkey = pubkey
    message.pki.certChainPem = sigma_auth.get_cert_chain()
    message.pki.signature = sigma_auth.get_signature()
    message.pki.idMac = sigma_auth.get_mac_tag()
    return serialize_length_delimited(message)


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

    def __init__(
            self,
            client: Client,
            session_id: str,
            driver_attestation_specification: AttestationSpecification,
            auth: Auth,
            email: str
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
        self.email = email
        self.keypair = chily.Keypair.from_random()
        self.fatquote = fatquote
        self.report_data = report_data
        self.driver_attestation_specification = driver_attestation_specification

    def _get_enclave_pubkey(self):
        pub_keyB = bytearray(self.report_data[:32])
        return chily.PublicKey.from_bytes(pub_keyB)

    def _encrypt_and_encode_data(self, data: bytes, auth: Auth) -> bytes:
        nonce = chily.Nonce.from_random()
        cipher = chily.Cipher(
            self.keypair.secret, self._get_enclave_pubkey()
        )
        enc_data = cipher.encrypt(data, nonce)
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
        return cipher.decrypt(dec_data, chily.Nonce.from_bytes(nonceB))

    def send_request(
            self,
            request: GcgRequest,
    ) -> List[GcgResponse]:
        """
        Low-level method for sending a raw `GcgRequest` to the enclave.
        Use this method if any of the convenience methods (such as `run_computation`) don't perform
        the exact task you want.
        """
        serialized_request = serialize_length_delimited(
            Request(
                deltaRequest=self._encrypt_and_encode_data(
                    serialize_length_delimited(request),
                    self.auth
                )
            )
        )
        url = Endpoints.SESSION_MESSAGES.replace(":sessionId", self.session_id)
        enclave_request = EnclaveMessage(data=b64encode(serialized_request).decode("ascii"))
        enclave_response: EnclaveMessage = self.client._api.post(
            url, json.dumps(enclave_request), {"Content-type": "application/json"}
        ).json()
        enclave_response_bytes = b64decode(enclave_response["data"])

        responses: List[GcgResponse] = []
        offset = 0
        while offset < len(enclave_response_bytes):
            response_container = Response()
            offset += parse_length_delimited(enclave_response_bytes[offset:], response_container)
            if response_container.HasField("unsuccessfulResponse"):
                raise Exception(response_container.unsuccessfulResponse)
            else:
                response = GcgResponse()
                decrypted_response = self._decode_and_decrypt_data(
                    response_container.successfulResponse
                )
                parse_length_delimited(decrypted_response, response)
                if response.HasField("failure"):
                    raise Exception(response.failure)
                responses.append(response)
        return responses

    def _publish_data_room(
            self,
            data_room_definition: DataRoom
    ) -> CreateDataRoomResponse:
        """
        Create a DataRoom with the provided protobuf `data_room` configuration object
        """
        scope_id = self.client._ensure_scope_with_metadata(self.email, {"type": ScopeTypes.DATA_ROOM_DEFINITION})
        request = CreateDataRoomRequest(
            dataRoom=data_room_definition,
            scope=bytes.fromhex(scope_id)
        )
        responses = self.send_request(GcgRequest(createDataRoomRequest=request))
        if len(responses) != 1:
            raise Exception("Malformed response")

        response = responses[0]

        if response.HasField("createDataRoomResponse"):
            if response.createDataRoomResponse.HasField("dataRoomValidationError"):
                raise Exception(
                    "Error when validating data room: {} (compute node index {})".format(
                        response.createDataRoomResponse.dataRoomValidationError.message,
                        response.createDataRoomResponse.dataRoomValidationError.computeNodeIndex
                    )
                )
        else:
            raise Exception(
                "Expected createDataRoomResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )

        return response.createDataRoomResponse

    def publish_data_room(self, data_room_definition: DataRoom) -> str:
        """
        Publish the given data room making it immutable.

        The id returned from this method will be used when interacting with the
        published data room (for example when running computations or publishing datasets).
        """
        response = self._publish_data_room(data_room_definition)
        return get_data_room_id(response).hex()

    def stop_data_room(self, data_room_id: str):
        """
        Stop the data room with the given id, making it impossible to run new computations.
        """
        self._update_data_room_status(data_room_id, DataRoomStatus.Value("Stopped"))

    def _update_data_room_status(
            self,
            data_room_id: str,
            status # type: DataRoomStatus.V
    ) -> UpdateDataRoomStatusResponse:
        """
        Update the status of the data room.

        For the special case of stopping a data room, the method `stop_data_room` can be used.
        """
        data_room_id_bytes = bytes.fromhex(data_room_id)
        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_INTERMEDIATE_DATA,
                "data_room_id": data_room_id
            }
        )
        request = UpdateDataRoomStatusRequest(
            dataRoomId=data_room_id_bytes,
            status=status,
            scope=bytes.fromhex(scope_id)
        )
        responses = self.send_request(GcgRequest(updateDataRoomStatusRequest=request))

        if len(responses) != 1:
            raise Exception("Malformed response")

        response = responses[0]
        if response.HasField("updateDataRoomStatusResponse"):
            pass
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
        Returns the status of the DataRoom. Valid values are `"Active"` or `"Stopped"`.
        """
        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_INTERMEDIATE_DATA,
                "data_room_id": data_room_id,
            }
        )
        request = RetrieveDataRoomStatusRequest(
            dataRoomId=bytes.fromhex(data_room_id),
            scope=bytes.fromhex(scope_id)
        )
        responses = self.send_request(GcgRequest(retrieveDataRoomStatusRequest=request))
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
        Returns the underlying protobuf configuration object for the DataRoom
        """
        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_INTERMEDIATE_DATA,
                "data_room_id": data_room_id
            }
        )
        request = RetrieveDataRoomRequest(
            dataRoomId=bytes.fromhex(data_room_id),
            scope=bytes.fromhex(scope_id)
        )
        responses = self.send_request(GcgRequest(retrieveDataRoomRequest=request))
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
        Returns the audit log for the DataRoom
        """
        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_INTERMEDIATE_DATA,
                "data_room_id": data_room_id,
            }
        )
        request = RetrieveAuditLogRequest(
            dataRoomId=bytes.fromhex(data_room_id),
            scope=bytes.fromhex(scope_id)
        )
        responses = self.send_request(GcgRequest(retrieveAuditLogRequest=request))
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
            leaf_name: str,
            key: Key,
    ) -> PublishDatasetToDataRoomResponse:
        """
        Publishes a file to the DataRoom
        """
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
            leafName=leaf_name,
            encryptionKey=key.material,
            scope=bytes.fromhex(scope_id)
        )
        responses = self.send_request(GcgRequest(publishDatasetToDataRoomRequest=request))
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
            leaf_name: str,
    ) -> RemovePublishedDatasetResponse:
        """
        Removes a published file from the DataRoom
        """
        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_INTERMEDIATE_DATA,
                "data_room_id": data_room_id,
            }
        )
        request = RemovePublishedDatasetRequest(
            dataRoomId=bytes.fromhex(data_room_id),
            leafName=leaf_name,
            scope=bytes.fromhex(scope_id)
        )
        responses = self.send_request(GcgRequest(removePublishedDatasetRequest=request))
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
        Returns the files published to the DataRoom
        """
        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_INTERMEDIATE_DATA,
                "data_room_id": data_room_id,
            }
        )
        request = RetrievePublishedDatasetsRequest(
            dataRoomId=bytes.fromhex(data_room_id),
            scope=bytes.fromhex(scope_id)
        )
        responses = self.send_request(GcgRequest(retrievePublishedDatasetsRequest=request))
        if len(responses) != 1:
            raise Exception("Malformed response")
        response = responses[0]
        if not response.HasField("retrievePublishedDatasetsResponse"):
            raise Exception(
                "Expected retrievePublishedDatasetResponse, got "
                + str(response.WhichOneof("gcg_response"))
            )
        return response.retrievePublishedDatasetsResponse

    def _submit_compute(
            self,
            data_room_id: str,
            goal_nodes: List[str],
            /, *,
            dry_run: bool = False,
    ) -> ExecuteComputeResponse:
        """
        Submits a computation request which will generate an execution plan to
        perform the computation of the goal nodes
        """
        scope_id = self.client._ensure_scope_with_metadata(
            self.email,
            {
                "type": ScopeTypes.DATA_ROOM_INTERMEDIATE_DATA,
                "data_room_id": data_room_id,
            }
        )
        request = ExecuteComputeRequest(
            dataRoomId=bytes.fromhex(data_room_id),
            computeNodeNames=goal_nodes,
            isDryRun=dry_run,
            scope=bytes.fromhex(scope_id)
        )
        responses = self.send_request(GcgRequest(executeComputeRequest=request))
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
        request = JobStatusRequest(
            jobId=bytes.fromhex(job_id),
        )
        responses = self.send_request(GcgRequest(jobStatusRequest=request))
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
            compute_node_name: str,
    ) -> Iterator[GetResultsResponseChunk]:
        """
        Streams the results of the provided `job_id`
        """
        request = GetResultsRequest(
            jobId=job_id,
            computeNodeName=compute_node_name,
        )
        responses = self.send_request(GcgRequest(getResultsRequest=request))
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
            compute_node_name: str,
    ) -> bytes:
        """
        Returns the results of the provided `job_id`
        """
        return b"".join(list(map(lambda chunk: chunk.data, self._stream_job_results(job_id, compute_node_name))))

    def run_computation(
            self,
            data_room_id: str,
            compute_node_name: str,
            /, *,
            dry_run: bool = False,
    ) -> JobId:
        """
        Run a specific computation within the data room with the given id.

        The result will be an identifier object of the job executing the computation.
        This object is required for checking a job's status and retrieving its results.
        """
        response = self._submit_compute(data_room_id, [compute_node_name], dry_run=dry_run)
        return JobId(response.jobId.hex(), compute_node_name)

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
        while True:
            if timeout is not None and elapsed > timeout:
                raise Exception(
                    f"Timeout when trying to get result for job {job_id.id} of {job_id.compute_node_name} (waited {timeout} seconds)"
                )
            elif job_id.compute_node_name in self.get_computation_status(job_id.id).completeComputeNodeNames:
                results = self._get_job_results(job_id_bytes, job_id.compute_node_name)
                return results
            else:
                sleep(interval)
                elapsed += interval

    def run_computation_and_get_results(
            self,
            data_room_id: str,
            compute_node_name: str,
            /, *,
            interval: int = 5,
            timeout: int = None
    ) -> Optional[bytes]:
        """
        Run a specific computation and return its results.

        This method is simply a wrapper for running `run_computation` and `get_computation_result`
        directly after each other
        """
        job_id = self.run_computation(data_room_id, compute_node_name)
        return self.get_computation_result(
            job_id,
            interval=interval,
            timeout=timeout
        )
