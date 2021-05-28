from __future__ import annotations
import chily
import json
import csv
import io
import time
from google.protobuf.message import Message
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import hmac
from typing_extensions import TypedDict
from typing import Optional, Union, Tuple, List, overload, TYPE_CHECKING
from dataclasses import dataclass
from base64 import b64encode, b64decode
from .proto.data_room_pb2 import DataRoom
from .proto.avato_enclave_pb2 import Request, Response, DataNoncePubkey
from .proto.waterfront_pb2 import WaterfrontRequest, WaterfrontResponse, CreateDataRoomResponse, DataRoomStatus
from .proto.length_delimited import parse_length_delimited, serialize_length_delimited
from .verification import QuoteBody, Verification
from .api import Endpoints
from .storage import Key
from .authentication import Auth, Sigma
from typing import TYPE_CHECKING, Dict
if TYPE_CHECKING:
    from .client import Client


def datanoncepubkey_to_message(encrypted_data: bytes, nonce: bytes, pubkey: bytes, sigma_auth: Sigma) -> bytes:
    message = DataNoncePubkey()
    message.data = encrypted_data
    message.nonce = nonce
    message.pubkey = pubkey
    message.auth.pki.certChain = sigma_auth.get_cert_chain()
    message.auth.pki.signature = sigma_auth.get_signature()
    message.auth.pki.idMac = sigma_auth.get_mac_tag()
    return serialize_length_delimited(message)

def message_to_datanoncepubkey(message: bytes) -> Tuple[bytes, bytes, bytes]:
    parsed_msg = DataNoncePubkey()
    parse_length_delimited(message, parsed_msg)
    return (parsed_msg.data, parsed_msg.nonce, parsed_msg.pubkey)


@dataclass
class Fatquote():
    signature: bytes
    certificate: bytes
    message: bytes

@dataclass
class VerificationOptions():
    accept_debug: bool
    accept_configuration_needed: bool
    accept_group_out_of_date: bool

@dataclass
class SessionOptions():
    verification_options: VerificationOptions

@dataclass
class PollingOptions():
    interval: int

class SignatureResponse(TypedDict):
    type: str
    data: List[int]

class B64EncodedMessage(TypedDict):
    data: str

class FatquoteResBody(TypedDict):
    signature: SignatureResponse
    response: str
    certificate: str

class Session():
    def __init__(
            self,
            client: Client,
            session_id: str,
            enclave_identifier: str,
            auth: Dict[str, Auth],
            options: SessionOptions
    ):
        url = Endpoints.SESSION_FATQUOTE.replace(":sessionId", session_id)
        response: FatquoteResBody = client.api.get(url).json()
        certificate = response["certificate"].encode("utf-8")
        message = response["response"].encode("utf-8")
        signature = bytes(response["signature"]["data"])
        fatquote = Fatquote(signature, certificate, message)
        verification_options = options.verification_options
        verification = Verification(
            expected_measurement=enclave_identifier,
            accept_debug=verification_options.accept_debug,
            accept_configuration_needed=verification_options.accept_configuration_needed,
            accept_group_out_of_date=verification_options.accept_group_out_of_date,
        )
        quote = verification.verify(certificate, message, signature)
        self.client = client
        self.session_id: str = session_id
        self.enclave_identifier: str = enclave_identifier
        self.auth: Auth = auth
        self.keypair = chily.Keypair.from_random()
        self.fatquote: Fatquote = fatquote
        self.quote: QuoteBody = quote

    @overload
    def make_sql_query(self, data_room_hash: bytes, query_name: str) -> Union[List[List[str]], None]: ...
    @overload
    def make_sql_query(self, data_room_hash: bytes, query_name: str, polling_options: PollingOptions, role: str = None) -> List[List[str]]: ...
    def make_sql_query(self, data_room_hash: bytes, query_name: str, polling_options: Optional[PollingOptions] = None, role: str = None) -> Union[List[List[str]], None]:
        req = WaterfrontRequest()
        req.sqlQueryRequest.queryName = query_name
        req.sqlQueryRequest.dataRoomHash = data_room_hash

        role_name, auth = self._get_auth_for_role(role)
        req.sqlQueryRequest.auth.role = role_name
        if auth.get_access_token() is not None:
            req.sqlQueryRequest.auth.passwordSha256 = auth.get_access_token()

        if polling_options is None:
            return self._get_query_results(req, auth)
        else:
            while True:
                results = self._get_query_results(req, auth)
                if results is not None:
                    return results
                time.sleep(polling_options.interval/1000)

    def _get_query_results(self, request: WaterfrontRequest, auth: Auth) -> Union[List[List[str]], None]:
        responses = self._send_message_many_responses(request, auth)
        if len(responses) == 1 and not responses[0].sqlQueryResponse.HasField("data"):
            return None
        contents = []
        for response in responses:
            if not response.HasField("sqlQueryResponse"):
                raise Exception("Expected inference response, got " + response.WhichOneof("waterfront_response"))
            if response.sqlQueryResponse.HasField("data") and response.sqlQueryResponse.data != None:
                contents.append(response.sqlQueryResponse.data)
            else:
                return None
        full_csv = b''.join(contents).decode('utf-8')
        return list(csv.reader(io.StringIO(full_csv)))

    def create_data_room(self, data_room: DataRoom, role: str = None) -> CreateDataRoomResponse:
        req = WaterfrontRequest()
        req.createDataRoomRequest.dataRoom.CopyFrom(data_room)

        _, auth = self._get_auth_for_role(role)
        response = self._send_and_parse_message(req, auth)
        if not response.HasField("createDataRoomResponse"):
            raise Exception(
                "Expected createDataRoomResponse, got "
                + response.WhichOneof("waterfront_response")
            )
        return response.createDataRoomResponse

    def retrieve_data_room(self, data_room_hash: bytes, role: str = None) -> DataRoom:
        req = WaterfrontRequest()
        req.retrieveDataRoomRequest.dataRoomHash = data_room_hash

        role_name, auth = self._get_auth_for_role(role)
        req.retrieveDataRoomRequest.auth.role = role_name
        if auth.get_access_token() is not None:
            req.retrieveDataRoomRequest.auth.passwordSha256 = auth.get_access_token()

        response = self._send_and_parse_message(req, auth)
        if not response.HasField("retrieveDataRoomResponse"):
            raise Exception(
                "Expected retrieveDataRoomResponse, got "
                + response.WhichOneof("waterfront_response")
            )
        return response.retrieveDataRoomResponse.dataRoom

    def retrieve_audit_log(self, data_room_hash: bytes, role: str = None) -> str:
        req = WaterfrontRequest()
        req.retrieveAuditLogRequest.dataRoomHash = data_room_hash

        role_name, auth = self._get_auth_for_role(role)
        req.retrieveAuditLogRequest.auth.role = role_name
        if auth.get_access_token() is not None:
            req.retrieveAuditLogRequest.auth.passwordSha256 = auth.get_access_token()

        response = self._send_and_parse_message(req, auth)
        if not response.HasField("retrieveAuditLogResponse"):
            raise Exception(
                "Expected retrieveAuditLogResponse, got "
                + response.WhichOneof("waterfront_response")
            )
        return response.retrieveAuditLogResponse.data

    def publish_dataset_to_data_room(
            self,
            manifest_hash: bytes,
            data_room_hash: bytes,
            data_room_table_name: str,
            key: Key,
            role: str = None
    ):
        req = WaterfrontRequest()
        req.publishDatasetToDataRoomRequest.manifestHash = manifest_hash
        req.publishDatasetToDataRoomRequest.dataRoomHash = data_room_hash
        req.publishDatasetToDataRoomRequest.dataRoomTableName = data_room_table_name
        req.publishDatasetToDataRoomRequest.encryptionKey.material = key.material
        req.publishDatasetToDataRoomRequest.encryptionKey.salt = key.salt

        role_name, auth = self._get_auth_for_role(role)
        req.publishDatasetToDataRoomRequest.auth.role = role_name
        if auth.get_access_token() is not None:
            req.publishDatasetToDataRoomRequest.auth.passwordSha256 = auth.get_access_token()

        response = self._send_and_parse_message(req, auth)
        if not response.HasField("publishDatasetToDataRoomResponse"):
            raise Exception(
                "Expected publishDatasetToDataRoomResponse, got "
                + response.WhichOneof("waterfront_response")
            )

    def validate_dataset(
            self,
            manifest_hash: bytes,
            key: Key,
            role: str = None
    ):

        _, auth = self._get_auth_for_role(role)
        req = WaterfrontRequest()
        req.validateDatasetRequest.manifestHash = manifest_hash
        req.validateDatasetRequest.encryptionKey.material = key.material
        req.validateDatasetRequest.encryptionKey.salt = key.salt
        response = self._send_and_parse_message(req, auth)
        if not response.HasField("validateDatasetResponse"):
            raise Exception(
                "Expected validateDatasetResponse, got "
                + response.WhichOneof("waterfront_response")
            )
        return response.validateDatasetResponse

    def retrieve_data_room_status(
        self,
        data_room_hash: bytes,
        role: str = None
    ):
        role, auth = self._get_auth_for_role(role)
        req = WaterfrontRequest()
        req.retrieveDataRoomStatusRequest.dataRoomHash = data_room_hash
        req.retrieveDataRoomStatusRequest.auth.role = role
        if auth.get_access_token() is not None:
            req.retrieveDataRoomStatusRequest.auth.passwordSha256 = auth.get_access_token()
        response = self._send_and_parse_message(req, auth)
        if not response.HasField("retrieveDataRoomStatusResponse"):
            raise Exception(
                "Expected retrieveDataRoomStatusResponse, got "
                + response.WhichOneof("waterfront_response")
            )
        return response.retrieveDataRoomStatusResponse

    def update_data_room_status(
        self,
        data_room_hash: bytes,
        status: DataRoomStatus,
        role: str = None
    ):
        role, auth = self._get_auth_for_role(role)
        req = WaterfrontRequest()
        req.updateDataRoomStatusRequest.dataRoomHash = data_room_hash
        req.updateDataRoomStatusRequest.auth.role = role
        if auth.get_access_token() is not None:
            req.updateDataRoomStatusRequest.auth.passwordSha256 = auth.get_access_token()
        req.updateDataRoomStatusRequest.status = status
        response = self._send_and_parse_message(req, auth)
        if not response.HasField("updateDataRoomStatusResponse"):
            raise Exception(
                "Expected updateDataRoomStatusResponse, got "
                + response.WhichOneof("waterfront_response")
            )
        return response.updateDataRoomStatusResponse

    def _get_enclave_pubkey(self):
        pub_keyB = bytearray(self.quote.reportdata[:32])
        return chily.PublicKey.from_bytes(pub_keyB)

    def _encrypt_and_encode_data(self, data: bytes, auth: Auth) -> bytes:
        nonce = chily.Nonce.from_random()
        cipher = chily.Cipher(
            self.keypair.secret, self._get_enclave_pubkey()
        )
        enc_data = cipher.encrypt(data, nonce)
        public_keys = bytes(self.keypair.public_key.bytes) + bytes(self._get_enclave_pubkey().bytes)
        signature = auth.sign(public_keys)
        shared_key = bytes(self.keypair.secret.diffie_hellman(self._get_enclave_pubkey()).bytes)
        hkdf = HKDF(algorithm=hashes.SHA512(), length=64, info=b"IdP KDF Context", salt=b"")
        mac_key = hkdf.derive(shared_key)
        mac_tag = hmac.digest(mac_key, auth.get_user_id().encode(), "sha512")
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

    def _send_and_parse_message(self, message: WaterfrontRequest, auth: Auth) -> WaterfrontResponse:
        waterfront_response = WaterfrontResponse()
        self._send_message(message, waterfront_response, auth)
        if waterfront_response.HasField("failure"):
            raise Exception(waterfront_response.failure)
        return waterfront_response

    def _send_message(self, message: Message, response_object: WaterfrontResponse, auth: Auth):
        enclave_response_bytes = self._send_message_raw(message, auth)
        response_container = Response()
        parse_length_delimited(enclave_response_bytes, response_container)
        if response_container.HasField("unsuccessfulResponse"):
            raise Exception(response_container.unsuccessfulResponse)
        decrypted_response = self._decode_and_decrypt_data(response_container.successfulResponse)
        parse_length_delimited(decrypted_response, response_object)

    def _send_message_many_responses(self, message: Message, auth: Auth) -> List[WaterfrontResponse]:
        enclave_response_bytes = self._send_message_raw(message, auth)
        responses = []
        offset = 0
        while offset < len(enclave_response_bytes):
            response_container = Response()
            offset += parse_length_delimited(enclave_response_bytes[offset:], response_container)
            if response_container.HasField("unsuccessfulResponse"):
                raise Exception(response_container.unsuccessfulResponse)
            else:
                waterfront_response = WaterfrontResponse()
                decrypted_response = self._decode_and_decrypt_data(response_container.successfulResponse)
                parse_length_delimited(decrypted_response, waterfront_response)
                if waterfront_response.HasField("failure"):
                    raise Exception(waterfront_response.failure)
                responses.append(waterfront_response)
        return responses

    def _send_message_raw(self, message: Message, auth: Auth) -> bytes:
        encrypted = self._encrypt_and_encode_data(serialize_length_delimited(message), auth)
        request = Request()
        request.avatoRequest = encrypted
        url = Endpoints.SESSION_MESSAGES.replace(":sessionId", self.session_id)
        serialized_request = serialize_length_delimited(request)
        enclave_message = B64EncodedMessage(data=b64encode(serialized_request).decode("ascii"))

        enclave_response: B64EncodedMessage = self.client.api.post(
            url, json.dumps(enclave_message), {"Content-type": "application/json"}
        ).json()
        enclave_response_bytes  = b64decode(enclave_response["data"])
        return enclave_response_bytes

    def _get_auth_for_role(self, role: str = None) -> Tuple[str, Auth]:
        if len(self.auth) == 0:
            raise Exception("No auth objects")
        if role is None:
            if len(self.auth) > 1:
                raise Exception("No role specififed but multiple auths")
            else:
                return (list(self.auth.keys())[0], list(self.auth.values())[0])
        else:
            if self.auth.has_key(role):
                return (role, self.auth.get(role))
            else:
                raise Exception("No auth found for specififed role")
