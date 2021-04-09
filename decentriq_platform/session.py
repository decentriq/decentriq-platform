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
from .proto.waterfront_pb2 import WaterfrontRequest, WaterfrontResponse
from .proto.length_delimited import parse_length_delimited, serialize_length_delimited
from .verification import QuoteBody, Verification
from .api import Endpoints
from .storage import Key
from .authentication import Auth, Sigma
from typing import TYPE_CHECKING
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
            auth: Auth,
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
    def make_sql_query(self, data_room_hash: bytes, query_name: str, polling_options: PollingOptions) -> List[List[str]]: ...
    def make_sql_query(self, data_room_hash: bytes, query_name: str, polling_options: Optional[PollingOptions] = None) -> Union[List[List[str]], None]:
        req = WaterfrontRequest()
        req.sqlQueryRequest.queryName = query_name
        req.sqlQueryRequest.dataRoomHash = data_room_hash
        if polling_options is None:
            return self._get_query_results(req)
        else:
            while True:
                results = self._get_query_results(req)
                if results is not None:
                    return results
                time.sleep(polling_options.interval/1000)

    def _get_query_results(self, request: WaterfrontRequest) -> Union[List[List[str]], None]:
        response = self._send_and_parse_message(request)
        if not response.HasField("sqlQueryResponse"):
            raise Exception(
                "Expected inference response, got "
                + response.WhichOneof("waterfront_response")
            )
        if response.sqlQueryResponse.HasField("data") and response.sqlQueryResponse.data != None:
            response_content = response.sqlQueryResponse.data.decode('utf-8')
            return list(csv.reader(io.StringIO(response_content)))
        else: 
            return None

    def create_data_room(self, data_room: DataRoom) -> bytes:
        req = WaterfrontRequest()
        req.createDataRoomRequest.dataRoom.CopyFrom(data_room)
        response = self._send_and_parse_message(req)
        if not response.HasField("createDataRoomResponse"):
            raise Exception(
                "Expected createDataRoomResponse, got "
                + response.WhichOneof("waterfront_response")
            )
        return response.createDataRoomResponse.dataRoomHash

    def retrieve_data_room(self, data_room_hash: bytes) -> DataRoom:
        req = WaterfrontRequest()
        req.retrieveDataRoomRequest.dataRoomHash = data_room_hash
        response = self._send_and_parse_message(req)
        if not response.HasField("retrieveDataRoomResponse"):
            raise Exception(
                "Expected retrieveDataRoomResponse, got "
                + response.WhichOneof("waterfront_response")
            )
        return response.retrieveDataRoomResponse.dataRoom

    def publish_dataset_to_data_room(
            self,
            manifest_hash: bytes,
            data_room_hash: bytes,
            data_room_table_name: str,
            key: Key
    ):
        req = WaterfrontRequest()
        req.publishDatasetToDataRoomRequest.manifestHash = manifest_hash
        req.publishDatasetToDataRoomRequest.dataRoomHash = data_room_hash
        req.publishDatasetToDataRoomRequest.dataRoomTableName = data_room_table_name
        req.publishDatasetToDataRoomRequest.encryptionKey.material = key.material
        req.publishDatasetToDataRoomRequest.encryptionKey.salt = key.salt
        response = self._send_and_parse_message(req)
        if not response.HasField("publishDatasetToDataRoomResponse"):
            raise Exception(
                "Expected publishDatasetToDataRoomResponse, got "
                + response.WhichOneof("waterfront_response")
            )

    def _get_enclave_pubkey(self):
        pub_keyB = bytearray(self.quote.reportdata[:32])
        return chily.PublicKey.from_bytes(pub_keyB)

    def _encrypt_and_encode_data(self, data: bytes) -> bytes:
        nonce = chily.Nonce.from_random()
        cipher = chily.Cipher(
            self.keypair.secret, self._get_enclave_pubkey()
        )
        enc_data = cipher.encrypt(data, nonce)
        public_keys = bytes(self.keypair.public_key.bytes) + bytes(self._get_enclave_pubkey().bytes)
        signature = self.auth.sign(public_keys)
        shared_key = bytes(self.keypair.secret.diffie_hellman(self._get_enclave_pubkey()).bytes)
        hkdf = HKDF(algorithm=hashes.SHA512(), length=64, info=b"IdP KDF Context", salt=b"")
        mac_key = hkdf.derive(shared_key)
        mac_tag = hmac.digest(mac_key, self.auth.get_user_id().encode(), "sha512")
        sigma_auth = Sigma(signature, mac_tag, self.auth)
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

    def _send_and_parse_message(self, message: WaterfrontRequest) -> WaterfrontResponse:
        waterfront_response = WaterfrontResponse()
        self._send_message(message, waterfront_response)
        if waterfront_response.HasField("failure"):
            raise Exception(waterfront_response.failure)
        return waterfront_response

    def _send_message(self, message: Message, response_object: Message):
        encrypted = self._encrypt_and_encode_data(serialize_length_delimited(message))
        request = Request()
        request.avatoRequest = encrypted
        url = Endpoints.SESSION_MESSAGES.replace(":sessionId", self.session_id)
        serialized_request = serialize_length_delimited(request)
        enclave_message = B64EncodedMessage(data=b64encode(serialized_request).decode("ascii"))
        
        enclave_response: B64EncodedMessage = self.client.api.post(
            url, json.dumps(enclave_message), {"Content-type": "application/json"}
        ).json()
        enclave_response_bytes  = b64decode(enclave_response["data"])
        response_container = Response()
        parse_length_delimited(enclave_response_bytes, response_container)
        if response_container.HasField("unsuccessfulResponse"):
            raise Exception(response_container.unsuccessfulResponse)
        decrypted_response = self._decode_and_decrypt_data(response_container.successfulResponse)
        parse_length_delimited(decrypted_response, response_object)
