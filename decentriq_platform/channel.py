import hashlib
import hmac
from base64 import b64decode
from typing_extensions import Self
from typing import Any, Callable, List, Tuple, TypeVar

import chily
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .api import Api, Endpoints
from .authentication import Auth, Sigma
from .graphql import GqlClient
from .proto.attestation_pb2 import AttestationSpecification, Fatquote
from .proto.data_room_pb2 import ComputeNodeProtocol
from .proto.delta_enclave_api_pb2 import DataNoncePubkey, Request, Response
from .proto.gcg_pb2 import GcgRequest, GcgResponse, Pki, UserAuth
from .proto.length_delimited import parse_length_delimited, serialize_length_delimited
from .verification import Verification
from .logger import logger


class EnclaveError(Exception):
    pass


CompilerRequest = TypeVar("CompilerRequest")
CompilerResponse = TypeVar("CompilerResponse")


def datanoncepubkey_to_message(
    encrypted_data: bytes,
    nonce: bytes,
    pubkey: bytes,
) -> DataNoncePubkey:
    message = DataNoncePubkey()
    message.data = encrypted_data
    message.nonce = nonce
    message.pubkey = pubkey
    return message


def message_to_datanoncepubkey(message: bytes) -> Tuple[bytes, bytes, bytes]:
    parsed_msg = DataNoncePubkey()
    parse_length_delimited(message, parsed_msg)
    return (parsed_msg.data, parsed_msg.nonce, parsed_msg.pubkey)


class Channel:
    """
    Class for managing the communication with an enclave.
    """

    session_id: str
    api: Api
    graphql_api: GqlClient
    enclave_public_key: Any
    driver_attestation_specification: AttestationSpecification
    driver_attestation_specification_hash: str

    def __init__(
        self,
        driver_attestation_specification: AttestationSpecification,
        api: Api,
        graphql_api: GqlClient,
        unsafe_disable_known_root_ca_check: bool = False,
    ):
        # Request a session with the enclave
        driver_attestation_specification_hash = hashlib.sha256(
            serialize_length_delimited(driver_attestation_specification)
        ).hexdigest()
        data = graphql_api.post(
            """
            mutation CreateSession($input: CreateSessionInput!) {
                session {
                    create(input: $input) {
                        record {
                            id
                        }
                    }
                }
            }
            """,
            {
                "input": {
                    "enclaveAttestationHash": driver_attestation_specification_hash,
                }
            },
        )
        session_id: str = data["session"]["create"]["record"]["id"]

        # Get fatquote from session and verify it
        data = graphql_api.post(
            """
            query GetFatquote($id: String!) {
                session(id: $id) {
                    fatquote
                }
            }
            """,
            {
                "id": session_id,
            },
        )
        encoded_fatquote: str = data["session"]["fatquote"]
        fatquote = Fatquote()
        fatquote_bytes_encoded = b64decode(encoded_fatquote)
        parse_length_delimited(fatquote_bytes_encoded, fatquote)
        verification = Verification(
            attestation_specification=driver_attestation_specification
        )
        if unsafe_disable_known_root_ca_check == True:
            logger.warning("WARNING: ROOT CHECK VERIFICATION DISABLED FOR CURRENT ENCLAVE SESSION")
            verification.disable_known_root_ca_check()

        # Extract enclave public key from report data
        report_data = verification.verify(fatquote)
        enclave_public_key_encoded = bytearray(report_data[:32])
        enclave_public_key = chily.PublicKey.from_bytes(enclave_public_key_encoded)

        self.api = api
        self.graphql_api = graphql_api
        self.session_id = session_id
        self.enclave_public_key = enclave_public_key
        self.driver_attestation_specification = driver_attestation_specification
        self.driver_attestation_specification_hash = (
            driver_attestation_specification_hash
        )

    def _encrypt_and_encode_data(self, data: bytes, auth: Auth) -> DataNoncePubkey:
        nonce = chily.Nonce.from_random()
        cipher = chily.Cipher(auth.keypair.secret, self.enclave_public_key)
        encrypted_data = cipher.encrypt("client sent session data", data, nonce)
        data_nonce_pubkey = datanoncepubkey_to_message(
            bytes(encrypted_data),
            bytes(nonce.bytes),
            bytes(auth.keypair.public_key.bytes),
        )
        return data_nonce_pubkey

    def _decode_and_decrypt_data(self, data: bytes, auth: Auth) -> bytes:
        decoded_data, data_nonce, _ = message_to_datanoncepubkey(data)
        cipher = chily.Cipher(auth.keypair.secret, self.enclave_public_key)
        return cipher.decrypt(
            "client received session data",
            decoded_data,
            chily.Nonce.from_bytes(data_nonce),
        )

    def _get_message_auth(self, auth: Auth) -> UserAuth:
        shared_key = bytes(
            auth.keypair.secret.diffie_hellman(self.enclave_public_key).bytes
        )
        hkdf = HKDF(
            algorithm=hashes.SHA512(), length=64, info=b"IdP KDF Context", salt=b""
        )
        mac_key = hkdf.derive(shared_key)
        mac_tag = hmac.digest(mac_key, auth.user_id.encode(), "sha512")
        public_keys = bytes(auth.keypair.public_key.bytes) + bytes(
            self.enclave_public_key.bytes
        )
        signature = auth.sign(public_keys)
        sigma_auth = Sigma(signature, mac_tag, auth)
        user_auth = UserAuth(
            pki=Pki(
                certChainPem=sigma_auth.get_cert_chain(),
                signature=sigma_auth.get_signature(),
                idMac=sigma_auth.get_mac_tag(),
            ),
            enclaveEndorsements=auth.get_enclave_endorsements(),
        )
        return user_auth

    def send_request_raw(
        self,
        request: bytes,
        protocol: int,
        auth: Auth,
    ) -> List[bytes]:
        gcg_protocol = serialize_length_delimited(ComputeNodeProtocol(version=protocol))
        serialized_request = serialize_length_delimited(
            Request(
                deltaRequest=self._encrypt_and_encode_data(
                    gcg_protocol + request,
                    auth,
                )
            )
        )
        url = Endpoints.SESSION_MESSAGES.replace(":sessionId", self.session_id)
        enclave_response: bytes = self.api.post(
            url,
            serialized_request,
            {"Content-type": "application/octet-stream", "Accept-Version": "2"},
        ).content

        responses: List[bytes] = []
        offset = 0
        while offset < len(enclave_response):
            response_container = Response()
            offset += parse_length_delimited(
                enclave_response[offset:], response_container
            )
            if response_container.HasField("unsuccessfulResponse"):
                raise Exception(response_container.unsuccessfulResponse)
            else:
                decrypted_response = self._decode_and_decrypt_data(
                    response_container.successfulResponse,
                    auth,
                )
                response_protocol = ComputeNodeProtocol()
                response_offset = parse_length_delimited(
                    decrypted_response, response_protocol
                )
                if response_protocol.version != protocol:
                    raise Exception(
                        "Different response protocol version than requested"
                    )
                responses.append(decrypted_response[response_offset:])
        return responses

    def send_compilable_request(
        self,
        compile_request: Callable[[CompilerRequest, Self], bytes],
        request: CompilerRequest,
        decompile_response: Callable[[List[bytes]], CompilerResponse],
        protocol: int,
        auth: Auth,
    ) -> CompilerResponse:
        compiled_request = compile_request(request, self)
        responses = self.send_request_raw(compiled_request, protocol, auth)
        response = decompile_response(responses)
        return response

    def send_request(
        self,
        request: GcgRequest,
        protocol: int,
        auth: Auth,
    ) -> List[GcgResponse]:
        """
        Low-level method for sending a raw `GcgRequest` to the enclave.
        Use this method if any of the convenience methods (such as `run_computation`) don't perform
        the exact task you want.
        """

        def parse_response(response_encoded: bytes) -> GcgResponse:
            response = GcgResponse()
            parse_length_delimited(response_encoded, response)
            if response.HasField("failure"):
                raise EnclaveError(response.failure)
            return response

        request.userAuth.CopyFrom(self._get_message_auth(auth))
        responses_encoded = self.send_request_raw(
            serialize_length_delimited(request), protocol, auth
        )
        responses = list(map(parse_response, responses_encoded))
        return responses
