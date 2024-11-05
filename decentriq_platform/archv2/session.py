from __future__ import annotations
from typing import (
    TYPE_CHECKING,
    Any,
    Tuple,
    cast
)

from ..connection import Connection
from ..channel import EnclaveError
from ..proto import (
    GcgRequestV2,
    AuthenticatedRequest,
    AuthenticatedResponse,
)
from ..proto.secret_store_pb2 import (
    SecretStoreEntry,
    SecretStoreRequest,
    SecretStoreResponse,
    GetSecretRequest,
    RemoveSecretRequest,
    CreateSecretRequest,
    UpdateSecretAclRequest,
)
from .secret import Secret
from decentriq_dcr_compiler.schemas.secret_store_entry_state import SecretStoreEntryState, SECRET_STORE_ENTRY_STATE_VERSION, v0

if TYPE_CHECKING:
    from ..client import Client

__all__ = [
    "SessionV2",
]

class SessionV2:
    """
    Class for managing the communication with an enclave.
    """

    client: Client
    connection: Connection
    keypair: Any

    def __init__(
        self,
        client: Client,
        connection: Connection,
    ):
        """
        `Session` instances should not be instantiated directly but rather
         be created using a `Client` object using  `decentriq_platform.Client.create_session_v2`.
        """
        self.client = client
        self.connection = connection

    def send_authenticated_request(
        self,
        authenticated_request: AuthenticatedRequest,
    ) -> AuthenticatedResponse:
        authenticated_request.apiToken = self.client.enclave_api_token
        request = GcgRequestV2(authenticated=authenticated_request)
        response = self.connection.send_request_v2(request)
        if response.HasField("failure"):
            raise EnclaveError(response.failure)
        successful_response = response.success
        if not successful_response.HasField("authenticated"):
            raise Exception(
                "Expected `authenticated` response, got "
                + str(successful_response.WhichOneof("response"))
            )
        authenticated_response = response.success.authenticated
        return authenticated_response

    def send_secret_store_request(
        self,
        request: SecretStoreRequest,
    ) -> SecretStoreResponse:
        authenticated_request = AuthenticatedRequest(secretStore=request)
        response = self.send_authenticated_request(authenticated_request)
        if not response.HasField("secretStore"):
            raise Exception(
                f"Expected `secretStore` response, got "
                + str(response.WhichOneof("response"))
            )
        secret_store_response = cast(SecretStoreResponse, response.secretStore)
        return secret_store_response

    def remove_secret(self, secret_id: str, expected_cas_index: int) -> bool:
        request = SecretStoreRequest(
            removeSecret=RemoveSecretRequest(
                id=secret_id,
                expectedCasIndex=expected_cas_index,
            )
        )
        secret_store_response = self.send_secret_store_request(request)
        if not secret_store_response.HasField("removeSecret"):
            raise Exception(
                f"Expected `removeSecret`, got "
                + str(secret_store_response.WhichOneof("response"))
            )
        return secret_store_response.removeSecret.removed

    def get_secret(self, secret_id: str) -> Tuple[Secret, int]:
        request = SecretStoreRequest(
            getSecret=GetSecretRequest(
                id=secret_id,
                version=SECRET_STORE_ENTRY_STATE_VERSION
            )
        )
        secret_store_response = self.send_secret_store_request(request)
        if not secret_store_response.HasField("getSecret"):
            raise Exception(
                f"Expected `getSecret`, got "
                + str(secret_store_response.WhichOneof("response"))
            )
        get_secret_response = secret_store_response.getSecret
        if not get_secret_response.HasField("secret"):
            raise Exception(
                f"Expected `secret` in `getSecret` response, got "
                + str(get_secret_response)
            )
        else:
            entry_state = SecretStoreEntryState.model_validate_json(get_secret_response.secret.state)
            return Secret(get_secret_response.secret.content, entry_state),  get_secret_response.casIndex

    def create_secret(self, secret: Secret) -> str:
        """Store a secret in the user's own enclave-protected secret store"""
        request = SecretStoreRequest(
            createSecret=CreateSecretRequest(
                secret=SecretStoreEntry(
                    content=secret.secret,
                    state=secret.state.model_dump_json().encode("utf-8")
                )
            )
        )
        secret_store_response = self.send_secret_store_request(request)
        if not secret_store_response.HasField("createSecret"):
            raise Exception(
                f"Expected `setSecret`, got "
                + str(secret_store_response.WhichOneof("response"))
            )
        return secret_store_response.createSecret.id
    
    def update_secret_acl(self, secret_id: str, new_acl: v0.SecretStoreEntryAcl, expected_cas_index: int) -> bool:
        """Update a secret ACL"""
        request = SecretStoreRequest(
            updateSecretAcl=UpdateSecretAclRequest(
                id=secret_id,
                newAcl=new_acl.model_dump_json().encode("utf-8"),
                version=SECRET_STORE_ENTRY_STATE_VERSION,
                expectedCasIndex=expected_cas_index
            )
        )
        secret_store_response = self.send_secret_store_request(request)
        if not secret_store_response.HasField("updateSecretAcl"):
            raise Exception(
                f"Expected `updatedSecretAcl`, got "
                + str(secret_store_response.WhichOneof("response"))
            )
        return secret_store_response.updateSecretAcl.updated