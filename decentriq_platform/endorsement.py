# This is to avoid circular import with Endorser
from __future__ import annotations
from typing import TYPE_CHECKING, Dict
if TYPE_CHECKING:
    from .client import Client

from .authentication import Auth, generate_csr
from .types import EnclaveSpecification
from .session import Session
from .proto import EnclaveEndorsement


class Endorser:
    _session: Session
    _client: Client

    def __init__(
        self,
        auth: Auth,
        client: Client,
        enclaves: Dict[str, EnclaveSpecification],
    ):
        self._session = client.create_session(auth, enclaves)
        self._client = client

    @property
    def auth(self) -> Auth:
        return self._session.auth

    def pki_endorsement(
        self,
        cert_chain_pem: bytes,
    ) -> EnclaveEndorsement:
        return self._session.pki_endorsement(cert_chain_pem).pkiEndorsement

    def decentriq_pki_endorsement(self) -> EnclaveEndorsement:
        csr = generate_csr(self._client.user_email, self.auth.kp)
        cert_chain_pem = self._client._get_user_certificate(self._client.user_email, csr.decode("utf-8"))
        return self.pki_endorsement(cert_chain_pem.encode('utf-8'))

    def dcr_secret_endorsement(
        self,
        dcr_secret: str,
    ) -> Tuple[EnclaveEndorsement, bytes]:
        response = self._session.dcr_secret_endorsement(dcr_secret)
        return response.dcrSecretEndorsement, response.dcrSecretId
