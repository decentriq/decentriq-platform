import json
from .authentication import generate_csr, generate_key, Auth
from .types import (
    UserCsrResponse,
    UserCsrRequest,
)
from .api import API, Endpoints
from .proto import (
    AuthenticationMethod, TrustedPki
)


class ClientPlatformFeatures:
    """
    Provider of a list of methods and properties mirroring what is offered by the Decentriq
    web platform.
    """
    _http_api: API

    def __init__(
        self,
        user_email: str,
        http_api: API,
    ):
        """
        Creating objects of this class directly is not necessary as an object of this class is
        provided as part of each `Client` object.
        """
        self._http_api = http_api
        self.user_email = user_email

    @property
    def decentriq_ca_root_certificate(self) -> bytes:
        """
        Returns the root certificate used by the Decentriq identity provider.
        Note that when using this certificate in any authentication scheme you trust Decentriq as an identity provider!
        """
        url = Endpoints.SYSTEM_CERTIFICATE_AUTHORITY
        response = self._http_api.get(url).json()
        return response["rootCertificate"].encode("utf-8")

    @property
    def decentriq_pki_authentication(self) -> AuthenticationMethod:
        """
        The authentication method that uses the Decentriq root certificate to authenticate
        users.

        This method should be specified when building a data room in case you want to interact
        with the that data room either via the web interface or with sessions created using
        `create_auth_using_decentriq_pki`.
        Note that when using this authentication method you trust Decentriq as an identity provider!

        You can also create an `AuthenticationMethod` object directly and supply your own root certificate,
        with which to authenticate users connecting to your data room.
        In this case you will also need to issue corresponding user certificates and create your
        own custom `Auth` objects.
        """
        root_pki = self.decentriq_ca_root_certificate
        return AuthenticationMethod(
            trustedPki=TrustedPki(rootCertificatePem=root_pki)
        )

    def create_auth_using_decentriq_pki(self, email: str = None) -> Auth:
        """
        Creates a `decentriq_platform.authentication.Auth` object which can be
        attached to a `decentriq_platform.session.Session`.
        Sessions created using such an `Auth` object will commonly be used with
        data rooms that have been configured to use the `decentriq_pki_authentication`
        authentication method.
        """
        email = email if email is not None else self.user_email
        keypair = generate_key()
        csr = generate_csr(email, keypair)
        url = Endpoints.USER_CERTIFICATE.replace(":userId", email)
        csr_req = UserCsrRequest(csrPem=csr.decode("utf-8"))
        resp: UserCsrResponse = self._http_api.post(url, req_body=json.dumps(csr_req)).json()
        cert_chain_pem = resp["certChainPem"].encode("utf-8")
        auth = Auth(cert_chain_pem, keypair, email)
        return auth
