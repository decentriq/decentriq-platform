import json
from .config import AVATO_HOST, AVATO_PORT, AVATO_USE_TLS
from .api import API, Endpoints
from .instance import Instance
from OpenSSL.crypto import dump_certificate_request, FILETYPE_PEM
from .authentication import generate_csr, generate_key, Pki


class Client:

    class UnknownUserEmail(Exception):
        """Raised when the user email doesn't exist"""
        pass

    class FileUploadError(Exception):
        """Raised when file upload fails"""
        pass

    def __init__(
            self,
            api_token: str,
            backend_host: str = AVATO_HOST,
            backend_port: int = AVATO_PORT,
            use_ssl: bool = AVATO_USE_TLS,
            http_proxy=None,
            https_proxy=None,
    ):
        self.instance = Instance
        self.api = API(
            api_token,
            backend_host,
            backend_port,
            use_ssl,
            http_proxy,
            https_proxy,
        )

    def get_user_id(self, email: str):
        url = f"{Endpoints.USERS_COLLECTION}?email={email}"
        response = self.api.get(url)
        users = response.json()
        if len(users) != 1:
            raise Client.UnknownUserEmail
        user_id = users[0]["id"]
        return user_id

    def create_instance(self):
        url = Endpoints.SESSIONS
        response = self.api.post(url)
        response_json = response.json()
        return self.instance(self, response_json["sessionId"], response_json["owner"])

    def create_instance_from_mrenclave(self, mrenclave):
        url = Endpoints.SESSIONS_MRENCLAVE.replace(":mrenclave", mrenclave)
        response = self.api.post(url)
        response_json = response.json()
        return self.instance(self, response_json["sessionId"], response_json["owner"], mrenclave)

    def get_mrenclaves(self):
        url = Endpoints.MRENCLAVES
        response = self.api.get(url)
        response_json = response.json()

        return response_json["response"]

    def get_ca_root_certificate(self) -> bytes:
        url = Endpoints.USERS_CERTIFICATE_AUTHORITY
        response = self.api.get(url)
        response_json = response.json()
        return bytes(response_json["rootCertificate"], "utf-8")

    def get_user_pki_authenticator(self, email: str) -> Pki:
        keypair = generate_key()
        csr = generate_csr(email, keypair)
        url = Endpoints.USER_CERTIFICATE.replace(":userId", self.get_user_id(email))
        csr_str = dump_certificate_request(FILETYPE_PEM, csr).decode("utf-8")
        csr_req = {"csrPem": csr_str}
        resp = self.api.post(url, req_body=json.dumps(csr_req))
        cert_chain_pem = resp.json()["certChainPem"].encode()
        return Pki(cert_chain_pem, keypair, email)
