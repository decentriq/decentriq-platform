import json
from .config import AVATO_HOST, AVATO_PORT, AVATO_USE_SSL
from .api import API, Endpoints
from typing import List, Any
from OpenSSL.crypto import dump_certificate_request, FILETYPE_PEM
from .authentication import generate_csr, generate_key, Pki


class Client:
    class UnknownInstanceTypeError(Exception):
        """Raised when the instance type requested is not supported"""
        pass

    class UnknownUserEmail(Exception):
        """Raised when the user email doesn't exist"""
        pass

    class FileUploadError(Exception):
        """Raised when file upload fails"""
        pass

    def __init__(
            self,
            api_token: str,
            instance_types: List[Any] = None,
            backend_host: str = AVATO_HOST,
            backend_port: int = AVATO_PORT,
            use_ssl: bool = AVATO_USE_SSL,
            http_proxy=None,
            https_proxy=None,
    ):
        if instance_types is None:
            instance_types = []
        self.registered_instances = instance_types
        self.api = API(
            api_token,
            backend_host,
            backend_port,
            use_ssl,
            http_proxy,
            https_proxy,
        )

    def get_instances(self):
        url = Endpoints.INSTANCES_COLLECTION
        response = self.api.get(url)
        return response.json()

    def _instance_from_type(self, type):
        for instance in self.registered_instances:
            if instance.type == type:
                return instance
        raise Client.UnknownInstanceTypeError

    def get_user_id(self, email: str):
        url = f"{Endpoints.USERS_COLLECTION}?email={email}"
        response = self.api.get(url)
        users = response.json()
        if len(users) != 1:
            raise Client.UnknownUserEmail
        user_id = users[0]["id"]
        return user_id

    
    def create_instance(self, name, type, participants):
        url = Endpoints.INSTANCES_COLLECTION
        data = {
            "name": name,
            "type": type,
            "participants": list(map(lambda x: {"participantId": self.get_user_id(x)}, participants)),
        }
        data_json = json.dumps(data)
        response = self.api.post(url, data_json, {"Content-type": "application/json"})
        response_json = response.json()
        instance_constructor = self._instance_from_type(type)
        return instance_constructor(self, response_json["instanceId"], name, response_json["owner"])

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
