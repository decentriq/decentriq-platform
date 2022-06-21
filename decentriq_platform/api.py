import requests
from enum import Enum

class Endpoints(str, Enum):
    # System
    SYSTEM_ENCLAVE_IDENTIFIERS = "/system/enclave-identifiers",
    SYSTEM_ATTESTATION_SPECS = "/system/attestation-specs",
    SYSTEM_CERTIFICATE_AUTHORITY = "/system/certificate-authority",
    # Session
    SESSIONS = "/sessions",
    SESSION = "/session/:sessionId",
    SESSION_FATQUOTE = "/session/:sessionId/fatquote",
    SESSION_MESSAGES = "/session/:sessionId/messages",
    # User
    USERS_COLLECTION = "/users",
    USER = "/user/:userId",
    USER_UPLOADS_COLLECTION = "/user/:userId/uploads",
    USER_UPLOAD = "/user/:userId/upload/:uploadId",
    USER_UPLOAD_CHUNKS = "/user/:userId/upload/:uploadId/chunks",
    USER_CERTIFICATE = "/user/:userId/certificate",
    USER_SCOPES_COLLECTION = "/user/:userId/scopes",
    USER_SCOPE = "/user/:userId/scope/:scopeId",
    USER_FILES = "/user/:userId/files",
    USER_FILE = "/user/:userId/file/:manifestHash",


class APIError(Exception):
    def __init__(self, body):
        self.body = body

class AuthorizationError(APIError):
    """ """

    pass


class NotFoundError(APIError):
    """ """

    pass


class BadRequestError(APIError):
    """ """

    pass


class ServerError(APIError):
    """ """

    pass


class UnknownError(APIError):
    """ """

    pass

class API:
    def __init__(
        self,
        api_token,
        client_id,
        host,
        port,
        use_tls,
        api_prefix,
        additional_auth_headers={},
        timeout=None,
    ):
        session = requests.Session()
        if use_tls:
            protocol = "https"
        else:
            protocol = "http"
        self.base_url = f"{protocol}://{host}:{port}{api_prefix}"
        auth_headers = {
                "Authorization": "Bearer " + api_token,
                "Authorization-Type": "app",
                "Authorization-Client": client_id
        }
        auth_headers.update(additional_auth_headers)
        session.headers.update(auth_headers)
        self.session = session
        self.timeout = timeout

    @staticmethod
    def __check_response_status_code(response):
        if response.status_code >= 200 and response.status_code <= 204:
            pass
        elif response.status_code == 400:
            raise BadRequestError(response.content)
        elif response.status_code == 401 or response.status_code == 403:
            raise AuthorizationError(response.content)
        elif response.status_code == 404:
            raise NotFoundError(response.content)
        elif response.status_code >= 500 and response.status_code <= 504:
            raise ServerError(response.content)
        else:
            raise UnknownError(response.content)

    def post(self, endpoint, req_body=None, headers={}):
        url = self.base_url + endpoint
        response = self.session.post(
            url, data=req_body, headers={**headers}, timeout=self.timeout, stream=True
        )
        API.__check_response_status_code(response)
        return response

    def post_multipart(self, endpoint, parts=None, headers={}):
        url = self.base_url + endpoint
        response = self.session.post(
            url, files=parts, headers={**headers}, timeout=self.timeout
        )
        API.__check_response_status_code(response)
        return response

    def put(self, endpoint, req_body=None, headers={}):
        url = self.base_url + endpoint
        response = self.session.put(
            url, data=req_body, headers={**headers}, timeout=self.timeout
        )
        API.__check_response_status_code(response)
        return response

    def patch(self, endpoint, req_body=None, headers={}):
        url = self.base_url + endpoint
        response = self.session.patch(
            url, data=req_body, headers={**headers}, timeout=self.timeout
        )
        API.__check_response_status_code(response)
        return response

    def get(self, endpoint, params={}, headers={}):
        url = self.base_url + endpoint
        response = self.session.get(
            url, params={**params}, headers={**headers}, timeout=self.timeout
        )
        API.__check_response_status_code(response)
        return response

    def head(self, endpoint, headers={}):
        url = self.base_url + endpoint
        response = self.session.head(
            url, headers={**headers}, timeout=self.timeout
        )
        API.__check_response_status_code(response)
        return response

    def delete(self, endpoint, headers={}):
        url = self.base_url + endpoint
        response = self.session.delete(
            url, headers={**headers}, timeout=self.timeout
        )
        API.__check_response_status_code(response)
        return response
