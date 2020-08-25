import requests
from enum import Enum
import socket
from http.client import HTTPConnection

AVATO_API_PREFIX = "/api"
AVATO_GENERAL_INFIX = ""
AVATO_ACTIVE_INSTANCE_INFIX = "/instance/:instanceId"


class Endpoints(str, Enum):
    # Instance
    INSTANCES_COLLECTION = "/instances",
    INSTANCE = "/instance/:instanceId",
    INSTANCE_FATQUOTE = "/instance/:instanceId/fatquote",
    INSTANCE_COMMANDS = "/instance/:instanceId/commands",
    INSTANCE_LOGS = "/instance/:instanceId/logs",
    # User
    USERS_COLLECTION = "/users",
    USER = "/user/:userId",
    USER_PASSWORD = "/user/:userId/password",
    USER_PERMISSIONS = "/user/:userId/permissions",
    USER_TOKENS_COLLECTION = "/user/:userId/tokens",
    USER_TOKEN = "/user/:userId/token/:tokenId",
    USER_FILES_COLLECTION = "/user/:userId/files"
    USER_FILE = "/user/:userId/file/:fileId",
    USER_FILE_CHUNK = "/user/:userId/file/:fileId/chunk/:chunkHash"

	

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


class MyHTTPConnection(HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt( socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.sock.setsockopt(socket.SOL_TCP, socket.TCP_KEEPINTVL, 15)
        if self._tunnel_host:
            self._tunnel()

requests.packages.urllib3.connectionpool.HTTPConnection = MyHTTPConnection

class API:
    def __init__(
        self,
        api_token,
        backend_host,
        backend_port,
        use_ssl,
        http_proxy,
        https_proxy,
    ):
        session = requests.Session()
        if use_ssl:
            if https_proxy:
                session.proxies = {"https": https_proxy}
            protocol = "https"
        else:
            if http_proxy:
                session.proxies = {"http": http_proxy}
            protocol = "http"
        self.base_url = f"{protocol}://{backend_host}:{backend_port}{AVATO_API_PREFIX}"
        auth_header = {"Authorization": "Bearer " + api_token}
        session.headers.update(auth_header)
        self.session = session

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
        response = self.session.post(url, data=req_body, headers={**headers})
        API.__check_response_status_code(response)
        return response

    def post_multipart(self, endpoint, parts=None, headers={}):
        url = self.base_url + endpoint
        response = self.session.post(url, files=parts, headers={**headers})
        API.__check_response_status_code(response)
        return response

    def put(self, endpoint, req_body=None, headers={}):
        url = self.base_url + endpoint
        response = self.session.put(url, data=req_body, headers={**headers})
        API.__check_response_status_code(response)
        return response

    def patch(self, endpoint, req_body=None, headers={}):
        url = self.base_url + endpoint
        response = self.session.patch(url, data=req_body, headers={**headers})
        API.__check_response_status_code(response)
        return response

    def get(self, endpoint, headers={}):
        url = self.base_url + endpoint
        response = self.session.get(url, headers={**headers})
        API.__check_response_status_code(response)
        return response

    def head(self, endpoint, headers={}):
        url = self.base_url + endpoint
        response = self.session.head(url, headers={**headers})
        API.__check_response_status_code(response)
        return response

    def delete(self, endpoint, headers={}):
        url = self.base_url + endpoint
        response = self.session.delete(url, headers={**headers})
        API.__check_response_status_code(response)
        return response
