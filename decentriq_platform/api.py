import requests
from enum import Enum


class Endpoints(str, Enum):
    GRAPHQL = "/graphql",
    SESSION_MESSAGES = "/sessions/:sessionId/messages",
    USER_UPLOAD_CHUNKS = "/uploads/:uploadId/chunks/:chunkHash",


class ApiError(Exception):
    pass


class AuthorizationError(ApiError):
    pass


class NotFoundError(ApiError):
    pass


class BadRequestError(ApiError):
    pass


class ServerError(ApiError):
    pass


class Api:
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
        body = response.content
        try:
            payload = response.json()
            if "errors" in payload:
                errors = payload["errors"]
                message = ",".join([error["message"] for error in errors])
                body = message
        except:
            pass

        if response.status_code >= 200 and response.status_code <= 204:
            pass
        elif response.status_code == 400:
            raise BadRequestError(body)
        elif response.status_code == 401 or response.status_code == 403:
            raise AuthorizationError(body)
        elif response.status_code == 404:
            raise NotFoundError(body)
        elif response.status_code >= 500 and response.status_code <= 504:
            raise ServerError(body)
        else:
            raise ApiError(body)

    def post(self, endpoint, req_body=None, headers={}):
        url = self.base_url + endpoint
        response = self.session.post(
            url, data=req_body, headers={**headers}, timeout=self.timeout, stream=True
        )
        Api.__check_response_status_code(response)
        return response

    def post_multipart(self, endpoint, parts=None, headers={}):
        url = self.base_url + endpoint
        response = self.session.post(
            url, files=parts, headers={**headers}, timeout=self.timeout
        )
        Api.__check_response_status_code(response)
        return response

    def put(self, endpoint, req_body=None, headers={}):
        url = self.base_url + endpoint
        response = self.session.put(
            url, data=req_body, headers={**headers}, timeout=self.timeout
        )
        Api.__check_response_status_code(response)
        return response

    def patch(self, endpoint, req_body=None, headers={}):
        url = self.base_url + endpoint
        response = self.session.patch(
            url, data=req_body, headers={**headers}, timeout=self.timeout
        )
        Api.__check_response_status_code(response)
        return response

    def get(self, endpoint, params={}, headers={}):
        url = self.base_url + endpoint
        response = self.session.get(
            url, params={**params}, headers={**headers}, timeout=self.timeout
        )
        Api.__check_response_status_code(response)
        return response

    def head(self, endpoint, headers={}):
        url = self.base_url + endpoint
        response = self.session.head(
            url, headers={**headers}, timeout=self.timeout
        )
        Api.__check_response_status_code(response)
        return response

    def delete(self, endpoint, headers={}):
        url = self.base_url + endpoint
        response = self.session.delete(
            url, headers={**headers}, timeout=self.timeout
        )
        Api.__check_response_status_code(response)
        return response
