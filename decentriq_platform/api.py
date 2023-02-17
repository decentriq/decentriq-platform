import requests
from enum import Enum
from urllib3.util import Retry
from .config import (
    DECENTRIQ_REQUEST_RETRY_TOTAL,
    DECENTRIQ_REQUEST_RETRY_BACKOFF_FACTOR,
)

retry = Retry(
    total=DECENTRIQ_REQUEST_RETRY_TOTAL,
    backoff_factor=DECENTRIQ_REQUEST_RETRY_BACKOFF_FACTOR,
)


class Endpoints(str, Enum):
    GRAPHQL = "/graphql"
    SESSION_MESSAGES = "/sessions/:sessionId/messages"
    USER_UPLOAD_CHUNKS = "/uploads/:uploadId/chunks/:chunkHash"


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
            "Authorization-Client": client_id,
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

    def _request(self, method, endpoint, **kwargs):
        retry = kwargs.pop("retry", None)

        url = self.base_url + endpoint
        try:
            response = self.session.request(method, url, timeout=self.timeout, **kwargs)
        except Exception as e:
            if retry is None:
                raise

            retry = retry.increment(method=method, url=url)
            retry.sleep()
            response = self._request(method, endpoint, retry=retry, **kwargs)
        Api.__check_response_status_code(response)
        return response

    def post(self, endpoint, req_body=None, headers=None, retry=None):
        response = self._request(
            method="POST",
            endpoint=endpoint,
            data=req_body,
            headers=headers,
            stream=True,
            retry=retry,
        )
        return response

    def post_multipart(self, endpoint, parts=None, headers=None, retry=None):
        response = self._request(
            method="POST", endpoint=endpoint, files=parts, headers=headers, retry=retry
        )
        return response

    def put(self, endpoint, req_body=None, headers=None, retry=None):
        response = self._request(
            method="PUT", endpoint=endpoint, data=req_body, headers=headers, retry=retry
        )
        return response

    def patch(self, endpoint, req_body=None, headers=None, retry=None):
        response = self._request(
            method="PATCH",
            endpoint=endpoint,
            data=req_body,
            headers=headers,
            retry=retry,
        )
        return response

    def get(self, endpoint, params=None, headers=None, retry=None):
        response = self._request(
            method="GET", endpoint=endpoint, params=params, headers=headers, retry=retry
        )
        return response

    def head(self, endpoint, headers=None, retry=None):
        response = self._request(
            method="HEAD", endpoint=endpoint, headers=headers, retry=retry
        )
        return response

    def delete(self, endpoint, headers=None, retry=None):
        response = self._request(
            method="DELETE", endpoint=endpoint, headers=headers, retry=retry
        )
        return response
