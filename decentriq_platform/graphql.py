import json
from .api import ApiError


class GqlClient:
    def __init__(
        self,
        http_api,
        path,
    ):
        self._http_api = http_api
        self._path = path

    def post(self, query: str, variables={}, retry=None) -> dict:
        request_payload = { "query": query }
        if variables:
            request_payload["variables"] = variables
        response = self._http_api.post(
            self._path,
            json.dumps(request_payload),
            {"Content-type": "application/json"},
            retry=retry
        )
        payload = response.json()
        if "errors" in payload:
            message = ",".join([error["message"] for error in payload["errors"]])
            raise ApiError(message)
        elif "data" in payload:
            return payload["data"]
        else:
            raise ApiError("Malformed GraphQL response: no 'data' or 'errors' key")
