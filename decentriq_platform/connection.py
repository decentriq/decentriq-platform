from typing import TYPE_CHECKING, Any, Callable, List, TypeVar, Protocol, cast

from .api import Api, ApiError
from .authentication import Auth
from .channel import Channel, CompilerRequest, CompilerResponse
from .graphql import GqlClient
from .proto.attestation_pb2 import AttestationSpecification
from .proto.gcg_pb2 import GcgRequest, GcgRequestV2, GcgResponse, GcgResponseV2

Response = TypeVar("Response")


class Connection:
    """
    Class that wraps a Channel and re-creates the enclave connection in case of exceptions
    """
    channel: Channel
    driver_attestation_specification: AttestationSpecification
    api: Api
    graphql_api: GqlClient
    unsafe_disable_known_root_ca_check: bool
    max_retries: int

    def __init__(
        self,
        driver_attestation_specification: AttestationSpecification,
        api: Api,
        graphql_api: GqlClient,
        unsafe_disable_known_root_ca_check: bool = False,
        max_retries: int = 5,
    ) -> None:
        self.driver_attestation_specification = driver_attestation_specification
        self.api = api
        self.graphql_api = graphql_api
        self.unsafe_disable_known_root_ca_check = unsafe_disable_known_root_ca_check
        self.channel = Channel(
            self.driver_attestation_specification,
            self.api,
            self.graphql_api,
            self.unsafe_disable_known_root_ca_check,
        )
        self.max_retries = max_retries

    def _retry_request(
        self, request_call: Callable[..., Response], *args: Any
    ) -> Response:
        for _ in range(0, self.max_retries):
            try:
                response = request_call(self.channel, *args)
                return response
            except ApiError as api_error:
                if api_error.message == "enclave unavailable":
                    self.channel = Channel(
                        self.driver_attestation_specification,
                        self.api,
                        self.graphql_api,
                        self.unsafe_disable_known_root_ca_check,
                    )
                    continue
                elif api_error.message == "manual deletion":
                    raise Exception(
                        "Your session with the enclave has expired. Please report this issue to the Decentriq support team."
                    )
                else:
                    raise Exception(
                        f"Unexpected API error {api_error.message}. Please report this issue to the Decentriq support team."
                    )
            except Exception as e:
                raise e
        raise Exception("Maximum retry limit reached")

    def send_request_v2(
        self,
        request: GcgRequestV2,
    ) -> GcgResponseV2:
        return self._retry_request(Channel.send_request_v2, request)

    def send_request(
        self,
        request: GcgRequest,
        protocol: int,
        auth: Auth,
    ) -> List[GcgResponse]:
        return self._retry_request(Channel.send_request, request, protocol, auth)

    def send_request_raw(
        self,
        request: bytes,
        protocol: int,
    ) -> List[bytes]:
        return self._retry_request(
            Channel.send_request_raw, request, protocol
        )

    def send_compilable_request(
        self,
        compile_request: Callable[[CompilerRequest, Channel], bytes],
        request: CompilerRequest,
        decompile_response: Callable[[List[bytes]], CompilerResponse],
        protocol: int,
    ) -> CompilerResponse:
        return cast(
            CompilerResponse,
            self._retry_request(
                Channel.send_compilable_request,
                compile_request,
                request,
                decompile_response,
                protocol,
            ),
        )
