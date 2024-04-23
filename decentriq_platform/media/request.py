from typing import List
from decentriq_dcr_compiler import compiler
from decentriq_dcr_compiler.schemas import MediaInsightsRequest, MediaInsightsResponse

from ..channel import Channel
from ..proto import serialize_length_delimited
from ..session import LATEST_GCG_PROTOCOL_VERSION, Session

class Request:
    @staticmethod
    def send(
        request: MediaInsightsRequest,
        session: Session
    ) -> MediaInsightsResponse:
        def compile_request(mi_request: MediaInsightsRequest, channel: Channel):
            user_auth = channel._get_message_auth(session.auth)
            request_serialized = compiler.compile_media_insights_request(
                mi_request,
                serialize_length_delimited(user_auth),
            )
            return bytes(request_serialized)

        def decompile_response(responses: List[bytes]) -> MediaInsightsResponse:
            if len(responses) != 1:
                raise Exception("Malformed response")
            response = compiler.decompile_media_insights_response(
                request, bytes(responses[0])
            )
            return response

        # TODO: The `endpoint_protocols` should come from DDC as it knows
        # the appropriate supported versions.
        endpoint_protocols = [3, 4, 5, 6]
        protocol = session._get_client_protocol(endpoint_protocols)
        response = session.send_compilable_request(
            compile_request, request, decompile_response, protocol 
        )
        return response

