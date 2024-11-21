from typing import List
from decentriq_dcr_compiler import ab_media as ab_media_compiler
from decentriq_dcr_compiler.schemas import AbMediaRequest, AbMediaResponse

from ..channel import Channel
from ..proto import serialize_length_delimited
from ..session import Session


class Request:
    @staticmethod
    def send(request: AbMediaRequest, session: Session) -> AbMediaResponse:
        def compile_request(request: AbMediaRequest, channel: Channel):
            user_auth = channel._get_message_auth(session.auth)
            request_serialized = ab_media_compiler.compile_ab_media_request(
                request,
                serialize_length_delimited(user_auth),
            )
            return bytes(request_serialized)

        def decompile_response(responses: List[bytes]) -> AbMediaResponse:
            if len(responses) != 1:
                raise Exception("Malformed response")
            response = ab_media_compiler.decompile_ab_media_response(
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
