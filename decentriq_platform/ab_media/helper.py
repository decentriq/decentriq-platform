from datetime import datetime
import json
from typing import Any, Dict
import uuid
from decentriq_dcr_compiler.schemas import Audience4, ParameterPayloads
from decentriq_dcr_compiler import ab_media as ab_media_compiler


def generate_id() -> str:
    return str(uuid.uuid4())


def current_iso_standard_utc_time() -> str:
    return str(datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f"))[:-3] + "Z"


def flatten_mutable_fields(definition: Dict[str, Any]) -> Dict[str, Any]:
    """
    Flatten the mutable field so that all mutable variables are
    included in the parent level of the dictionary.
    """
    audiences = definition.pop("audiences")
    flattened_dict = definition

    flattened_audience = []
    for audience in audiences:
        if "mutable" in audience:
            mutable = audience.pop("mutable")
            for k, v in mutable.items():
                audience[k] = v
        flattened_audience.append(audience)

    flattened_dict["audiences"] = flattened_audience
    return flattened_dict


def get_parameter_payloads(
    audience_name: str, audiences_json: Dict[str, Any]
) -> ParameterPayloads:
    audiences = {
        a["mutable"]["name"]: Audience4.parse_raw(json.dumps(a))
        for a in audiences_json["audiences"]
    }

    if audience_name not in audiences:
        raise Exception(
            f'Requested audience with name "{audience_name}" not in list of available audiences'
        )

    target_audience = audiences[audience_name].root
    parameter_payloads_str = ab_media_compiler.get_parameter_payloads(
        target_ref=target_audience.id, audiences=list(audiences.values())
    )
    parameter_payloads = ParameterPayloads.parse_raw(parameter_payloads_str)
    return parameter_payloads


def audience_depends_on_lookalike(
    audience_name: str, audiences_json: Dict[str, Any]
) -> bool:
    audiences = {
        a["mutable"]["name"]: Audience4.parse_raw(json.dumps(a))
        for a in audiences_json["audiences"]
    }

    if audience_name not in audiences:
        raise Exception(
            f'Requested audience with name "{audience_name}" not in list of available audiences'
        )

    target_audience = audiences[audience_name].root
    return ab_media_compiler.does_audience_depend_on_lookalike_audience(
        target_ref=target_audience.id, audiences=audiences.values()
    )


def get_dependencies(
    target_audience_id: str, audiences: list[Any]
) -> list[str]:
    return ab_media_compiler.get_dependencies(
        target_ref=target_audience_id,
        audiences=[Audience4.parse_raw(json.dumps(a)) for a in audiences]
    )
