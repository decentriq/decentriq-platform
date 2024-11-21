from __future__ import annotations

import json
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
from .helper import generate_id, current_iso_standard_utc_time
from typing_extensions import Self
from decentriq_dcr_compiler.schemas import Audience1, Audience2, Audience3


class FilterOperator(str, Enum):
    CONTAINS_ANY = "contains_any_of"
    CONTAINS_NONE = "contains_none_of"
    CONTAINS_ALL = "contains_all_of"
    EMPTY = "empty"
    NOT_EMPTY = "not_empty"


class Filter:
    def __init__(
        self, *, attribute: str, values: List[str], operator: FilterOperator
    ) -> None:
        self.attribute = attribute
        self.values = values
        self.operator = operator

    def as_dict(self) -> Dict[str, Any]:
        return {
            "operator": self.operator.value,
            "attribute": self.attribute,
            "values": self.values,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> Self:
        return cls(
            attribute=d["attribute"],
            values=d["values"],
            operator=FilterOperator(d["operator"]),
        )


class MatchOperator(str, Enum):
    # All filter criteria must be satisfied.
    MATCH_ALL = "and"
    # Any filter criteria may be satisfied.
    MATCH_ANY = "or"


class AudienceFilters:
    def __init__(
        self,
        *,
        filters: List[Filter],
        operator: MatchOperator,
    ) -> None:
        self.filters = filters
        self.operator = operator

    def as_dict(self) -> Dict[str, Any]:
        return {
            "boolean_op": self.operator.value,
            "filters": [f.as_dict() for f in self.filters],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> Self:
        return cls(
            filters=[Filter.from_dict(f) for f in d["filters"]],
            operator=MatchOperator(d["boolean_op"]),
        )


class CombineOperator(str, Enum):
    # Users in both audiences.
    INTERSECT = "intersect"
    # All users.
    UNION = "union"
    # Users in first audience only.
    DIFF = "diff"


class AudienceCombinator:
    def __init__(
        self,
        *,
        operator: CombineOperator,
        source_audience_name: str,
        source_audience_id: str,
        filters: Optional[AudienceFilters] = None,
    ) -> None:
        self.operator = operator
        self.source_ref_name = source_audience_name
        self.source_ref_id = source_audience_id
        self.filters = filters

    def as_dict(self) -> Dict[str, Any]:
        return {
            "operator": self.operator.value,
            "source_ref": self.source_ref_id,
            "filters": self.filters.as_dict() if self.filters else None,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any], audiences: Dict[str, Any]) -> Self:
        return cls(
            operator=CombineOperator(d["operator"]),
            source_audience_name=audience_name_from_id(d["source_ref"], audiences),
            source_audience_id=d["source_ref"],
            filters=AudienceFilters.from_dict(d["filters"]) if d["filters"] else None,
        )


class AudienceStatus(str, Enum):
    READY = "ready"
    PUBLISHED = "published"
    PUBLISHED_AS_INTERMEDIATE = "published_as_intermediate"


class RuleBasedAudienceDefinition:
    def __init__(
        self,
        *,
        name: str,
        source_ref_name: str,
        source_ref_id: str,
        status: AudienceStatus,
        filters: Optional[AudienceFilters] = None,
        combinators: Optional[List[AudienceCombinator]] = None,
        id: Optional[str] = None,
        created_at: Optional[str] = None,
        audiences: Optional[AudienceDefinitions] = None,
    ) -> None:
        self.name = name
        self.id = id if id else generate_id()
        self.source_ref_name = source_ref_name
        self.source_ref_id = source_ref_id
        self.status = status
        self.filters = filters
        self.combinators = combinators
        self.kind = "rulebased"
        self.created_at = created_at if created_at else current_iso_standard_utc_time()

    def _as_ddc_audience(self) -> Audience3:
        return Audience3.parse_raw(json.dumps(self.as_dict()))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "source_ref": self.source_ref_id,
            "filters": self.filters.as_dict() if self.filters else None,
            "combine": (
                [c.as_dict() for c in self.combinators] if self.combinators else None
            ),
            "mutable": {
                "name": self.name,
                "status": self.status.value,
                "created_at": self.created_at,
            },
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any], audiences: Dict[str, Any]) -> Self:
        (name, status, created_at) = get_mutable_variables(d["mutable"])
        return cls(
            name=name,
            source_ref_name=audience_name_from_id(d["source_ref"], audiences),
            source_ref_id=d["source_ref"],
            status=status,
            filters=AudienceFilters.from_dict(d["filters"]) if d["filters"] else None,
            combinators=(
                [
                    AudienceCombinator.from_dict(c, audiences=audiences)
                    for c in d["combine"]
                ]
                if d["combine"]
                else None
            ),
            id=d["id"],
            created_at=created_at,
        )


class LookalikeAudienceDefinition:
    def __init__(
        self,
        *,
        name: str,
        reach: int,
        seed_audience_name: str,
        source_ref_id: str,
        exclude_seed_audience: bool,
        status: AudienceStatus,
        id: Optional[str] = None,
        created_at: Optional[str] = None,
    ) -> None:
        self.name = name
        self.id = id if id else generate_id()
        self.reach = reach
        self.source_ref_name = seed_audience_name
        self.exclude_seed_audience = exclude_seed_audience
        self.status = status
        self.source_ref_id = source_ref_id
        self.kind = "lookalike"
        self.created_at = created_at if created_at else current_iso_standard_utc_time()

    def _as_ddc_audience(self) -> Audience2:
        return Audience2.parse_raw(json.dumps(self.as_dict()))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "source_ref": self.source_ref_id,
            "reach": self.reach,
            "exclude_seed_audience": self.exclude_seed_audience,
            "mutable": {
                "name": self.name,
                "status": self.status,
                "created_at": self.created_at,
            },
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any], audiences: Dict[str, Any]) -> Self:
        (name, status, created_at) = get_mutable_variables(d["mutable"])
        return cls(
            name=name,
            reach=d["reach"],
            seed_audience_name=audience_name_from_id(d["source_ref"], audiences),
            source_ref_id=d["source_ref"],
            exclude_seed_audience=d["exclude_seed_audience"],
            status=status,
            id=d["id"],
            created_at=created_at,
        )


class AdvertiserAudienceDefinition:
    def __init__(
        self,
        *,
        name: str,
        audience_size: int,
        audience_type: str,
        status: AudienceStatus,
        id: Optional[str] = None,
        created_at: Optional[str] = None,
    ) -> None:
        self.name = name
        self.audience_size = audience_size
        self.audience_type = audience_type
        self.id = id if id else generate_id()
        self.kind = "advertiser"
        self.status = status
        self.created_at = created_at if created_at else current_iso_standard_utc_time()

    def _as_ddc_audience(self) -> Audience1:
        return Audience1.parse_raw(json.dumps(self.as_dict()))

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "audience_size": self.audience_size,
            "audience_type": self.audience_type,
            "mutable": {
                "name": self.name,
                "status": self.status,
                "created_at": self.created_at,
            },
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any], audiences: Dict[str, Any]) -> Self:
        (name, status, created_at) = get_mutable_variables(d["mutable"])
        return cls(
            name=name,
            audience_size=d["audience_size"],
            audience_type=d["audience_type"],
            status=status,
            id=d["id"],
            created_at=created_at,
        )


def audience_name_from_id(audience_id: str, audiences: Dict[str, Any]) -> str:
    lookup = {a["id"]: a["mutable"]["name"] for a in audiences}
    if audience_id not in lookup:
        raise Exception(f'Audience with ID "{audience_id}" could not be found')
    return lookup[audience_id]


def audience_id_from_name(name: str, audiences: AudienceDefinitions) -> str:
    audience = [a for a in audiences if a.name == name]
    if len(audience) == 0:
        raise Exception(
            f'Audience with name "{name}" does not exist in the audience list'
        )
    elif len(audience) > 1:
        raise Exception(f'More than one audience has name "{name}"')
    return audience[0].id


def get_mutable_variables(mutable: Dict[str, Any]) -> Tuple[str, AudienceStatus, str]:
    name = mutable["name"]
    status = AudienceStatus(mutable["status"])
    created_at = mutable["created_at"] if "created_at" in mutable else None
    return (name, status, created_at)


AudienceDefinitions = List[
    Union[
        RuleBasedAudienceDefinition
        , LookalikeAudienceDefinition
        , AdvertiserAudienceDefinition
    ]
]
