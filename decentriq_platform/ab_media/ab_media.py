from __future__ import annotations

import json

from typing import TYPE_CHECKING, Dict, Any, Optional, List
from typing_extensions import Self
from decentriq_dcr_compiler import ab_media as ab_media_compiler

from ..session import Session
from ..attestation import enclave_specifications
from ..types import EnclaveSpecification
from .advertiser_api import AdvertiserApi
from .publisher_api import PublisherApi
from .features import AbMediaDcrFeatures
from .version import AUDIENCE_BUILDER_WRAPPER_SUPPORTED_VERSION

if TYPE_CHECKING:
    from ..client import Client

__docformat__ = "restructuredtext"


class AbMediaDcrDefinition:
    """
    Class representing an Audience Builder DCR Definition.
    """

    def __init__(
        self,
        name: str,
        high_level: Dict[str, Any],
        enclave_specs: Optional[Dict[str, EnclaveSpecification]] = None,
    ) -> None:
        self.name = name
        self._high_level = high_level
        self._enclave_specs = enclave_specs


class AbMediaDcr:
    """
    Class representing an Audience Builder DCR.
    """

    def __init__(
        self,
        dcr_id: str,
        high_level: Dict[str, Any],
        session: Session,
        *,
        client: Client,
    ) -> None:
        """
        Initialise an Audience Builder DCR.

        **Parameters**:
        - `dcr_id`: ID of the Audience Builder DCR.
        - `high_level`: High level representation of the Audience Builder DCR.
        - `session`: A `Session` object which can be used for communication with the enclave.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        """
        self.client = client
        self.session = session
        self.high_level = high_level
        self.id = dcr_id
        self.features = _get_features(high_level)
        self.advertiser = AdvertiserApi(self)
        self.publisher = PublisherApi(self)

    def retrieve_audit_log(self) -> str:
        """
        Retrieve the audit log.
        """
        return self.session.retrieve_audit_log(self.id).log.decode("utf-8")

    def participants(self) -> Dict[str, Any]:
        """
        Retrieve the participants of the Audience Builder DCR.
        This returns a dictionary of roles (keys) mapped to participants (email addresses).
        """
        dcr = self.high_level[AUDIENCE_BUILDER_WRAPPER_SUPPORTED_VERSION]
        compute_keys_list = list(dcr["compute"].keys())
        if len(compute_keys_list) != 1:
            raise Exception(
                f"Unable to extract Media DCR version. Expected a single top-level property indicating the DCR version."
            )

        compute_version = compute_keys_list[0]
        compute = dcr["compute"][compute_version]
        return {
            "publisher": compute["publisherEmails"],
            "advertiser": compute["advertiserEmails"],
            "observer": compute["observerEmails"],
            "agency": compute["agencyEmails"],
            "data_partner": compute["dataPartnerEmails"],
        }

    def stop(self):
        """
        Stop the Audience Builder DCR.
        """
        self.session.stop_data_room(self.id)

    @classmethod
    def _from_existing(
        cls,
        dcr_id: str,
        *,
        client: Client,
        enclave_specs: Optional[List[EnclaveSpecification]] = None,
    ) -> Self:
        """
        Construct an Audience Builder DCR from an existing DCR with the given ID.

        **Parameters**:
        - `dcr_id`: ID of the Audience Builder DCR.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `enclave_specs`: Determines the types of enclaves that are supported by this Data Clean Room.
            If not specified, the latest enclave specifications will be used.
        """
        specs = enclave_specs if enclave_specs else enclave_specifications.all()
        specs_dict = {spec["name"]: spec for spec in specs}
        existing_data_room_description = client.get_data_room_description(
            dcr_id, enclave_specs=specs_dict
        )
        if not existing_data_room_description:
            raise Exception(
                f"Unable to retrieve data room description for data room with ID {dcr_id}"
            )
        session = client.create_session_from_data_room_description(
            existing_data_room_description, specs
        )
        existing_dcr = session.retrieve_data_room(dcr_id)
        high_level = json.loads(existing_dcr.highLevelRepresentation.decode())

        dcr = cls(dcr_id=dcr_id, session=session, high_level=high_level, client=client)
        return dcr


def _get_features(high_level: Dict[str, Any]) -> AbMediaDcrFeatures:
    features = ab_media_compiler.get_ab_media_dcr_features_serialized(
        json.dumps(high_level)
    )
    return AbMediaDcrFeatures(features)
