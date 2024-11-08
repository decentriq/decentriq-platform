from __future__ import annotations

import io
import json
from typing import TYPE_CHECKING, Dict, Any, Optional, List

from ..storage import Key
from ..session import Session
from typing_extensions import Self
from ..attestation import enclave_specifications
from decentriq_dcr_compiler import compiler
from decentriq_dcr_compiler.schemas import (
    MediaInsightsRequest,
)
from .features import MediaInsightFeatures
from .publisher_computations import (
    OverlapInsightsComputation,
    OverlapStatisticsComputation,
    GetAudiencesForPublisherComputation,
    GetAudienceUserListComputation,
)

from .advertiser_computations import (
    AvailableAudiencesComputation,
    GetAudiencesForAdvertiserComputation,
    GetAudienceUserListForAdvertiserComputation,
)
from .request import Request
from .audience import Audience
from ..types import EnclaveSpecification
from .version import MEDIA_DCR_SUPPORTED_VERSION, MEDIA_DCR_WRAPPER_SUPPORTED_VERSION

if TYPE_CHECKING:
    from ..client import Client

__docformat__ = "restructuredtext"


class MediaDcrDefinition:
    """
    Class representing a Media DCR Definition.
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


class MediaDcr:
    """
    Class representing a Media DCR.
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
        Initialise a Media DCR.

        **Parameters**:
        - `dcr_id`: ID of the Media DCR.
        - `high_level`: High level representation of the Media DCR.
        - `session`: A `Session` object which can be used for communication with the enclave.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        """
        self.client = client
        self.session = session
        self.high_level = high_level
        self.id = dcr_id
        self.features = _get_features(high_level)

    def retrieve_audit_log(self) -> str:
        """
        Retrieve the audit log.
        """
        return self.session.retrieve_audit_log(self.id).log.decode("utf-8")

    def stop(self):
        """
        Stop the Media DCR.
        """
        self.session.stop_data_room(self.id)

    def get_insights(self) -> Dict[str, Any]:
        """
        Get the insights.
        """
        if not self.features.has_enable_insights():
            raise Exception("This Media DCR does not support insights.")

        overlap_insights_computation = OverlapInsightsComputation(
            dcr_id=self.id, client=self.client, session=self.session
        )
        return overlap_insights_computation.run_and_get_results()

    def get_overlap_statistics(self) -> Dict[str, Any]:
        """
        Get the overlap statistics.
        """
        overlap_statistics_computation = OverlapStatisticsComputation(
            dcr_id=self.id, client=self.client, session=self.session
        )
        return overlap_statistics_computation.run_and_get_results()

    def get_audiences_for_publisher(self) -> Dict[str, Any]:
        """
        Get the audiences for the publisher.
        """
        if (
            not self.features.has_enable_lookalike()
            and not self.features.has_enable_retargeting()
            and not self.features.has_enable_exclusion_targeting()
        ):
            raise Exception(
                "Unable to retrieve audiences. Lookalike, Retargeting or Exclusion Targeting must be enabled."
            )

        get_audiences_for_publisher_computation = GetAudiencesForPublisherComputation(
            dcr_id=self.id, client=self.client, session=self.session
        )
        return get_audiences_for_publisher_computation.run_and_get_results()

    def get_audiences_for_advertiser(self) -> Dict[str, Any]:
        """
        Get the audiences for the advertiser.
        """
        if (
            not self.features.has_enable_lookalike()
            and not self.features.has_enable_retargeting()
            and not self.features.has_enable_exclusion_targeting()
        ):
            raise Exception(
                "Unable to retrieve audience. Lookalike, Retargeting or Exclusion Targeting must be enabled."
            )

        get_audiences_for_advertiser_computation = GetAudiencesForAdvertiserComputation(
            dcr_id=self.id, client=self.client, session=self.session
        )
        return get_audiences_for_advertiser_computation.run_and_get_results()

    def get_available_audiences(self) -> Dict[str, Any]:
        """
        Get the available audiences for the advertiser.
        """
        if (
            not self.features.has_enable_lookalike()
            and not self.features.has_enable_retargeting()
            and not self.features.has_enable_exclusion_targeting()
        ):
            raise Exception(
                "Unable to retrieve audience. Lookalike, Retargeting or Exclusion Targeting must be enabled."
            )

        get_available_audiences_computation = AvailableAudiencesComputation(
            dcr_id=self.id, client=self.client, session=self.session
        )
        return get_available_audiences_computation.run_and_get_results()

    def get_audience_user_list(
        self,
        activated_audience: Audience,
    ) -> List[str]:
        """
        Get the audience user list.
        """
        get_audience_user_list_computation = GetAudienceUserListComputation(
            dcr_id=self.id,
            audience=activated_audience,
            client=self.client,
            session=self.session,
        )
        return get_audience_user_list_computation.run_and_get_results()

    def get_audience_user_list_for_advertiser(
        self,
        activated_audience: Audience,
    ) -> List[str]:
        """
        Get the list of user ids for the given audience.
        This method is to be called by the advertiser and is different from `get_audience_user_list`
        in that it can be used to download user ids for audiences that have not been made available
        to the publisher.
        The Media DCR must have been created with the `enable_advertiser_audience_download` set to `true`,
        in order for this feature to work.
        """
        if not self.features.has_enable_advertiser_audience_download():
            raise Exception(
                "This Media DCR does not support downloading audiences for advertisers."
            )
        computation = GetAudienceUserListForAdvertiserComputation(
            dcr_id=self.id,
            audience=activated_audience,
            client=self.client,
            session=self.session,
        )
        return computation.run_and_get_results()

    def provision_from_data_lab(self, data_lab_id: str):
        """
        Provision the DataLab with the given ID to the Media DCR.

        **Parameters**:
        - `data_lab_id`: ID of the DataLab to provision to the Media DCR.
        """
        # First deprovision any existing datalabs before provisioning a new one.
        # This ensures that we don't get into issues with optional datasets not
        # being updated.
        self.deprovision_data_lab()

        # Check DataLab is validated
        data_lab = self.client.get_data_lab(data_lab_id)
        if not data_lab["isValidated"]:
            raise Exception("Cannot provision DataLab, not validated.")

        # Check compatibility
        hl_data_lab = data_lab["highLevelRepresentationAsString"]
        compatible = compiler.is_data_lab_compatible_with_media_insights_dcr_serialized(
            hl_data_lab, json.dumps(self.high_level)
        )
        if not compatible:
            raise Exception("DataLab is incompatible with Media DCR")

        # Provision datasets
        data_lab_datasets = self._get_data_lab_datasets_dict(data_lab)

        # Provision all existing Data Lab datasets to the DCR.
        for dataset_type, dataset in data_lab_datasets.items():
            if not dataset:
                # Dataset was not provisioned to the Data Lab.
                continue
            manifest_hash = dataset["manifestHash"]
            encryption_key = self.client.get_dataset_key(manifest_hash)
            if dataset_type == "MATCHING_DATA":
                request_key = "publishPublisherUsersDataset"
            elif dataset_type == "SEGMENTS_DATA":
                request_key = "publishSegmentsDataset"
            elif dataset_type == "DEMOGRAPHICS_DATA":
                request_key = "publishDemographicsDataset"
            elif dataset_type == "EMBEDDINGS_DATA":
                request_key = "publishEmbeddingsDataset"
            else:
                raise Exception(
                    f"Failed to provision Data Lab. Dataset type '{dataset_type}' unknown."
                )
            self._send_publish_dataset_request(
                request_key, manifest_hash, encryption_key
            )

        # Update DB.
        provisioned_data_lab_id = self.client._provision_data_lab_to_midcr(
            self.id, data_lab_id
        )["id"]
        if provisioned_data_lab_id != data_lab_id:
            raise Exception(
                f"Incorrectly provisioned DataLab {provisioned_data_lab_id}"
            )

    def _send_publish_dataset_request(
        self, request_key: str, manifest_hash: str, encryption_key: Key
    ):
        request = MediaInsightsRequest.model_validate(
            {
                request_key: {
                    "dataRoomIdHex": self.id,
                    "datasetHashHex": manifest_hash,
                    "encryptionKeyHex": encryption_key.material.hex(),
                    "scopeIdHex": self.client._ensure_dcr_data_scope(self.id),
                },
            }
        )
        response = Request.send(request, self.session)
        if request_key not in response.model_dump_json():
            raise Exception(f'Failed to publish "{request_key}"')

    # This function should not throw on repeated calls. This allows it to be
    # called when provisioning also (where there may not yet be any data provisioned).
    def deprovision_data_lab(self):
        """
        Deprovision a DataLab from the Media DCR.
        """
        # Get a list of published datasets
        request = MediaInsightsRequest.model_validate(
            {
                "retrievePublishedDatasets": {
                    "dataRoomIdHex": self.id,
                },
            }
        )
        response = Request.send(request, self.session)
        datasets = response.model_dump()["retrievePublishedDatasets"]
        if datasets["publisherDatasetHashHex"]:
            request_key = "unpublishPublisherUsersDataset"
        elif datasets["segmentsDatasetHashHex"]:
            request_key = "unpublishSegmentsDataset"
        elif datasets["demographicsDatasetHashHex"]:
            request_key = "unpublishDemographicsDataset"
        elif datasets["embeddingsDatasetHashHex"]:
            request_key = "unpublishEmbeddingsDataset"
        else:
            request_key = None

        if request_key:
            self._send_unpublish_dataset_request(request_key)
            # Update DB.
            data_lab = self.client._deprovision_data_lab_from_midcr(self.id)
            if data_lab:
                raise Exception("DataLab should have been deprovisioned")

    def _send_unpublish_dataset_request(self, request_key: str):
        request = MediaInsightsRequest.model_validate(
            {
                request_key: {
                    "dataRoomIdHex": self.id,
                },
            }
        )
        response = Request.send(request, self.session)
        if request_key not in response.model_dump_json():
            raise Exception(f"Failed to unpublish {request_key}")

    def _get_data_lab_datasets_dict(self, data_lab: compiler.DataLab):
        datasets_dict = {}
        for dataset in data_lab["datasets"]:
            datasets_dict[dataset["name"]] = dataset["dataset"]
        return datasets_dict

    @classmethod
    def _from_existing(
        cls,
        dcr_id: str,
        *,
        client: Client,
        enclave_specs: Optional[List[EnclaveSpecification]] = None,
    ) -> Self:
        """
        Construct a Media DCR from an existing DCR with the given ID.

        **Parameters**:
        - `dcr_id`: ID of the Media DCR.
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

    def activate_audience(
        self,
        audiences: List[Audience],
    ):
        """
        Activate the list of audiences, making it accessible to the Publisher if they are published.
        The Publisher will be able to download the user ids belonging to all the audiences, for which the is_published flag is set to True.

        **Parameters**:
        - `audiences`: List of audiences that should be made available to the Publisher.
        """
        audiences_list = self._create_activated_audiences_list(audiences)
        activate_audience_list_json = json.dumps(
            {
                "advertiser_manifest_hash": self._get_advertiser_manifest_hash(),
                "activated_audiences": [
                    audience.as_dict() for audience in audiences_list
                ],
            }
        )
        key = Key()
        manifest_hash = self.client.upload_dataset(
            io.BytesIO(activate_audience_list_json.encode()),
            key,
            "audiences.json",
        )
        self.session.publish_dataset(
            self.id,
            manifest_hash,
            "activated_audiences.json",
            key,
        )

    # Create an activated audiences list that contains all previously
    # activated audiences together with the newly activated audiences.
    def _create_activated_audiences_list(
        self, audiences: List[Audience]
    ) -> List[Audience]:

        # Generates a dictionary key for a given audience.
        def generate_key(audience: Audience) -> str:
            if audience.reach:
                # The key for lookalike audiences.
                return f"{audience.audience_type}-{audience.activation_type.value}-{audience.reach}"
            else:
                # The key for non-lookalike audiences.
                return f"{audience.audience_type}-{audience.activation_type.value}"

        existing_audiences = self.get_audiences_for_advertiser()
        activated_audiences_dict: Dict[str, Audience] = {}

        # Store the existing audiences in a map.
        for activated_audience in existing_audiences["activated_audiences"]:
            audience = Audience.from_activated_audience(activated_audience)
            key = generate_key(audience)
            activated_audiences_dict[key] = audience

        # Ensure all new published audiences are included.
        for audience in audiences:
            key = generate_key(audience)
            activated_audience = activated_audiences_dict.get(key)
            if activated_audience:
                # Audience already exists. Update the "is_published" flag to
                # that specified by the user.
                activated_audience.is_published = audience.is_published
                activated_audiences_dict[key] = activated_audience
            else:
                # Entry doesn't exist. Add it.
                activated_audiences_dict[key] = audience
        return activated_audiences_dict.values()

    def _get_advertiser_manifest_hash(self) -> str:
        request = MediaInsightsRequest.model_validate(
            {
                "retrievePublishedDatasets": {
                    "dataRoomIdHex": self.id,
                },
            }
        )
        response = Request.send(request, self.session).model_dump()
        return response["retrievePublishedDatasets"]["advertiserDatasetHashHex"]

    def participants(self) -> Dict[str, Any]:
        """
        Retrieve the participants of the Media DCR.
        This returns a dictionary of roles (keys) mapped to participants (email addresses).
        """
        dcr = self.high_level[MEDIA_DCR_WRAPPER_SUPPORTED_VERSION]
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
        }


def _get_features(high_level: Dict[str, Any]) -> MediaInsightFeatures:
    features = compiler.get_media_insights_dcr_features_serialized(
        json.dumps(high_level)
    )
    return MediaInsightFeatures(features)
