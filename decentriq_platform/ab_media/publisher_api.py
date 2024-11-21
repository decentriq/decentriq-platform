from __future__ import annotations

import json

from typing import Any, Dict, TYPE_CHECKING, List, Union
from decentriq_dcr_compiler import compiler, ab_media as ab_media_compiler
from decentriq_dcr_compiler.schemas import AbMediaRequest
from .publisher_computations import (
    GetAudiencesForPublisherComputation,
    EstimateAudienceSizeForPublisherComputation,
    GetAudienceUserListForPublisherComputation,
    EstimateAudienceSizeForPublisherLalComputation,
    GetAudienceUserListForPublisherLalComputation,
    ComputeInsightsComputation,
)
from .helper import (
    get_parameter_payloads,
    audience_depends_on_lookalike,
)
from .audience_definitions import (
    RuleBasedAudienceDefinition,
    LookalikeAudienceDefinition,
    AdvertiserAudienceDefinition,
)
from .request import Request
from ..storage import Key

if TYPE_CHECKING:
    from ..client import Client


class PublisherApi:
    """
    Provides the API for interacting with an Audience Builder DCR as a publisher.
    """

    def __init__(self, dcr: AbMediaDcr) -> None:
        self.dcr_id = dcr.id
        self.session = dcr.session
        self.client = dcr.client
        self.high_level_dcr = dcr.high_level
        self.features = dcr.features

    def get_audiences(
        self,
    ) -> List[
        Union[
            RuleBasedAudienceDefinition
            | LookalikeAudienceDefinition
            | AdvertiserAudienceDefinition
        ]
    ]:
        """
        Get the audiences for the publisher.
        """
        if (
            not self.features.has_enable_lookalike_audiences()
            and not self.features.has_enable_remarketing()
            and not self.features.has_enable_rule_based_audiences()
        ):
            raise Exception(
                "Unable to retrieve audiences. Lookalike, remarketing or rule-based features must be enabled."
            )

        audiences_dict = self._request_audiences()
        audiences = []
        for a in audiences_dict["audiences"]:
            if a["kind"] == "rulebased":
                audiences.append(
                    RuleBasedAudienceDefinition.from_dict(
                        a, audiences_dict["audiences"]
                    )
                )
            elif a["kind"] == "lookalike":
                audiences.append(
                    LookalikeAudienceDefinition.from_dict(
                        a, audiences_dict["audiences"]
                    )
                )
            elif a["kind"] == "advertiser":
                audiences.append(
                    AdvertiserAudienceDefinition.from_dict(
                        a, audiences_dict["audiences"]
                    )
                )
            else:
                raise Exception(f'Audience kind "{a["kind"]}" unknown')

        return audiences

    def _request_audiences(self) -> Dict[str, Any]:
        """
        Retrieve the audiences data structure as provided by the backend.
        """
        computation = GetAudiencesForPublisherComputation(
            dcr_id=self.dcr_id, client=self.client, session=self.session
        )
        return computation.run_and_get_results()

    def estimate_audience_size(self, audience_name: str) -> int:
        """
        Estimate the audience size for the publisher.
        """
        audiences_json = self._request_audiences()
        payloads = get_parameter_payloads(
            audience_name=audience_name, audiences_json=audiences_json
        )

        if audience_depends_on_lookalike(
            audience_name=audience_name, audiences_json=audiences_json
        ):
            computation = EstimateAudienceSizeForPublisherLalComputation(
                dcr_id=self.dcr_id,
                client=self.client,
                session=self.session,
                generate_audience=payloads.generate,
                lal_audience=payloads.lal,
            )
            result = computation.run_and_get_results()
            return result["audience_size"]
        else:
            computation = EstimateAudienceSizeForPublisherComputation(
                dcr_id=self.dcr_id,
                client=self.client,
                session=self.session,
                generate_audience=payloads.generate,
            )
            result = computation.run_and_get_results()
            return result["audience_size"]

    def get_audience_user_list(self, audience_name: str) -> List[str]:
        """
        Get the audience user list for the publisher.
        """
        if (
            not self.features.has_enable_lookalike_audiences()
            and not self.features.has_enable_remarketing()
            and not self.features.has_enable_rule_based_audiences()
        ):
            raise Exception(
                "Unable to retrieve audience user list. Lookalike, remarketing or rule-based features must be enabled."
            )

        audiences_json = self._request_audiences()
        payloads = get_parameter_payloads(
            audience_name=audience_name, audiences_json=audiences_json
        )

        if audience_depends_on_lookalike(
            audience_name=audience_name, audiences_json=audiences_json
        ):
            computation = GetAudienceUserListForPublisherLalComputation(
                dcr_id=self.dcr_id,
                client=self.client,
                session=self.session,
                generate_audience=payloads.generate,
                lal_audience=payloads.lal,
            )
            return computation.run_and_get_results()
        else:
            computation = GetAudienceUserListForPublisherComputation(
                dcr_id=self.dcr_id,
                client=self.client,
                session=self.session,
                generate_audience=payloads.generate,
            )
            return computation.run_and_get_results()

    def get_insights(self) -> Dict[str, Any]:
        """
        Get the insights.
        """
        if not self.features.has_enable_insights():
            raise Exception("This Audience Builder DCR does not support insights.")

        overlap_insights_computation = ComputeInsightsComputation(
            dcr_id=self.dcr_id, client=self.client, session=self.session
        )
        return overlap_insights_computation.run_and_get_results()

    def provision_from_data_lab(self, data_lab_id: str):
        """
        Provision the DataLab with the given ID to the Audience Builder DCR.

        **Parameters**:
        - `data_lab_id`: ID of the DataLab to provision to the Audience Builder DCR.
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
        compatible = (
            ab_media_compiler.is_data_lab_compatible_with_ab_media_dcr_serialized(
                hl_data_lab, json.dumps(self.high_level_dcr)
            )
        )
        if not compatible:
            raise Exception("DataLab is incompatible with Audience Builder DCR")

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
                request_key = "publishMatchingDataset"
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
        provisioned_data_lab_id = self.client._provision_data_lab_to_ab_dcr(
            self.dcr_id, data_lab_id
        )["id"]
        if provisioned_data_lab_id != data_lab_id:
            raise Exception(
                f"Incorrectly provisioned DataLab {provisioned_data_lab_id}"
            )

    def _get_data_lab_datasets_dict(self, data_lab: compiler.DataLab):
        datasets_dict = {}
        for dataset in data_lab["datasets"]:
            datasets_dict[dataset["name"]] = dataset["dataset"]
        return datasets_dict

    def _send_publish_dataset_request(
        self, request_key: str, manifest_hash: str, encryption_key: Key
    ):
        request = AbMediaRequest.model_validate(
            {
                request_key: {
                    "dataRoomIdHex": self.dcr_id,
                    "datasetHashHex": manifest_hash,
                    "encryptionKeyHex": encryption_key.material.hex(),
                    "scopeIdHex": self.client._ensure_dcr_data_scope(self.dcr_id),
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
        Deprovision a DataLab from the Audience Builder DCR.
        """
        # Get a list of published datasets
        request = AbMediaRequest.model_validate(
            {
                "retrievePublishedDatasets": {
                    "dataRoomIdHex": self.dcr_id,
                },
            }
        )
        response = Request.send(request, self.session)
        datasets = response.model_dump()["retrievePublishedDatasets"]
        if datasets["matchingDatasetHashHex"]:
            request_key = "unpublishMatchingDataset"
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
            data_lab = self.client._deprovision_data_lab_from_ab_dcr(self.dcr_id)
            if data_lab:
                raise Exception("DataLab should have been deprovisioned")

    def _send_unpublish_dataset_request(self, request_key: str):
        request = AbMediaRequest.model_validate(
            {
                request_key: {
                    "dataRoomIdHex": self.dcr_id,
                },
            }
        )
        response = Request.send(request, self.session)
        if request_key not in response.model_dump_json():
            raise Exception(f"Failed to unpublish {request_key}")
