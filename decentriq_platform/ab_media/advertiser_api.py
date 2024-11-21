from __future__ import annotations
import io
import json
from typing import Any, BinaryIO, Dict, TYPE_CHECKING, List, Optional, Union

from ..storage import Key
from .advertiser_computations import (
    GetAudiencesForAdvertiserComputation,
    EstimateAudienceSizeForAdvertiserComputation,
    GetAudienceUserListForAdvertiserComputation,
    GetAudienceUserListForAdvertiserLalComputation,
    RetrievePublishedDatasetsComputation,
    PublishAudiencesJson,
    EstimateAudienceSizeForAdvertiserLalComputation,
    GetLookalikeAudienceStatisticsComputation,
    GetDataAttributesComputation,
)
from .helper import (
    get_parameter_payloads,
    audience_depends_on_lookalike,
    get_dependencies,
)
from .audience_definitions import (
    RuleBasedAudienceDefinition,
    LookalikeAudienceDefinition,
    AdvertiserAudienceDefinition,
    AudienceDefinitions
)
from .audience_statistics_definition import LalAudienceStatistics
from decentriq_dcr_compiler.schemas import Audience2, Audience3
from decentriq_dcr_compiler.schemas import AbMediaRequest
from .request import Request
from .version import AUDIENCES_JSON_SUPPORTED_VERSION
from .audience_definitions import AudienceStatus

if TYPE_CHECKING:
    from .ab_media import AbMediaDcr


class Attribute:
    def __init__(self, name: str, values: List[str]) -> None:
        self.name = name
        self.values = values

    def as_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "values": self.values}


class AdvertiserApi:
    """
    Provides the API for interacting with an Audience Builder DCR as an advertiser.
    """

    def __init__(self, dcr: AbMediaDcr) -> None:
        self.dcr_id = dcr.id
        self.session = dcr.session
        self.client = dcr.client
        self.features = dcr.features

    def upload_and_publish_audiences_dataset(
        self,
        data: BinaryIO,
        key: Key,
        file_name: str,
    ) -> None:
        """
        Upload the data to the Decentriq Platform and publish
        the data to the Audience Builder DCR.

        **Parameters**:
        - `data`: The data to upload and provision.
        - `key`: Key used to encrypt the file.
        - `file_name`: Name of the file.
        """
        audiences_dataset_id = self.client.upload_dataset(data, key, file_name)
        self.provision_audiences_dataset(audiences_dataset_id, key)

    def provision_audiences_dataset(self, dataset_id: str, key: Key) -> None:
        """
        Provision the audiences dataset to the Audience Builder DCR.

        **Parameters**:
        - `dataset_id`: ID of the uploaded dataset to provision to the DCR.
        - `key`: Key used to encrypt the dataset.
        """
        request_key = "publishAudiencesDataset"
        request = AbMediaRequest.model_validate(
            {
                request_key: {
                    "dataRoomIdHex": self.dcr_id,
                    "datasetHashHex": dataset_id,
                    "encryptionKeyHex": key.material.hex(),
                    "scopeIdHex": self.client._ensure_dcr_data_scope(self.dcr_id),
                },
            }
        )
        response = Request.send(request, self.session)
        if request_key not in response.model_dump_json():
            raise Exception(
                f"Failed to provision the audiences dataset to the Audience Builder DCR"
            )

    def deprovision_audiences_dataset(self) -> None:
        """
        Deprovision the audiences dataset from the Audience Builder DCR.
        """
        request_key = "unpublishAudiencesDataset"
        request = AbMediaRequest.model_validate(
            {
                request_key: {
                    "dataRoomIdHex": self.dcr_id,
                },
            }
        )
        response = Request.send(request, self.session)
        if request_key not in response.model_dump_json():
            raise Exception(
                f"Failed to deprovision the audiences dataset from the Audience Builder DCR"
            )

    def get_audiences(
        self,
    ) -> AudienceDefinitions:
        """
        Retrieve all advertiser audiences.
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
        computation = GetAudiencesForAdvertiserComputation(
            dcr_id=self.dcr_id, client=self.client, session=self.session
        )
        return computation.run_and_get_results()

    def estimate_audience_size(self, audience_name: str) -> int:
        """
        Estimate the audience size for the advertiser.

        **Parameters**:
        - `audience_name`: Name of the audience for which the estimated audience size should be retrieved.
        """
        audiences_json = self._request_audiences()
        payloads = get_parameter_payloads(
            audience_name=audience_name, audiences_json=audiences_json
        )

        if audience_depends_on_lookalike(
            audience_name=audience_name, audiences_json=audiences_json
        ):
            computation = EstimateAudienceSizeForAdvertiserLalComputation(
                dcr_id=self.dcr_id,
                client=self.client,
                session=self.session,
                generate_audience=payloads.generate,
                lal_audience=payloads.lal,
            )
            result = computation.run_and_get_results()
            return result["audience_size"]
        else:
            computation = EstimateAudienceSizeForAdvertiserComputation(
                dcr_id=self.dcr_id,
                client=self.client,
                session=self.session,
                generate_audience=payloads.generate,
            )
            result = computation.run_and_get_results()
            return result["audience_size"]

    def get_audience_user_list(self, audience_name: str) -> List[str]:
        """
        Get the list of user IDs for the advertiser.

        **Parameters**:
        - `audience_name`: Name of the audience for which the audience user list should be retrieved.
        """
        if not self.features.has_enable_advertiser_audience_download():
            raise Exception(
                "This Audience Builder DCR does not support downloading audiences for advertisers"
            )

        audiences_json = self._request_audiences()
        payloads = get_parameter_payloads(
            audience_name=audience_name, audiences_json=audiences_json
        )

        if audience_depends_on_lookalike(
            audience_name=audience_name, audiences_json=audiences_json
        ):
            computation = GetAudienceUserListForAdvertiserLalComputation(
                dcr_id=self.dcr_id,
                client=self.client,
                session=self.session,
                generate_audience=payloads.generate,
                lal_audience=payloads.lal,
            )
            return computation.run_and_get_results()
        else:
            computation = GetAudienceUserListForAdvertiserComputation(
                dcr_id=self.dcr_id,
                client=self.client,
                session=self.session,
                generate_audience=payloads.generate,
            )
            return computation.run_and_get_results()

    def make_audiences_available_to_publisher(self, audience_names: List[str]):
        """
        Make the audiences with the given names available to the Publisher.
        The Publisher will be able to download the user ids belonging to these audiences.

        **Parameters**:
        - `audience_names`: Names of the audiences to make available to the publisher.
        """
        audiences_json = self._request_audiences()
        audiences = audiences_json.pop("audiences")
        audiences_dict = {a["mutable"]["name"]: a for a in audiences}

        for audience_name in audience_names:
            if audience_name not in audiences_dict:
                raise Exception(
                    f'Audience with name "{audience_name}" not in the list of available audiences'
                )

            # Set the status of the audience to "published".
            audience_to_activate = audiences_dict[audience_name]
            audience_to_activate["mutable"]["status"] = "published"
            audiences_dict[audience_name] = audience_to_activate

        # Update the audiences in the `audiences.json`.
        audiences_json["audiences"] = [a for a in audiences_dict.values()]
        self._upload_and_publish_audiences_json(audiences_json=audiences_json)

    def add_audiences(
        self,
        audiences: list[
            LookalikeAudienceDefinition
            | RuleBasedAudienceDefinition
        ],
    ):
        """
        Add the given audiences to the current DCR.
        The audiences will only be visible to the publisher after they have been published.

        **Parameters**:
        - `audiences`: The audience definitions to add.
        """

        # Get the existing audiences.
        audiences_json = self._request_audiences()
        existing_audiences = audiences_json.pop("audiences")
        audiences_dict = {}
        for a in existing_audiences:
            audience_name = a["mutable"]["name"]
            if audience_name in audiences_dict:
                raise Exception(f'Multiple audiences with name "{audience_name}"')
            audiences_dict[audience_name] = a
        existing_audiences_by_id = {a["id"]: a for a in audiences_dict.values()}

        # Add the new audiences.
        new_audiences_by_id = {a.id: a for a in audiences}
        all_audiences = existing_audiences + [new_audience.as_dict() for new_audience in audiences]
        for audience in audiences:
            if isinstance(audience, LookalikeAudienceDefinition):
                # Additional checks for lookalike audiences.
                if not self.features.has_enable_lookalike_audiences():
                    raise Exception(
                        "This Audience Builder DCR does not support Lookalike audiences"
                    )
                if audience.reach < 0 or audience.reach > 30:
                    raise Exception(
                        "Reach value must be an integer in the range 0 - 30"
                    )

            if audience.name in audiences_dict:
                raise Exception(
                    f'Audience with name "{audience.name}" already exists in audience list'
                )

            # Check if we need to mark any of the existing dependencies as PUBLISHED_AS_INTERMEDIATE
            # in order for them to be retrievable by the publisher.
            if audience.status == AudienceStatus.PUBLISHED:
                dependency_ids = get_dependencies(audience.id, all_audiences)
                for audience_id in dependency_ids:
                    if audience_id in existing_audiences_by_id:
                        dependency = existing_audiences_by_id[audience_id]
                        if dependency["mutable"]["status"] == AudienceStatus.READY.value:
                            dependency["mutable"]["status"] = AudienceStatus.PUBLISHED_AS_INTERMEDIATE.value
                    elif audience_id in new_audiences_by_id:
                        # Check whether the dependency is added as part of the same call.
                        # If yes, then it must have a published state.
                        dependency = new_audiences_by_id[audience_id]
                        if dependency.status == AudienceStatus.READY:
                            dependency.status = AudienceStatus.PUBLISHED_AS_INTERMEDIATE
                    else:
                        raise Exception(
                            f"Unable to find audience dependency '{audience_id}' in neither the existing audiences nor the audiences to be added"
                        )

        # Loop again over the audiences and dump them in JSON format.
        # The second loop is required since some of the audiences (that are dependencies
        # of other audiences to be added) got their status changed.
        for audience in audiences:
            parsed_audience = audience._as_ddc_audience()  # parse into the DDC representation
            audiences_dict[audience.name] = parsed_audience.model_dump(mode="json")

        # Update the audiences.json.
        audiences_json["audiences"] = [a for a in audiences_dict.values()]
        self._upload_and_publish_audiences_json(audiences_json=audiences_json)

    def get_audience_attributes(self) -> List[Attribute]:
        """
        Retrieve all audience attributes.
        These attributes can be used to build new rule-based audiences.
        """
        computation = GetDataAttributesComputation(
            dcr_id=self.dcr_id,
            client=self.client,
            session=self.session,
        )
        results = computation.run_and_get_results()
        attributes = [
            Attribute(k, v["values"]) for k, v in results["attributes"].items()
        ]
        return attributes

    def get_lookalike_audience_statistics(
        self, audience_name: str
    ) -> LalAudienceStatistics:
        """
        Retrieve lookalike statistics for an audience with the given name.

        **Parameters**:
        - `audience_name`: Name of the audience whose lookalike statistics should be retrieved.
        """
        audiences_json = self._request_audiences()
        if audience_depends_on_lookalike(
            audience_name=audience_name, audiences_json=audiences_json
        ):
            raise Exception("Requested audience cannot be a Lookalike audience")

        payloads = get_parameter_payloads(
            audience_name=audience_name, audiences_json=audiences_json
        )
        computation = GetLookalikeAudienceStatisticsComputation(
            dcr_id=self.dcr_id,
            client=self.client,
            session=self.session,
            generate_audience=payloads.generate,
        )
        results = computation.run_and_get_results()
        return LalAudienceStatistics.from_dict(results)

    def _update_manifest_hashes_in_audiences_json(self, audiences_json: Dict[str, Any]):
        # Set the dataset hashes to the latest versions.
        datasets = self._retrieve_published_datasets()
        if "matchingDatasetHashHex" not in datasets:
            raise Exception("Matching dataset must be provisioned to the DCR")
        audiences_json["matching_manifest_hash"] = datasets["matchingDatasetHashHex"]
        if "segmentsDatasetHashHex" in datasets:
            audiences_json["segments_manifest_hash"] = datasets[
                "segmentsDatasetHashHex"
            ]
        if "embeddingsDatasetHashHex" in datasets:
            audiences_json["embeddings_manifest_hash"] = datasets[
                "embeddingsDatasetHashHex"
            ]
        if "demographicsDatasetHashHex" in datasets:
            audiences_json["demographics_manifest_hash"] = datasets[
                "demographicsDatasetHashHex"
            ]
        if "audiencesDatasetHashHex" in datasets:
            audiences_json["advertiser_manifest_hash"] = datasets[
                "audiencesDatasetHashHex"
            ]

    def _upload_and_publish_audiences_json(self, audiences_json: Dict[str, Any]):
        audiences_json["version"] = AUDIENCES_JSON_SUPPORTED_VERSION

        # Update the manifest hashes whenever the `audiences.json` is published.
        self._update_manifest_hashes_in_audiences_json(audiences_json=audiences_json)

        key = Key()
        manifest_hash = self.client.upload_dataset(
            io.BytesIO(json.dumps(audiences_json).encode()),
            key,
            "audiences.json",
        )
        publish_audiences_json = PublishAudiencesJson(
            dcr_id=self.dcr_id,
            manifest_hash=manifest_hash,
            encryption_key_hex=key.material.hex(),
            client=self.client,
            session=self.session,
        )
        publish_audiences_json.run()

    def _retrieve_published_datasets(self) -> Dict[str, Any]:
        """
        Get all datasets that have been published to the DCR.
        """
        retrieve_published_datasets_computation = RetrievePublishedDatasetsComputation(
            dcr_id=self.dcr_id,
            client=self.client,
            session=self.session,
        )
        return retrieve_published_datasets_computation.run_and_get_results()
