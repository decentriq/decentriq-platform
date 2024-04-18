import hashlib
import io
import json
import numbers
import zipfile
from enum import Enum
from typing import Dict, List, Optional, Tuple

from decentriq_dcr_compiler import (
    LookalikeMediaDataRoom,
    LookalikeMediaRequest,
    LookalikeMediaResponse,
    compiler,
)

from ..channel import Channel
from ..client import Client
from ..helpers import get_latest_enclave_specs_as_dictionary
from ..keychain import Keychain, KeychainEntry
from ..proto import (
    CreateDcrKind,
    DataRoom,
    GcgRequest,
    UserAuth,
    parse_length_delimited,
    serialize_length_delimited,
)
from ..session import LATEST_GCG_PROTOCOL_VERSION, Session
from ..storage import Key
from ..types import (
    CreateMediaComputeJobInput,
    EnclaveSpecification,
    JobId,
    OverlapInsightsCacheKey,
    PublishedDataset,
)

__docformat__ = "restructuredtext"


__all__ = [
    "LookalikeMediaDcr",
]


class DatasetType(Enum):
    MATCHING = "matching"
    SEGMENTS = "segments"
    DEMOGRAPHICS = "demographics"
    EMBEDDINGS = "embeddings"
    AUDIENCES = "audiences"


class ExistingLookalikeMediaDcr:
    def __init__(self, id: str, driver_spec: EnclaveSpecification) -> None:
        self.id = id
        self.driver_enclave_spec = {"decentriq.driver": driver_spec}


class LookalikeMediaDcr:
    def __init__(
        self,
        client: Client,
        high_level_representation: str,
        existing_lookalike_media_dcr: Optional[ExistingLookalikeMediaDcr] = None,
    ) -> None:
        self.client = client
        if existing_lookalike_media_dcr:
            self.auth, _ = client.create_auth_using_decentriq_pki(
                existing_lookalike_media_dcr.driver_enclave_spec
            )
            self.session = client.create_session(
                self.auth, existing_lookalike_media_dcr.driver_enclave_spec
            )
            self.hl_lmdcr = LookalikeMediaDataRoom.model_validate(
                high_level_representation
            )
            self.id = existing_lookalike_media_dcr.id
        else:
            enclave_specs = get_latest_enclave_specs_as_dictionary(self.client)
            self.auth, _ = client.create_auth_using_decentriq_pki(enclave_specs)
            self.session = client.create_session(self.auth, enclave_specs)
            (self.hl_lmdcr, self.id) = self._create_lmdcr(high_level_representation)
        self.overlap_insights_job = None

    @staticmethod
    def send_request(
        lmdcr_request: LookalikeMediaRequest,
        session: Session,
    ) -> LookalikeMediaResponse:
        def compile_request(lmdcr_request: LookalikeMediaRequest, channel: Channel):
            user_auth = channel._get_message_auth(session.auth)
            request_serialized = compiler.compile_lookalike_media_request_serialized(
                lmdcr_request,
                serialize_length_delimited(user_auth),
            )
            return bytes(request_serialized)

        def decompile_response(responses: List[bytes]) -> LookalikeMediaResponse:
            if len(responses) != 1:
                raise Exception("Malformed response")
            response = compiler.decompile_lookalike_media_response(
                lmdcr_request, bytes(responses[0])
            )
            return response

        response = session.send_compilable_request(
            compile_request,
            lmdcr_request,
            decompile_response,
            LATEST_GCG_PROTOCOL_VERSION,
        )
        return response

    def _create_lmdcr(
        self, high_level_representation: str
    ) -> Tuple[LookalikeMediaDataRoom, str]:
        create_lmdcr = compiler.CreateLookalikeMediaDataRoom.model_validate(
            high_level_representation
        )
        lmdcr = compiler.create_lookalike_media_data_room(create_lmdcr)
        lmdcr_serialised = compiler.compile_lookalike_media_data_room(lmdcr)
        low_level_dcr = DataRoom()
        parse_length_delimited(lmdcr_serialised, low_level_dcr)
        lmdcr_id = self.session.publish_data_room(
            low_level_dcr,
            kind=CreateDcrKind.LOOKALIKE_MEDIA,
            high_level_representation=lmdcr.json().encode(),
        )
        return (lmdcr, lmdcr_id)

    def provision_from_data_lab(self, data_lab_id: str, keychain: Keychain):
        """
        Provision the DataLab with the given ID to the Lookalike Media DCR.

        **Parameters**:
        - `data_lab_id`: ID of the DataLab to provision to the Lookalike Media DCR.
        - `keychain`: Keychain to use to provision datasets from the DataLab.
        """
        # Check DataLab is validated
        data_lab = self.client.get_data_lab(data_lab_id)
        if not data_lab["isValidated"]:
            raise Exception("Cannot provision DataLab, not validated.")

        # Check compatibility
        hl_data_lab = data_lab["highLevelRepresentationAsString"]
        compatible = (
            compiler.is_data_lab_compatible_with_lookalike_media_data_room_serialized(
                hl_data_lab, self.hl_lmdcr.json()
            )
        )
        if not compatible:
            raise Exception("DataLab is incompatible with Lookalike Media DCR")

        # Provision datasets
        lmdcr_datasets = compiler.get_consumed_datasets(self.hl_lmdcr.json())
        data_lab_datasets = self._get_data_lab_datasets_dict(data_lab)

        # Check all required datasets can be provisioned by the DataLab before
        # actually provisioning. This is necessary because we could otherwise
        # provision only some of the datasets resulting in a "broken" LMDCR.
        for required_dataset in lmdcr_datasets.required:
            if not data_lab_datasets[required_dataset]["manifestHash"]:
                # The manifest hash of the dataset could not be found in the database.
                raise Exception(
                    f"Unable to provision the required dataset '{required_dataset}' from the DataLab."
                )

        # Provision all required datasets.
        for required_dataset in lmdcr_datasets.required:
            lmdcr_node_name = self._get_lmdcr_node_name(required_dataset)
            manifest_hash = data_lab_datasets[required_dataset]["manifestHash"]
            retrieved_key = keychain.get("dataset_key", manifest_hash)
            self.session.publish_dataset(
                self.id, manifest_hash, lmdcr_node_name, Key(retrieved_key.value)
            )

        # Provision optional datasets if the DataLab is able to.
        for optional_dataset in lmdcr_datasets.optional:
            if (
                optional_dataset not in data_lab_datasets
                or not data_lab_datasets[optional_dataset]
            ):
                # If we can't provision the dataset, move on to the next.
                continue
            lmdcr_node_name = self._get_lmdcr_node_name(optional_dataset)
            manifest_hash = data_lab_datasets[optional_dataset]["manifestHash"]
            retrieved_key = keychain.get("dataset_key", manifest_hash)
            self.session.publish_dataset(
                self.id, manifest_hash, lmdcr_node_name, Key(retrieved_key.value)
            )

        # Update DB.
        provisioned_data_lab_id = self.client._provision_data_lab(self.id, data_lab_id)[
            "id"
        ]
        if provisioned_data_lab_id != data_lab_id:
            raise Exception(
                f"Incorrectly provisioned DataLab {provisioned_data_lab_id}"
            )

    def deprovision_data_lab(self):
        """
        Deprovision a DataLab from the Lookalike Media DCR.
        """
        lmdcr_datasets = compiler.get_consumed_datasets(self.hl_lmdcr.json())
        # Deprovision all required datasets.
        for required_dataset in lmdcr_datasets.required:
            lmdcr_node_name = self._get_lmdcr_node_name(required_dataset)
            self.session.remove_published_dataset(self.id, lmdcr_node_name)

        # Deprovision optional datasets.
        for optional_dataset in lmdcr_datasets.optional:
            lmdcr_node_name = self._get_lmdcr_node_name(optional_dataset)
            self.session.remove_published_dataset(self.id, lmdcr_node_name)

        # Update DB.
        data_lab = self.client._deprovision_data_lab(self.id)
        if data_lab:
            raise Exception("DataLab should have been deprovisioned")

    def _get_data_lab_datasets_dict(self, data_lab: compiler.DataLab):
        datasets_dict = {}
        for dataset in data_lab["datasets"]:
            datasets_dict[dataset["name"]] = dataset["dataset"]
        return datasets_dict

    def _get_lmdcr_node_name(self, dataset_name: str):
        lmdcr_node_name = (
            compiler.get_lookalike_media_node_names_from_data_lab_data_type(
                dataset_name
            )
        )
        if not lmdcr_node_name:
            raise Exception(f"Unknown LMDCR node name for dataset name {dataset_name}")
        return lmdcr_node_name

    def generate_insights(self):
        """
        Run the overlap insights computation.
        Use the `get_overlap_insights` method to retrieve the results of this computation.
        """
        if not self._has_insights_generation_support():
            raise Exception("LMDCR does not support insights generation")

        scope_id = self.client._ensure_dcr_data_scope(self.id)
        lmdcr_request = LookalikeMediaRequest.parse_obj(
            {
                "calculateOverlapInsights": {
                    "dataRoomIdHex": self.id,
                    "scopeIdHex": scope_id,
                }
            }
        )
        response = LookalikeMediaDcr.send_request(lmdcr_request, self.session)
        response_json = json.loads(response.json())
        job_id_hex = response_json["calculateOverlapInsights"]["jobIdHex"]
        cache_key = self._get_overlap_insights_cache_key_string()
        input = CreateMediaComputeJobInput(
            publishedDataRoomId=self.id,
            computeNodeName="consentless_overlap_insights",
            cacheKey=cache_key,
            jobType="LOOKALIKE_MEDIA_OVERLAP_INSIGHTS",
            jobIdHex=job_id_hex,
        )
        self.overlap_insights_job = self.client._create_media_compute_job(input)

    def _has_insights_generation_support(self) -> bool:
        features = self._get_features()
        return "GENERATE_INSIGHTS_COMPUTATION" in features

    def _get_features(self):
        features = compiler.get_lookalike_media_data_room_features(self.hl_lmdcr)
        return features

    def _get_overlap_insights_cache_key_string(self) -> str:
        published_datasets = self.session.retrieve_published_datasets(
            self.id
        ).publishedDatasets
        cache_key = self._generate_overlap_insights_cache_key(published_datasets)
        return self._compute_cache_key_string(cache_key)

    def _generate_overlap_insights_cache_key(
        self, published_datasets
    ) -> OverlapInsightsCacheKey:
        cache_key = OverlapInsightsCacheKey(dataRoomId=self.id)
        published_datasets_list: List[PublishedDataset] = []
        for dataset in published_datasets:
            published_dataset = PublishedDataset(
                leafId=dataset.leafId,
                user=dataset.user,
                timestamp=dataset.timestamp,
                datasetHash=bytearray(dataset.datasetHash),
            )
            published_datasets_list.append(published_dataset)

            node_id = dataset.leafId
            dataset_hash = dataset.datasetHash.hex()
            if node_id == "audiences":
                cache_key["advertiserDatasetHash"] = dataset_hash
            elif node_id == "matching":
                cache_key["publisherUsersDatasetHash"] = dataset_hash
            elif node_id == "segments":
                cache_key["publisherSegmentsDatasetHash"] = dataset_hash
            elif node_id == "embeddings":
                cache_key["publisherEmbeddingsDatasetHash"] = dataset_hash
            elif node_id == "demographics":
                cache_key["publisherDemographicsDatasetHash"] = dataset_hash
        cache_key["publishedDatasets"] = published_datasets_list
        return cache_key

    # TODO: Add this function to DDC so it is common between the JS and Python clients.
    #       At the moment the functionality is implemented twice, which could lead to a mismatch
    #       in behaviour.
    def _compute_cache_key_string(self, key) -> str:
        def cache_key_hashed(digest, key):
            if isinstance(key, str):
                digest.update(bytes(key, "UTF-8"))
                return
            elif isinstance(key, bool):
                digest.update(str(key))
                return
            elif isinstance(key, numbers.Number):
                digest.update(bytes(str(key), "UTF-8"))
                return
            elif isinstance(key, list):
                for element in key:
                    cache_key_hashed(digest, element)
                # Do it a second time as that is what the JS code does.
                # https://github.com/decentriq/delta/blob/c9d4c56703ccbbe9c0a2bf65daba18036d9c7aac/avato-backend/frontend/decentriq-platform/src/wrappers/ApolloWrapper/resolvers/LruCache.ts#L19-L26
                for element in key:
                    cache_key_hashed(digest, element)
                cache_key_hashed(digest, len(key))
            elif isinstance(key, bytearray):
                # Sort an index of `str` values so that we get a list similar to:
                # ['0', '1', '10', '11', '12', '13', '14', '15', '2', '3', '4', '5', '6', '7', '8', '9']
                # This sorted index list will be used to determine the order of fields to hash.
                # ** Note: The list is not numerically ordered. **
                index_list = [str(x) for x in list(range(0, len(key)))]
                sorted_index_list = [int(x) for x in sorted(index_list)]
                for index in sorted_index_list:
                    cache_key_hashed(digest, key[index])
            elif isinstance(key, dict):
                for field in dict(sorted(key.items())):
                    cache_key_hashed(digest, key[field])
                return
            elif isinstance(key, bytes):
                digest.update(key)
            else:
                raise Exception(f"Unexpected nested key type {type(key)}, key {key}")

        if isinstance(key, str):
            return key
        digest = hashlib.sha256()
        cache_key_hashed(digest, key)
        hex_digest = digest.hexdigest()
        return hex_digest

    def get_overlap_insights(self, timeout: Optional[int] = None) -> Dict[str, str]:
        """
        Retrieve the results of running the overlap insights computation.
        """
        if not self._has_insights_generation_support():
            raise Exception("LMDCR does not support insights generation")

        input = {
            "publishedDataRoomId": self.overlap_insights_job["publishedDataRoomId"],
            "jobType": self.overlap_insights_job["jobType"],
            "cacheKey": self.overlap_insights_job["cacheKey"],
        }
        media_compute_job = self.client._get_media_compute_job(input)
        job_id = JobId(media_compute_job["jobIdHex"], "consentless_overlap_insights")
        results = self.session.get_computation_result(
            job_id, interval=5, timeout=timeout
        )
        zip = zipfile.ZipFile(io.BytesIO(results), "r")
        if "overlap.json" in zip.namelist():
            overlap_insights = zip.read("overlap.json").decode()
            report = json.loads(overlap_insights)
            return report
        else:
            raise Exception("Failed to retrieve overlap insights")

    def _upload_dataset_to_keychain(
        self, file_path: str, name: str, key: Key, keychain: Keychain
    ):
        with open(file_path, "rb") as file:
            dataset_id = self.client.upload_dataset(file, key, name)
            keychain.insert(KeychainEntry("dataset_key", dataset_id, key.material))
            return dataset_id

    def retrieve_audit_log(self) -> str:
        """
        Retrieve the Lookalike Media DCR audit log.
        """
        return self.session.retrieve_audit_log(self.id).log.decode("utf-8")


# Allow provisioning a dataset directly to a Lookalike Media DCR.
# This is not intended for end users. They should use the `provision_from_data_lab` method instead.
def provision_dataset(
    data: io.BytesIO,
    *,
    name: str,
    session: Session,
    key: Key,
    data_room_id: str,
    dataset_type: DatasetType,
    store_in_keychain: Optional[Keychain] = None,
    description: str = "",
) -> str:
    manifest_hash = session.client.upload_dataset(
        data, key, name, description=description, store_in_keychain=store_in_keychain
    )
    session.publish_dataset(
        data_room_id, manifest_hash, leaf_id=dataset_type.value, key=key
    )

    return manifest_hash
