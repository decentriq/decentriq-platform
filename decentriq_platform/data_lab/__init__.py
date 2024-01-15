import base64
import io
import json
from typing import Dict, Mapping, Optional, Text
from uuid import uuid4
import uuid
import zipfile
from ..client import Client
from ..types import (
    DataLabDatasetType,
    DataLabDefinition,
    DryRunOptions,
    EnclaveSpecification,
    JobId,
    MatchingId,
    MatchingIdFormat,
    TableColumnHashingAlgorithm,
)
from decentriq_dcr_compiler import compiler
from decentriq_dcr_compiler.schemas.lookalike_media_data_room import (
    LookalikeMediaDataRoom,
)
from decentriq_dcr_compiler.schemas.create_data_lab import (
    CreateDataLab,
    CreateDataLab,
    CreateDataLabItem1,
    CreateDataLabComputeV1,
)
from ..proto import DataRoom, CreateDcrPurpose
from ..proto.length_delimited import parse_length_delimited, serialize_length_delimited
from ..storage import Key
from ..keychain import Keychain, KeychainEntry
from ..session import LATEST_GCG_PROTOCOL_VERSION, Session
from ..helpers import (
    get_latest_enclave_specs_as_dictionary,
    create_session_from_driver_spec,
)
from ..lookup_tables import MATCHING_ID_INTERNAL_LOOKUP
from pathlib import Path

__all__ = [
    "MatchingId",
    "provision_local_datasets",
    "run",
    "get_validation_report",
    "get_statistics_report",
    "provision_to_lookalike_media_data_room",
]


class Dataset:
    def __init__(self, manifest_hash: str, key: Key):
        self.manifest_hash = manifest_hash
        self.key = key


class DataLabConfig:
    def __init__(
        self,
        name: str,
        has_demographics: bool,
        has_embeddings: bool,
        num_embeddings: int,
        matching_id: MatchingId,
    ):
        self.name = name
        self.has_demographics = has_demographics
        self.has_embeddings = has_embeddings
        self.num_embeddings = num_embeddings
        self.matching_id = matching_id


class ExistingDataLab:
    def __init__(
        self,
        data_lab_definition: DataLabDefinition,
        keychain: Keychain,
    ):
        self.keychain = keychain
        self.id = data_lab_definition["id"]
        self.high_level_representation = data_lab_definition[
            "highLevelRepresentationAsString"
        ]
        self.match_dataset = data_lab_definition["usersDataset"]
        self.segments_dataset = data_lab_definition["segmentsDataset"]
        self.demographics_dataset = data_lab_definition["demographicsDataset"]
        self.embeddings_dataset = data_lab_definition["embeddingsDataset"]


class DataLab:
    def __init__(
        self,
        client: Client,
        cfg: DataLabConfig,
        existing_data_lab: ExistingDataLab = None,
    ):
        self.client = client
        enclave_specs = get_latest_enclave_specs_as_dictionary(self.client)
        auth, _ = client.create_auth_using_decentriq_pki(enclave_specs)
        self.session = client.create_session(auth, enclave_specs)
        self.cfg = cfg
        self.dcr_id = ""
        self.datasets: Dict[DataLabDatasetType, Dataset] = dict()

        if existing_data_lab:
            # Create a DataLab using the existing configuration.
            self.data_lab_id = existing_data_lab.id
            self.hl_data_lab = compiler.DataLab.parse_obj(
                json.loads(existing_data_lab.high_level_representation)
            )
            self._populate_datasets_cache_from_existing(existing_data_lab)
        else:
            # Create a new DataLab.
            self.data_lab_id = f"DataLab-{str(uuid.uuid4())}"
            (
                matching_id_format,
                matching_id_hashing_algorithm,
            ) = MATCHING_ID_INTERNAL_LOOKUP[self.cfg.matching_id]
            create_data_lab = CreateDataLab(
                __root__=CreateDataLabItem1(
                    v1=CreateDataLabComputeV1(
                        authenticationRootCertificatePem=self.client.decentriq_ca_root_certificate.decode(),
                        driverEnclaveSpecification=EnclaveSpecification(
                            attestationProtoBase64="",
                            id="",
                            workerProtocol=0,
                        ),
                        hasDemographics=self.cfg.has_demographics,
                        hasEmbeddings=self.cfg.has_embeddings,
                        id=self.data_lab_id,
                        matchingIdFormat=matching_id_format,
                        matchingIdHashingAlgorithm=matching_id_hashing_algorithm,
                        name=self.cfg.name,
                        numEmbeddings=self.cfg.num_embeddings,
                        publisherEmail=self.client.user_email,
                        pythonEnclaveSpecification=EnclaveSpecification(
                            attestationProtoBase64="",
                            id="",
                            workerProtocol=0,
                        ),
                    ),
                )
            )
            self.hl_data_lab = compiler.create_data_lab(create_data_lab)
            self.data_lab_id = self.client._publish_data_lab_from_existing(
                json.loads(self.hl_data_lab.json())
            )

    def _populate_datasets_cache_from_existing(
        self, existing_data_lab: ExistingDataLab
    ):
        keychain = existing_data_lab.keychain
        match_dataset = existing_data_lab.match_dataset
        if match_dataset is not None:
            manifest_hash = match_dataset["manifestHash"]
            key = keychain.get("dataset_key", manifest_hash)
            self.datasets[DataLabDatasetType.MATCH] = Dataset(
                manifest_hash, Key(key.value)
            )

        segments_dataset = existing_data_lab.segments_dataset
        if segments_dataset is not None:
            manifest_hash = segments_dataset["manifestHash"]
            key = keychain.get("dataset_key", manifest_hash)
            self.datasets[DataLabDatasetType.SEGMENTS] = Dataset(
                manifest_hash, Key(key.value)
            )

        demographics_dataset = existing_data_lab.demographics_dataset
        if self.cfg.has_demographics and demographics_dataset is not None:
            manifest_hash = demographics_dataset["manifestHash"]
            key = keychain.get("dataset_key", manifest_hash)
            self.datasets[DataLabDatasetType.DEMOGRAPHICS] = Dataset(
                manifest_hash, Key(key.value)
            )

        embeddings_dataset = existing_data_lab.embeddings_dataset
        if self.cfg.has_embeddings and embeddings_dataset is not None:
            manifest_hash = embeddings_dataset["manifestHash"]
            key = keychain.get("dataset_key", manifest_hash)
            self.datasets[DataLabDatasetType.EMBEDDINGS] = Dataset(
                manifest_hash, Key(key.value)
            )

    def _get_data_lab_enclave_specs(
        self,
        enclave_specs: Dict[str, EnclaveSpecification],
    ) -> (EnclaveSpecification, EnclaveSpecification):
        driver_spec = {}
        python_spec = {}
        for spec_id, spec in enclave_specs.items():
            spec_payload = {
                "attestationProtoBase64": base64.b64encode(
                    serialize_length_delimited(spec["proto"])
                ).decode(),
                "id": spec_id,
                "workerProtocol": spec["workerProtocols"][0],
            }
            if "decentriq.driver" in spec_id:
                spec["clientProtocols"] = [LATEST_GCG_PROTOCOL_VERSION]
                driver_spec = compiler.EnclaveSpecification.parse_obj(spec_payload)
            elif "decentriq.python-ml-worker" in spec_id:
                spec["clientProtocols"] = [LATEST_GCG_PROTOCOL_VERSION]
                python_spec = compiler.EnclaveSpecification.parse_obj(spec_payload)
        return (driver_spec, python_spec)

    def provision_local_datasets(
        self,
        key: Key,
        keychain: Keychain,
        matching_data_path: str,
        segments_data_path: str,
        demographics_data_path: Optional[str] = None,
        embeddings_data_path: Optional[str] = None,
    ):
        """
        Upload local datasets to the keychain and provision to the DataLab.

        **Parameters**
        - `key`: The key used to encrypt the dataset.
        - `keychain`: The keychain where the key will be stored.
        - `match`: The file path to the "match" dataset.
        - `segments`: The file path to the "segments" dataset.
        - `demographics`: The file path to the "demographics" dataset.
        - `embeddings`: The file path to the "embeddings" dataset.
        """
        if matching_data_path is not None:
            dataset_name = Path(matching_data_path).stem
            dataset_id = self._upload_dataset_to_keychain(
                matching_data_path, dataset_name, key, keychain
            )
            self.provision_dataset(dataset_id, key, DataLabDatasetType.MATCH)
        if segments_data_path is not None:
            dataset_name = Path(segments_data_path).stem
            dataset_id = self._upload_dataset_to_keychain(
                segments_data_path, dataset_name, key, keychain
            )
            self.provision_dataset(dataset_id, key, DataLabDatasetType.SEGMENTS)
        if embeddings_data_path is not None:
            dataset_name = Path(embeddings_data_path).stem
            self._check_dataset_type_permitted(
                dataset_type=DataLabDatasetType.EMBEDDINGS
            )
            dataset_id = self._upload_dataset_to_keychain(
                embeddings_data_path, dataset_name, key, keychain
            )
            self.provision_dataset(dataset_id, key, DataLabDatasetType.EMBEDDINGS)
        if demographics_data_path is not None:
            dataset_name = Path(demographics_data_path).stem
            self._check_dataset_type_permitted(
                dataset_type=DataLabDatasetType.DEMOGRAPHICS
            )
            dataset_id = self._upload_dataset_to_keychain(
                demographics_data_path, dataset_name, key, keychain
            )
            self.provision_dataset(dataset_id, key, DataLabDatasetType.DEMOGRAPHICS)

    def _upload_dataset_to_keychain(
        self, file_path: str, name: str, key: Key, keychain: Keychain
    ):
        with open(file_path, "rb") as file:
            dataset_id = self.client.upload_dataset(file, key, name)
            keychain.insert(KeychainEntry("dataset_key", dataset_id, key.material))
            return dataset_id

    def provision_dataset(
        self, manifest_hash: str, key: Key, dataset_type: DataLabDatasetType
    ):
        self._check_dataset_type_permitted(dataset_type=dataset_type)

        if dataset_type == DataLabDatasetType.EMBEDDINGS:
            self.client._set_datalab_embeddings_dataset(self.data_lab_id, manifest_hash)
        elif dataset_type == DataLabDatasetType.DEMOGRAPHICS:
            self.client._set_datalab_demographics_dataset(
                self.data_lab_id, manifest_hash
            )
        elif dataset_type == DataLabDatasetType.MATCH:
            self.client._set_datalab_matching_dataset(self.data_lab_id, manifest_hash)
        elif dataset_type == DataLabDatasetType.SEGMENTS:
            self.client._set_datalab_segments_dataset(self.data_lab_id, manifest_hash)
        else:
            raise Exception(f"Unknown dataset type {dataset_type}")

        # Store the provisioned datasets in the local cache.
        self.datasets[dataset_type] = Dataset(manifest_hash, key)

    def deprovision_dataset(self, dataset_type: DataLabDatasetType):
        self._check_dataset_type_permitted(dataset_type=dataset_type)

        # Sending "None" as the manifest hash causes the dataset to be deprovisioned.
        if dataset_type == DataLabDatasetType.EMBEDDINGS:
            self.client._set_datalab_embeddings_dataset(self.data_lab_id, None)
        elif dataset_type == DataLabDatasetType.DEMOGRAPHICS:
            self.client._set_datalab_demographics_dataset(self.data_lab_id, None)
        elif dataset_type == DataLabDatasetType.MATCH:
            self.client._set_datalab_matching_dataset(self.data_lab_id, None)
        elif dataset_type == DataLabDatasetType.SEGMENTS:
            self.client._set_datalab_segments_dataset(self.data_lab_id, None)
        else:
            raise Exception(f"Unknown dataset type {dataset_type}")

    def _check_dataset_type_permitted(self, dataset_type: DataLabDatasetType):
        if dataset_type == DataLabDatasetType.EMBEDDINGS:
            if not self.cfg.has_embeddings:
                raise Exception("Embeddings not enabled")
        elif dataset_type == DataLabDatasetType.DEMOGRAPHICS:
            if not self.cfg.has_demographics:
                raise Exception("Demographics not enabled")

    def run(
        self,
        /,
        *,
        dry_run: Optional[DryRunOptions] = None,
        parameters: Optional[Mapping[Text, Text]] = None,
    ):
        """
        Running the DataLab results in the validation jobs and statistics job being kicked off. 
        This function does not block waiting for the results. Instead the user should call the 
        `get_validation_report` or `get_statistics_report` function.
        """
        features = self._get_features()
        if "COMPUTE_STATISTICS" not in features:
            raise Exception("DataLab does not support computing statistics")

        self._update_enclave_specs()
        self.dcr_id = self._construct_backing_dcr(self.session)
        for dataset_type, dataset in self.datasets.items():
            node_name = self._get_data_lab_node_names(dataset_type)
            self.session.publish_dataset(
                self.dcr_id, dataset.manifest_hash, node_name, dataset.key
            )
        # Start validation jobs
        validation_job_id = self.session._submit_compute(
            self.dcr_id,
            self._get_validation_nodes(),
            dry_run=dry_run,
            parameters=parameters,
        ).jobId.hex()
        # Start statistics job
        statistics_job_id = self.session._submit_compute(
            self.dcr_id, ["publisher_data_statistics"]
        ).jobId.hex()

        self.client._set_datalab_job_ids(
            self.data_lab_id,
            validation_job_id,
            statistics_job_id,
            self.session.driver_attestation_specification_hash,
        )

    def get_validation_report(self, timeout: int = None):
        """
        Retrieve the validation report. This function will block until the report is ready unless a timeout is specified.

        **Parameters**:
        - `timeout`: Amount of time to wait (in seconds) for the validation report to become available.
        """
        data_lab = self.client.get_data_lab(self.data_lab_id)

        # A validation report is not stored in the DB if statistics have already been produced.
        if data_lab["statistics"]:
            raise Exception(
                "Cannot retrieve validation report. Statistics already calculated."
            )

        driver_attestation_hash = data_lab["jobsDriverAttestationHash"]
        if not driver_attestation_hash:
            raise Exception("Driver attestation spec not found")

        validation_compute_job_id = data_lab["validationComputeJobId"]
        if not validation_compute_job_id:
            raise Exception(
                "Validation compute job ID not found. Please run the DataLab."
            )

        driver_spec = self.client._get_enclave_spec_from_hash(driver_attestation_hash)
        if not driver_spec:
            raise Exception(f"Failed to find driver for data lab {self.data_lab_id}")

        session = create_session_from_driver_spec(self.client, driver_spec)
        validation_nodes = self._get_validation_nodes()
        session.wait_until_computation_has_finished_for_all_compute_nodes(
            validation_compute_job_id, validation_nodes, timeout=timeout
        )
        # Get individual reports
        validation_reports = {}
        for node in validation_nodes:
            job_id = JobId(validation_compute_job_id, node)
            result = session.get_computation_result(job_id, timeout=timeout)
            zip = zipfile.ZipFile(io.BytesIO(result), "r")
            if "validation-report.json" in zip.namelist():
                validation_reports[
                    node.removesuffix("_validation_report")
                ] = json.loads(zip.read("validation-report.json").decode())
        return validation_reports

    def get_statistics_report(self, timeout: int = None):
        """
        Retrieve the statistics report. This function will block until the report is ready unless a timeout is specified.

        **Parameters**:
        - `timeout`: Amount of time to wait (in seconds) for the statistics report to become available.
        """
        features = self._get_features()
        if "COMPUTE_STATISTICS" not in features:
            raise Exception("DataLab does not support computing statistics")

        data_lab = self.client.get_data_lab(self.data_lab_id)
        if data_lab["statistics"]:
            # If we already have the statistics, return them.
            return data_lab["statistics"]

        statistics_compute_job_id = data_lab["statisticsComputeJobId"]
        if not statistics_compute_job_id:
            raise Exception(
                "Statistics compute job ID not found. Please run the DataLab."
            )

        driver_attestation_hash = data_lab["jobsDriverAttestationHash"]
        if not driver_attestation_hash:
            raise Exception("Driver attestation spec not found")

        driver_spec = self.client._get_enclave_spec_from_hash(driver_attestation_hash)
        if not driver_spec:
            raise Exception(f"Failed to find driver for data lab {self.data_lab_id}")

        session = create_session_from_driver_spec(self.client, driver_spec)
        job_id = JobId(statistics_compute_job_id, "publisher_data_statistics")
        results = session.get_computation_result(job_id, interval=5, timeout=timeout)
        zip = zipfile.ZipFile(io.BytesIO(results), "r")
        if "statistics.json" in zip.namelist():
            statistics = zip.read("statistics.json").decode()
            # Store the statistics.
            self.client._set_datalab_statistics(self.data_lab_id, statistics)
            report = json.loads(statistics)
            return report
        else:
            raise Exception("Failed to retrieve statistics")

    def provision_to_lookalike_media_data_room(
        self, data_room_id: str, keychain: Keychain
    ):
        """
        Provision the DataLab to the DCR with the given ID.

        **Parameters**:
        - `data_room_id`: ID of the DCR to provision the DataLab to.
        - `keychain`: Keychain to use to provision the datasets.
        """
        # DataLab must be validated before it can be provisioned.
        if not self._validated():
            # Retrieve and store the statistics. This will validate the DataLab.
            self.get_statistics_report()
            # Check again if the DataLab is validated.
            if not self._validated():
                raise Exception("Can't provision to DCR. DataLab not validated.")

        # Check DataLab and LMDCR are compatible.
        lmdcr, lmdcr_session = self._get_lmdcr(data_room_id)
        compatible = compiler.is_data_lab_compatible_with_lookalike_media_data_room(
            self.hl_data_lab, lmdcr
        )
        if not compatible:
            raise Exception("DataLab is incompatible with DCR")

        lmdcr_datasets = compiler.get_consumed_datasets(lmdcr)
        data_lab = self.client.get_data_lab(self.data_lab_id)
        data_lab_datasets = self._get_data_lab_datasets_dict(data_lab)
        # Check all required datasets can be provisioned by the DataLab before
        # actually provisioning. This is necessary because we could otherwise
        # provision only some of the datasets resulting in a "broken" LMDCR.
        for required_dataset in lmdcr_datasets.required:
            if not data_lab_datasets[required_dataset]["manifestHash"]:
                raise Exception(
                    f"DataLab does not provide the required dataset {required_dataset}"
                )

        # Provision all required datasets.
        for required_dataset in lmdcr_datasets.required:
            lmdcr_node_name = self._get_lmdcr_node_name(required_dataset)
            manifest_hash = data_lab_datasets[required_dataset]["manifestHash"]
            retrieved_key = keychain.get("dataset_key", manifest_hash)
            lmdcr_session.publish_dataset(
                data_room_id, manifest_hash, lmdcr_node_name, Key(retrieved_key.value)
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
            lmdcr_session.publish_dataset(
                data_room_id, manifest_hash, lmdcr_node_name, Key(retrieved_key.value)
            )

    @staticmethod
    def is_validation_passed(validation_report: Dict[str, str]) -> bool:
        return (
            validation_report["dataset_users"]["report"]["outcome"] == "PASSED"
            and validation_report["dataset_segments"]["report"]["outcome"] == "PASSED"
            and validation_report["dataset_embeddings"]["report"]["outcome"] == "PASSED"
            and validation_report["dataset_demographics"]["report"]["outcome"]
            == "PASSED"
        )

    def _validated(self) -> bool:
        data_lab = self.client.get_data_lab(self.data_lab_id)
        return data_lab["isValidated"]

    def _get_data_lab_datasets_dict(self, data_lab: compiler.DataLab):
        datasets_dict = {}
        for dataset in data_lab["datasets"]:
            datasets_dict[dataset["name"]] = dataset["dataset"]
        return datasets_dict

    def _get_lmdcr(self, data_room_id) -> (LookalikeMediaDataRoom, Session):
        # Get the high level representation of the LMDCR.
        lmdcr_driver_attestation_hash = self.client._get_lmdcr_driver_attestation_hash(
            data_room_id
        )
        lmdcr_driver_spec = self.client._get_enclave_spec_from_hash(
            lmdcr_driver_attestation_hash
        )
        if lmdcr_driver_spec == None:
            raise Exception(f"Failed to find driver for data room {data_room_id}")

        session = create_session_from_driver_spec(self.client, lmdcr_driver_spec)
        existing_lmdcr = session.retrieve_data_room(data_room_id)
        lmdcr_hl = json.loads(existing_lmdcr.highLevelRepresentation.decode())
        lmdcr = LookalikeMediaDataRoom.parse_obj(lmdcr_hl)

        # Verify data room.
        # Verification involves compiling the LMDCR again and checking that the
        # low level representation matches the original low level representation.
        compiled_serialized = compiler.compile_lookalike_media_data_room(lmdcr)
        recompiled_low_level_dcr = DataRoom()
        parse_length_delimited(compiled_serialized, recompiled_low_level_dcr)
        if recompiled_low_level_dcr != existing_lmdcr.dataRoom:
            raise Exception("LMDCR failed verification")
        return (lmdcr, session)

    # Construct the actual DCR that implements the DataLab functionality.
    def _construct_backing_dcr(self, session: Session) -> str:
        compiled_serialized = compiler.compile_data_lab(self.hl_data_lab)
        low_level_dcr = DataRoom()
        parse_length_delimited(compiled_serialized, low_level_dcr)
        # By default the backing DCR will have the same ID as the DataLab.
        # This causes an issue if there has previously been a DCR created for the DataLab. Instead generate a new ID.
        low_level_dcr.id = str(uuid4())
        dcr_id = session.publish_data_room(
            low_level_dcr, purpose=CreateDcrPurpose.DATA_LAB
        )
        return dcr_id

    # Updates the HL DataLab representation and the session object.
    def _update_enclave_specs(self):
        enclave_specs = get_latest_enclave_specs_as_dictionary(self.client)
        (driver_spec, python_spec) = self._get_data_lab_enclave_specs(enclave_specs)
        # Update to the latest enclave specs
        root_certificate_pem = self.client.decentriq_ca_root_certificate.decode("utf-8")
        # Update the HL representation with the new enclave specs.
        self.hl_data_lab = compiler.update_data_lab_enclave_specifications(
            self.hl_data_lab, driver_spec, python_spec, root_certificate_pem
        )
        auth, _ = self.client.create_auth_using_decentriq_pki(enclave_specs)
        self.session = self.client.create_session(auth, enclave_specs)

    def _get_data_lab_node_names(self, dataset_type: DataLabDatasetType):
        if dataset_type == DataLabDatasetType.EMBEDDINGS:
            return compiler.get_data_lab_node_id(compiler.DataLabNode.Embeddings)
        elif dataset_type == DataLabDatasetType.DEMOGRAPHICS:
            return compiler.get_data_lab_node_id(compiler.DataLabNode.Demographics)
        elif dataset_type == DataLabDatasetType.MATCH:
            return compiler.get_data_lab_node_id(compiler.DataLabNode.Users)
        elif dataset_type == DataLabDatasetType.SEGMENTS:
            return compiler.get_data_lab_node_id(compiler.DataLabNode.Segments)

    def _get_validation_nodes(self):
        features = self._get_features()
        validation_nodes = []
        if "VALIDATE_MATCHING" in features:
            users = self._get_data_lab_node_names(DataLabDatasetType.MATCH)
            validation_nodes.append(users)
        if "VALIDATE_SEGMENTS" in features:
            segments = self._get_data_lab_node_names(DataLabDatasetType.SEGMENTS)
            validation_nodes.append(segments)
        if "VALIDATE_EMBEDDINGS" in features and self.cfg.has_embeddings:
            embeddings = self._get_data_lab_node_names(DataLabDatasetType.EMBEDDINGS)
            validation_nodes.append(embeddings)
        if "VALIDATE_DEMOGRAPHICS" in features and self.cfg.has_demographics:
            demographics = self._get_data_lab_node_names(
                DataLabDatasetType.DEMOGRAPHICS
            )
            validation_nodes.append(demographics)
        # Add the appropriate suffix for the validation nodes.
        validation_nodes = [node + "_validation_report" for node in validation_nodes]
        return validation_nodes

    def _get_features(self):
        features = compiler.get_data_lab_features(self.hl_data_lab)
        return features

    def _get_lmdcr_node_name(self, dataset_name: str):
        lmdcr_node_name = (
            compiler.get_lookalike_media_node_names_from_data_lab_data_type(
                dataset_name
            )
        )
        if not lmdcr_node_name:
            raise Exception(f"Unknown LMDCR node name for dataset name {dataset_name}")
        return lmdcr_node_name
