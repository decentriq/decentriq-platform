import base64
import io
import json
import uuid
import zipfile
from pathlib import Path
from typing import Dict, Mapping, Optional, Text, Tuple
from uuid import uuid4

from decentriq_dcr_compiler import compiler
from decentriq_dcr_compiler._schemas.create_data_lab import (
    EnclaveSpecification as HlEnclaveSpecification,
)
from decentriq_dcr_compiler import (
    CreateDataLab,
    CreateDataLab7,
    CreateDataLabComputeV6,
    MediaInsightsRequest,
)

from ..media.request import Request
from ..client import Client, SecretStoreOptions
from ..helpers import (
    create_session_from_driver_spec,
    get_latest_enclave_specs_as_dictionary,
)
from ..proto import (
    CreateDcrPurpose,
    DataRoom,
    parse_length_delimited,
    serialize_length_delimited,
)
from ..proto.length_delimited import parse_length_delimited, serialize_length_delimited
from ..session import LATEST_GCG_PROTOCOL_VERSION, Session
from ..storage import Key
from ..types import (
    MATCHING_ID_INTERNAL_LOOKUP,
    DataLabDatasetType,
    DataLabDefinition,
    DryRunOptions,
    EnclaveSpecification,
    JobId,
    MatchingId,
)

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
        has_segments: bool,
        matching_id: MatchingId,
        force_spark_validation: bool = False,
    ):
        self.name = name
        self.has_demographics = has_demographics
        self.has_embeddings = has_embeddings
        self.num_embeddings = num_embeddings
        self.has_segments = has_segments
        self.matching_id = matching_id
        self._force_spark_validation = force_spark_validation


class ExistingDataLab:
    def __init__(
        self,
        data_lab_definition: DataLabDefinition,
    ):
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
        existing_data_lab: Optional[ExistingDataLab] = None,
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
                root=CreateDataLab7(
                    v6=CreateDataLabComputeV6(
                        authenticationRootCertificatePem=self.client.decentriq_ca_root_certificate.decode(),
                        driverEnclaveSpecification=HlEnclaveSpecification(
                            attestationProtoBase64="",
                            id="",
                            workerProtocol=0,
                        ),
                        hasDemographics=self.cfg.has_demographics,
                        hasEmbeddings=self.cfg.has_embeddings,
                        hasSegments=self.cfg.has_segments,
                        id=self.data_lab_id,
                        matchingIdFormat=matching_id_format.value,
                        matchingIdHashingAlgorithm=(
                            None
                            if matching_id_hashing_algorithm is None
                            else matching_id_hashing_algorithm.value
                        ),
                        name=self.cfg.name,
                        numEmbeddings=self.cfg.num_embeddings,
                        publisherEmail=self.client.user_email,
                        pythonEnclaveSpecification=HlEnclaveSpecification(
                            attestationProtoBase64="",
                            id="",
                            workerProtocol=0,
                        ),
                        forceSparkValidation=self.cfg._force_spark_validation
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
        match_dataset = existing_data_lab.match_dataset
        if match_dataset is not None:
            manifest_hash = match_dataset["manifestHash"]
            key = self.client.get_dataset_key(manifest_hash)
            self.datasets[DataLabDatasetType.MATCH] = Dataset(
                manifest_hash, key
            )

        segments_dataset = existing_data_lab.segments_dataset
        if segments_dataset is not None:
            manifest_hash = segments_dataset["manifestHash"]
            key = self.client.get_dataset_key(manifest_hash)
            self.datasets[DataLabDatasetType.SEGMENTS] = Dataset(
                manifest_hash, key
            )

        demographics_dataset = existing_data_lab.demographics_dataset
        if self.cfg.has_demographics and demographics_dataset is not None:
            manifest_hash = demographics_dataset["manifestHash"]
            key = self.client.get_dataset_key(manifest_hash)
            self.datasets[DataLabDatasetType.DEMOGRAPHICS] = Dataset(
                manifest_hash, key
            )

        embeddings_dataset = existing_data_lab.embeddings_dataset
        if self.cfg.has_embeddings and embeddings_dataset is not None:
            manifest_hash = embeddings_dataset["manifestHash"]
            key = self.client.get_dataset_key(manifest_hash)
            self.datasets[DataLabDatasetType.EMBEDDINGS] = Dataset(
                manifest_hash, key
            )

    def _get_data_lab_enclave_specs(
        self,
        enclave_specs: Dict[str, EnclaveSpecification],
    ) -> Tuple[HlEnclaveSpecification, HlEnclaveSpecification]:
        driver_spec = None
        python_spec = None
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
                driver_spec = HlEnclaveSpecification.parse_obj(spec_payload)
            elif "decentriq.python-ml-worker" in spec_id:
                spec["clientProtocols"] = [LATEST_GCG_PROTOCOL_VERSION]
                python_spec = HlEnclaveSpecification.parse_obj(spec_payload)
        if driver_spec is None:
            raise Exception("No driver enclave spec found for the datalab")
        if python_spec is None:
            raise Exception("No python-ml-worker enclave spec found for the datalab")
        return (driver_spec, python_spec)

    def provision_local_datasets(
        self,
        key: Key,
        matching_data_path: str,
        segments_data_path: Optional[str] = None,
        demographics_data_path: Optional[str] = None,
        embeddings_data_path: Optional[str] = None,
        *,
        secret_store_options: Optional[SecretStoreOptions] = None,
    ):
        """
        Upload local datasets and provision to the DataLab.

        **Parameters**
        - `key`: The key used to encrypt the dataset.
        - `match`: The file path to the "match" dataset.
        - `segments`: The file path to the "segments" dataset.
        - `demographics`: The file path to the "demographics" dataset.
        - `embeddings`: The file path to the "embeddings" dataset.
        """
        if matching_data_path is not None:
            dataset_name = Path(matching_data_path).stem
            dataset_id = self._upload_dataset(
                matching_data_path, dataset_name, key, secret_store_options
            )
            self.provision_dataset(dataset_id, key, DataLabDatasetType.MATCH)
        if segments_data_path is not None:
            dataset_name = Path(segments_data_path).stem
            dataset_id = self._upload_dataset(
                segments_data_path, dataset_name, key, secret_store_options
            )
            self.provision_dataset(dataset_id, key, DataLabDatasetType.SEGMENTS)
        if embeddings_data_path is not None:
            dataset_name = Path(embeddings_data_path).stem
            self._check_dataset_type_permitted(
                dataset_type=DataLabDatasetType.EMBEDDINGS
            )
            dataset_id = self._upload_dataset(
                embeddings_data_path, dataset_name, key, secret_store_options
            )
            self.provision_dataset(dataset_id, key, DataLabDatasetType.EMBEDDINGS)
        if demographics_data_path is not None:
            dataset_name = Path(demographics_data_path).stem
            self._check_dataset_type_permitted(
                dataset_type=DataLabDatasetType.DEMOGRAPHICS
            )
            dataset_id = self._upload_dataset(
                demographics_data_path, dataset_name, key, secret_store_options
            )
            self.provision_dataset(dataset_id, key, DataLabDatasetType.DEMOGRAPHICS)

    def _upload_dataset(
        self, file_path: str, name: str, key: Key, secret_store_options: Optional[SecretStoreOptions]
    ):
        with open(file_path, "rb") as file:
            dataset_id = self.client.upload_dataset(file, key, name, secret_store_options=secret_store_options)
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
            self.session.connection.channel.driver_attestation_specification_hash,
        )

    def get_validation_report(self, timeout: Optional[int] = None):
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
                validation_reports[node.removesuffix("_validation_report")] = (
                    json.loads(zip.read("validation-report.json").decode())
                )
        return validation_reports

    def get_statistics_report(self, timeout: Optional[int] = None):
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

    def provision_to_media_insights_data_room(
        self, data_room_id: str
    ):
        """
        Provision the DataLab to the DCR with the given ID.

        **Parameters**:
        - `data_room_id`: ID of the DCR to provision the DataLab to.
        """
        # DataLab must be validated before it can be provisioned.
        if not self._validated():
            # Retrieve and store the statistics. This will validate the DataLab.
            self.get_statistics_report()
            # Check again if the DataLab is validated.
            if not self._validated():
                raise Exception("Can't provision to DCR. DataLab not validated.")

        # Check compatibility.
        midcr_hl, midcr_session = self._get_midcr(data_room_id)
        compatible = compiler.is_data_lab_compatible_with_media_insights_dcr_serialized(
            self.hl_data_lab.json(), midcr_hl
        )
        if not compatible:
            raise Exception("DataLab is incompatible with DCR")

        # Deprovision existing datalabs before provisioning new ones.
        self._deprovision_existing_data_lab_from_media_dcr(data_room_id, midcr_session)

        data_lab = self.client.get_data_lab(self.data_lab_id)
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
                request_key, manifest_hash, encryption_key.material, midcr_session, data_room_id
            )

    def _deprovision_existing_data_lab_from_media_dcr(
        self, dcr_id: str, session: Session
    ):
        midcr_driver_attestation_hash = self.client._get_midcr_driver_attestation_hash(
            dcr_id
        )
        midcr_driver_spec = self.client._get_enclave_spec_from_hash(
            midcr_driver_attestation_hash
        )
        endpoint_protocols = [3, 4, 5, 6]
        protocol = session._get_client_protocol(endpoint_protocols)
        midcr_driver_spec["clientProtocols"] = [protocol]
        media_dcr = self.client.retrieve_media_dcr(dcr_id, [midcr_driver_spec])
        media_dcr.deprovision_data_lab()

    def _send_publish_dataset_request(
        self,
        request_key: str,
        manifest_hash: str,
        encryption_key: bytes,
        session: Session,
        data_room_id: str,
    ):
        request = MediaInsightsRequest.model_validate(
            {
                request_key: {
                    "dataRoomIdHex": data_room_id,
                    "datasetHashHex": manifest_hash,
                    "encryptionKeyHex": encryption_key.hex(),
                    "scopeIdHex": self.client._ensure_dcr_data_scope(data_room_id),
                },
            }
        )
        response = Request.send(request, session)
        if request_key not in response.model_dump_json():
            raise Exception(f'Failed to publish "{request_key}"')

    def provision_to_lookalike_media_data_room(
        self, data_room_id: str
    ):
        """
        Provision the DataLab to the DCR with the given ID.

        **Parameters**:
        - `data_room_id`: ID of the DCR to provision the DataLab to.
        """
        # DataLab must be validated before it can be provisioned.
        if not self._validated():
            # Retrieve and store the statistics. This will validate the DataLab.
            self.get_statistics_report()
            # Check again if the DataLab is validated.
            if not self._validated():
                raise Exception("Can't provision to DCR. DataLab not validated.")

        # Check DataLab and LMDCR are compatible.
        lmdcr_hl, lmdcr_session = self._get_lmdcr(data_room_id)
        compatible = (
            compiler.is_data_lab_compatible_with_lookalike_media_data_room_serialized(
                self.hl_data_lab.json(), lmdcr_hl
            )
        )
        if not compatible:
            raise Exception("DataLab is incompatible with DCR")

        lmdcr_datasets = compiler.get_consumed_datasets(lmdcr_hl)
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
            retrieved_key = self.client.get_dataset_key(manifest_hash)
            lmdcr_session.publish_dataset(
                data_room_id, manifest_hash, lmdcr_node_name, retrieved_key
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
            retrieved_key = self.client.get_dataset_key(manifest_hash)
            lmdcr_session.publish_dataset(
                data_room_id, manifest_hash, lmdcr_node_name, retrieved_key
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

    def _get_midcr(self, data_room_id) -> Tuple[str, Session]:
        midcr_driver_attestation_hash = self.client._get_midcr_driver_attestation_hash(
            data_room_id
        )
        midcr_driver_spec = self.client._get_enclave_spec_from_hash(
            midcr_driver_attestation_hash
        )
        if midcr_driver_spec == None:
            raise Exception(f"Failed to find driver for data room {data_room_id}")

        session = create_session_from_driver_spec(self.client, midcr_driver_spec)
        existing_midcr = session.retrieve_data_room(data_room_id)
        midcr_hl = existing_midcr.highLevelRepresentation.decode()
        return (midcr_hl, session)

    def _get_lmdcr(self, data_room_id) -> Tuple[str, Session]:
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
        lmdcr_hl = existing_lmdcr.highLevelRepresentation.decode()
        return (lmdcr_hl, session)

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
