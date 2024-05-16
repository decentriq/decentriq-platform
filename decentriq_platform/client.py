import hashlib
import json
import os
from base64 import b64decode, b64encode
from concurrent import futures
from threading import BoundedSemaphore
from typing import TYPE_CHECKING, BinaryIO, Dict, List, Optional, Tuple

from decentriq_dcr_compiler import compiler
from decentriq_dcr_compiler.schemas.data_science_data_room import DataScienceDataRoom
from decentriq_dcr_compiler.schemas import MediaInsightsDcr as MediaInsightsDcrSchema

from .analytics import AnalyticsDcr, AnalyticsDcrDefinition
from .api import Api, Endpoints, NotFoundError, retry
from .attestation import enclave_specifications
from .authentication import Auth, generate_key, generate_self_signed_certificate
from .config import (
    _DECENTRIQ_UNSAFE_DISABLE_KNOWN_ROOT_CA_CHECK,
    DECENTRIQ_CLIENT_ID,
    DECENTRIQ_HOST,
    DECENTRIQ_PORT,
    DECENTRIQ_USE_TLS,
)
from .connection import Connection
from .endorsement import Endorser
from .graphql import GqlClient
from .keychain import Keychain
from .media import MediaDcr, MediaDcrDefinition
from .proto import AttestationSpecification, AuthenticationMethod, CreateDcrKind
from .proto import DataRoom as ProtoDataRoom
from .proto import PkiPolicy, parse_length_delimited, serialize_length_delimited
from .session import LATEST_WORKER_PROTOCOL_VERSION, Session
from .storage import Chunker, Key, StorageCipher, create_encrypted_chunk
from .types import (
    CreateMediaComputeJobInput,
    DataLabDefinition,
    DataLabListFilter,
    DataRoom,
    DataRoomDescription,
    DataRoomKind,
    DatasetDescription,
    DatasetUsage,
    EnclaveSpecification,
    KeychainInstance,
    MediaComputeJob,
    MediaComputeJobFilterInput,
)
from .logger import logger


class Client:
    """
    A `Client` object allows you to upload datasets and to create `Session` objects that
    can communicate with enclaves and perform essential operations such as publishing
    data rooms and execute computations and retrieve results.

    Objects of this class can be used to create and run data rooms, as well as to securely
    upload data and retrieve computation results.

    Objects of this class should be created using the `create_client` function.
    """

    _api: Api
    _graphql: GqlClient
    _connections: Dict[str, Connection]

    def __init__(
        self,
        user_email: str,
        api: Api,
        graphql: GqlClient,
        request_timeout: Optional[int] = None,
        unsafe_disable_known_root_ca_check: bool = False,
    ):
        """
        Create a client instance.

        Rather than creating `Client` instances directly using this constructor,
        use the function `create_client`.
        """
        self.user_email = user_email
        self._api = api
        self._graphql = graphql
        self.request_timeout = request_timeout
        self.unsafe_disable_known_root_ca_check = unsafe_disable_known_root_ca_check
        self._connections = dict()

    def check_enclave_availability(self, specs: Dict[str, EnclaveSpecification]):
        """
        Check whether the selected enclaves are deployed at this moment.
        If one of the enclaves is not deployed, an exception will be raised.
        """
        available_specs = [
            spec["proto"].SerializeToString()
            for spec in self._get_enclave_specifications()
        ]
        for spec in specs.values():
            if spec["proto"].SerializeToString() not in available_specs:
                raise Exception(
                    "No available enclave deployed for attestation spec '{name}' (version {version})".format(
                        name=spec["name"], version=spec["version"]
                    )
                )

    def _get_enclave_specifications(self) -> List[EnclaveSpecification]:
        data = self._graphql.post(
            """
            {
                attestationSpecs {
                    name
                    version
                    spec
                }
            }
            """
        )
        enclave_specs = []
        for spec_json in data["attestationSpecs"]:
            attestation_specification = AttestationSpecification()
            spec_length_delimited = b64decode(spec_json["spec"])
            parse_length_delimited(spec_length_delimited, attestation_specification)
            enclave_spec = EnclaveSpecification(
                name=spec_json["name"],
                version=spec_json["version"],
                proto=attestation_specification,
                decoder=None,
                workerProtocols=[LATEST_WORKER_PROTOCOL_VERSION],
                clientProtocols=None,
            )
            enclave_specs.append(enclave_spec)
        return enclave_specs

    def create_session_from_data_room_description(
        self,
        data_room_description: DataRoomDescription,
        specs: Optional[List[EnclaveSpecification]] = None,
    ) -> Session:
        """
        Create a session for interacting with a DCR of the given data room description.
        """
        driver_attestation_hash = data_room_description["driverAttestationHash"]
        driver_enclave_spec = dict()
        specs = specs if specs else enclave_specifications.all()
        for spec in specs:
            attestation_hash = hashlib.sha256(
                serialize_length_delimited(spec["proto"])
            ).hexdigest()
            if attestation_hash == driver_attestation_hash:
                driver_enclave_spec = {"decentriq.driver": spec}
                break
        if not driver_enclave_spec:
            raise Exception(
                f"Driver enclave specification with attestation hash {driver_attestation_hash} not found"
            )
        auth, _ = self.create_auth_using_decentriq_pki(driver_enclave_spec)
        return self.create_session(auth, driver_enclave_spec)

    def create_session(
        self,
        auth: Auth,
        enclaves: Dict[str, EnclaveSpecification],
    ) -> Session:
        """
        Creates a new `decentriq_platform.session.Session` instance to communicate
        with a driver enclave.
        The passed set of enclave specifications must include a specification for
        a driver enclave.

        Messages sent through this session will be authenticated
        with the given authentication object.
        """
        if "decentriq.driver" not in enclaves:
            raise Exception(
                "Unable to find a specification for the driver enclave"
                + f" named 'decentriq.driver', you can get these specifications"
                + " from the main package."
            )
        driver_spec = enclaves["decentriq.driver"]
        if (
            "clientProtocols" not in driver_spec
            or driver_spec["clientProtocols"] is None
        ):
            raise Exception("Missing client supported protocol versions")
        attestation_proto = driver_spec["proto"]
        client_protocols = driver_spec["clientProtocols"]
        attestation_specification_hash = hashlib.sha256(
            serialize_length_delimited(attestation_proto)
        ).hexdigest()
        connection = self._connections.get(attestation_specification_hash)
        if connection is None:
            connection = Connection(
                attestation_proto,
                self._api,
                self._graphql,
                self.unsafe_disable_known_root_ca_check,
            )
            self._connections[attestation_specification_hash] = connection
        session = Session(
            self,
            connection,
            client_protocols,
            auth=auth,
        )

        return session

    def _ensure_dataset_scope(
        self,
        manifest_hash: Optional[str] = None,
    ) -> str:
        payload = {
            "manifestHash": manifest_hash,
        }
        data = self._graphql.post(
            """
            mutation GetOrCreateDatasetScope($input: CreateDatasetScopeInput!) {
                scope {
                    getOrCreateDatasetScope(input: $input) {
                        record {
                            id
                        }
                    }

                }
            }
            """,
            {"input": payload},
        )
        scope = data["scope"]["getOrCreateDatasetScope"]["record"]
        return scope["id"]

    def _ensure_dcr_data_scope(
        self,
        data_room_hash: str,
    ) -> str:
        data = self._graphql.post(
            """
            mutation GetOrCreateDcrDataScope($input: CreateDcrDataScopeInput!) {
                scope {
                    getOrCreateDcrDataScope(input: $input) {
                        record {
                            id
                        }
                    }

                }
            }
            """,
            {
                "input": {
                    "dataRoomHash": data_room_hash,
                }
            },
        )
        scope = data["scope"]["getOrCreateDcrDataScope"]["record"]
        return scope["id"]

    def _set_datalab_matching_dataset(
        self,
        data_lab_id: str,
        manifest_hash: Optional[str],
    ) -> str:
        """
        Store the matching dataset manifest hash in the database.
        """
        data = self._graphql.post(
            """
            mutation SetDataLabUsersDataset($input: SetDataLabDatasetInput!) {
                dataLab {
                    setUsersDataset(input: $input) {
                        record {
                            id
                            validationComputeJobId
                            statisticsComputeJobId
                            jobsDriverAttestationHash
                        }
                    }

                }
            }
            """,
            {"input": {"id": data_lab_id, "manifestHash": manifest_hash}},
        )
        return data["dataLab"]["setUsersDataset"]["record"]["id"]

    def _set_datalab_segments_dataset(
        self,
        data_lab_id: str,
        manifest_hash: Optional[str],
    ) -> str:
        """
        Store the segments dataset manifest hash in the database.
        """
        data = self._graphql.post(
            """
            mutation SetDataLabSegmentsDataset($input: SetDataLabDatasetInput!) {
                dataLab {
                    setSegmentsDataset(input: $input) {
                        record {
                            id
                            validationComputeJobId
                            statisticsComputeJobId
                            jobsDriverAttestationHash
                        }
                    }

                }
            }
            """,
            {"input": {"id": data_lab_id, "manifestHash": manifest_hash}},
        )
        return data["dataLab"]["setSegmentsDataset"]["record"]["id"]

    def _set_datalab_demographics_dataset(
        self,
        data_lab_id: str,
        manifest_hash: Optional[str],
    ) -> str:
        """
        Store the demographics dataset manifest hash in the database.
        """
        data = self._graphql.post(
            """
            mutation SetDataLabDemographicsDataset($input: SetDataLabDatasetInput!) {
                dataLab {
                    setDemographicsDataset(input: $input) {
                        record {
                            id
                            validationComputeJobId
                            statisticsComputeJobId
                            jobsDriverAttestationHash
                        }
                    }

                }
            }
            """,
            {"input": {"id": data_lab_id, "manifestHash": manifest_hash}},
        )
        return data["dataLab"]["setDemographicsDataset"]["record"]["id"]

    def _set_datalab_embeddings_dataset(
        self,
        data_lab_id: str,
        manifest_hash: Optional[str],
    ) -> str:
        """
        Store the embeddings dataset manifest hash in the database.
        """
        data = self._graphql.post(
            """
            mutation SetDataLabEmbeddingsDataset($input: SetDataLabDatasetInput!) {
                dataLab {
                    setEmbeddingsDataset(input: $input) {
                        record {
                            id
                            validationComputeJobId
                            statisticsComputeJobId
                            jobsDriverAttestationHash
                        }
                    }

                }
            }
            """,
            {"input": {"id": data_lab_id, "manifestHash": manifest_hash}},
        )
        return data["dataLab"]["setEmbeddingsDataset"]["record"]["id"]

    def _set_datalab_job_ids(
        self,
        data_lab_id: str,
        validation_compute_job_id: str,
        statistics_compute_job_id: str,
        jobs_driver_attestation_hash: str,
    ) -> str:
        """
        Store the job IDs associated with the DataLab.
        """
        data = self._graphql.post(
            """
            mutation SetDataLabJobIds($input: SetDataLabJobIdsInput!) {
                dataLab {
                    setJobIds(input: $input) {
                        record {
                            id
                        }
                    }

                }
            }
            """,
            {
                "input": {
                    "id": data_lab_id,
                    "validationComputeJobId": validation_compute_job_id,
                    "statisticsComputeJobId": statistics_compute_job_id,
                    "jobsDriverAttestationHash": jobs_driver_attestation_hash,
                }
            },
        )
        return data["dataLab"]["setJobIds"]["record"]["id"]

    def _set_datalab_statistics(
        self,
        data_lab_id: str,
        statistics: str,
    ) -> str:
        """
        Store the DataLab statistics in the database.
        """
        data = self._graphql.post(
            """
            mutation SetDataLabStatistics($input: SetDataLabStatisticsInput!) {
                dataLab {
                    setStatistics(input: $input) {
                        record {
                            id
                        }
                    }
                }
            }
            """,
            {
                "input": {
                    "id": data_lab_id,
                    "statistics": json.loads(statistics),
                }
            },
        )
        return data["dataLab"]["setStatistics"]["record"]["id"]

    def upload_dataset(
        self,
        data: BinaryIO,
        key: Key,
        file_name: str,
        /,
        *,
        description: str = "",
        chunk_size: int = 8 * 1024**2,
        parallel_uploads: int = 8,
        usage: DatasetUsage = DatasetUsage.PUBLISHED,
        store_in_keychain: Optional[Keychain] = None,
    ) -> str:
        """
        Uploads `data` as a file usable by enclaves and returns the
        corresponding manifest hash.

        **Parameters**:
        - `data`: The data to upload as a buffered stream.
            Such an object can be obtained by wrapping a binary string in a `io.BytesIO()`
            object or, if reading from a file, by using `with open(path, "rb") as file`.
        - `key`: Encryption key used to encrypt the file.
        - `file_name`: Name of the file.
        - `description`: An optional file description.
        - `chunk_size`: Size of the chunks into which the stream is split in bytes.
        - `parallel_uploads`: Whether to upload chunks in parallel.
        - `store_in_keychain`: An optional keychain in which to store the dataset key.
        """
        uploader = BoundedExecutor(
            bound=parallel_uploads * 2, max_workers=parallel_uploads
        )
        # create and upload chunks
        chunker = Chunker(data, chunk_size=chunk_size)
        chunk_hashes: List[str] = []
        chunk_content_sizes: List[int] = []
        chunk_uploads_futures = []
        upload_id = self._create_upload()

        for chunk_hash, chunk_data, chunk_content_size in chunker:
            chunk_uploads_futures.append(
                uploader.submit(
                    self._encrypt_and_upload_chunk,
                    chunk_hash,
                    chunk_data,
                    key.material,
                    upload_id,
                )
            )
            chunk_hashes.append(chunk_hash.hex())
            chunk_content_sizes.append(chunk_content_size)

        # check chunks uploads were successful
        completed, pending = futures.wait(
            chunk_uploads_futures, None, futures.FIRST_EXCEPTION
        )
        # re-raise exception
        for future in completed:
            future.result()
        uploader.shutdown(wait=False)

        # create manifest and upload
        manifest_hash_bytes, manifest_encrypted = create_encrypted_chunk(
            key.material,
            os.urandom(16),
            json.dumps(chunk_hashes).encode("utf-8"),
            content_size=chunker.content_size,
            chunk_content_sizes=chunk_content_sizes,
        )
        scope_id = self._ensure_dataset_scope(
            manifest_hash_bytes.hex(),
        )
        manifest_hash = self._finalize_upload(
            scope_id=scope_id,
            upload_id=upload_id,
            name=file_name,
            manifest_hash_bytes=manifest_hash_bytes,
            manifest_encrypted=manifest_encrypted,
            chunks=chunk_hashes,
            description=description,
            usage=usage,
        )

        if store_in_keychain:
            from .keychain import KeychainEntry

            store_in_keychain.insert(
                KeychainEntry("dataset_key", manifest_hash, key.material)
            )

        return manifest_hash

    def _encrypt_and_upload_chunk(
        self, chunk_hash: bytes, chunk_data: bytes, key: bytes, upload_id: str
    ):
        cipher = StorageCipher(key)
        chunk_data_encrypted = cipher.encrypt(chunk_data)
        self._upload_chunk(chunk_hash, chunk_data_encrypted, upload_id)

    def _create_upload(self) -> str:
        """
        Create an upload record for the user identified by the used
        API token and return its id.
        """
        data = self._graphql.post(
            """
            mutation CreateUpload() {
                upload {
                    create {
                        record {
                            id
                        }
                    }
                }
            }
            """,
        )
        upload_id = data["upload"]["create"]["record"]["id"]
        return upload_id

    def _upload_chunk(
        self, chunk_hash: bytes, chunk_data_encrypted: bytes, upload_id: str
    ):
        url = Endpoints.USER_UPLOAD_CHUNKS.replace(":uploadId", upload_id).replace(
            ":chunkHash", chunk_hash.hex()
        )
        try:
            self._api.put(
                url,
                chunk_data_encrypted,
                {"Content-type": "application/octet-stream"},
                retry=retry,
            )
        except Exception as e:
            logger.error(e)
            raise e

    def _delete_user_upload(self, upload_id: str):
        self._graphql.post(
            """
            mutation DeleteUpload($id: Id!) {
                upload {
                    delete(id: $id)
                }
            }
            """,
            {"id": upload_id},
        )

    def _finalize_upload(
        self,
        scope_id: str,
        upload_id: str,
        name: str,
        manifest_hash_bytes: bytes,
        manifest_encrypted: bytes,
        chunks: List[str],
        description: Optional[str] = None,
        usage: Optional[DatasetUsage] = None,
    ) -> str:
        data = self._graphql.post(
            """
            mutation FinalizeUpload($input: CreateDatasetForUploadInput!) {
                upload {
                    finalizeUploadAndCreateDataset(input: $input) {
                        record {
                            id
                            manifestHash
                        }
                    }
                }
            }
            """,
            {
                "input": {
                    "uploadId": upload_id,
                    "manifest": b64encode(manifest_encrypted).decode("ascii"),
                    "manifestHash": manifest_hash_bytes.hex(),
                    "name": name,
                    "description": description,
                    "usage": usage,
                    "chunkHashes": chunks,
                    "scopeId": scope_id,
                }
            },
            retry=retry,
        )

        dataset = data["upload"]["finalizeUploadAndCreateDataset"]["record"]
        manifest_hash = dataset["manifestHash"]

        return manifest_hash

    def get_dataset(self, manifest_hash: str) -> Optional[DatasetDescription]:
        """
        Returns information about a user dataset given a dataset id.
        """
        try:
            data = self._graphql.post(
                """
                query GetDataset($manifestHash: HexString!)
                {
                    datasetByManifestHash(manifestHash: $manifestHash) {
                        id
                        name
                        manifestHash
                        description
                        createdAt
                    }
                }
                """,
                {"manifestHash": manifest_hash},
            )
            return data["datasetByManifestHash"]
        except NotFoundError:
            return None

    def get_available_datasets(self) -> List[DatasetDescription]:
        """
        Returns the a list of datasets that the current user uploaded,
        regardless of whether they have already been connected to a
        data room or not.
        """
        data = self._graphql.post(
            """
            {
                myself {
                    datasets {
                        nodes {
                            id
                            name
                            manifestHash
                            statistics
                            size
                            description
                            createdAt
                            usage
                        }
                    }
                }
            }
            """
        )
        return data["myself"]["datasets"]["nodes"]

    def delete_dataset(self, manifest_hash: str, force: bool = False):
        """
        Deletes the dataset with the given id from the Decentriq platform.

        In case the dataset is still published to one or more data rooms,
        an exception will be thrown and the dataset will need to be
        unpublished manually from the respective data rooms using
        `Session.remove_published_dataset`.
        This behavior can be overridden by using the `force` flag.
        Note, however, that this might put some data rooms in a broken
        state as they might try to read data that does not exist anymore.
        """
        data_rooms_ids_with_dataset = self._get_data_room_ids_for_publication(
            manifest_hash
        )
        if data_rooms_ids_with_dataset:
            id_list = "\n".join(
                [f"- {dcr_id}" for dcr_id in data_rooms_ids_with_dataset]
            )
            if force:
                logger.warning(
                    "This dataset is published to the following data rooms."
                    " These data rooms might be in a broken state now:"
                    f"\n{id_list}"
                )
            else:
                raise Exception(
                    "This dataset is published to the following data rooms"
                    " and needs to be unpublished before it can be deleted!"
                    f"\n{id_list}"
                )
        self._graphql.post(
            """
            mutation DeleteDataset($manifestHash: HexString!) {
                dataset {
                    deleteByManifestHash(manifestHash: $manifestHash)
                }
            }
            """,
            {
                "manifestHash": manifest_hash,
            },
        )

    @property
    def decentriq_ca_root_certificate(self) -> bytes:
        """
        Returns the root certificate used by the Decentriq identity provider.
        Note that when using this certificate in any authentication scheme,
        you trust Decentriq as an identity provider!
        """
        data = self._graphql.post(
            """
            {
                certificateAuthority {
                    rootCertificate
                }
            }
        """
        )
        certificate = data["certificateAuthority"]["rootCertificate"].encode("utf-8")
        return certificate

    @property
    def decentriq_pki_authentication(self) -> AuthenticationMethod:
        """
        The authentication method that uses the Decentriq root certificate to authenticate
        users.

        This method should be specified when building a data room in case you want to interact
        with the that data room either via the web interface or with sessions created using
        `create_auth_using_decentriq_pki`.
        Note that when using this authentication method you trust Decentriq as an identity provider!

        You can also create an `AuthenticationMethod` object directly and supply your own root certificate,
        with which to authenticate users connecting to your data room.
        In this case you will also need to issue corresponding user certificates and create your
        own custom `decentriq_platform.authentication.Auth` objects.
        """
        root_pki = self.decentriq_ca_root_certificate
        return AuthenticationMethod(dqPki=PkiPolicy(rootCertificatePem=root_pki))

    def create_auth_using_decentriq_pki(
        self, enclaves: Dict[str, EnclaveSpecification]
    ) -> Tuple[Auth, Endorser]:
        auth = self.create_auth()
        endorser = Endorser(auth, self, enclaves)
        dq_pki = endorser.decentriq_pki_endorsement()
        auth.attach_endorsement(decentriq_pki=dq_pki)
        return auth, endorser

    def create_auth(self) -> Auth:
        """
        Creates a `decentriq_platform.authentication.Auth` object which can be attached
        to `decentriq_platform.session.Session`.
        """
        keypair = generate_key()
        cert_chain_pem = generate_self_signed_certificate(self.user_email, keypair)
        auth = Auth(cert_chain_pem, keypair, self.user_email)
        return auth

    def get_data_room_descriptions(self) -> List[DataRoomDescription]:
        """
        Returns the a list of descriptions of all the data rooms a user created
        or participates in.
        """
        data = self._graphql.post(
            """
            {
                publishedDataRooms {
                    nodes {
                        id
                        title
                        driverAttestationHash
                        isStopped
                        createdAt
                        updatedAt
                        owner {
                            email
                        }
                        kind
                    }
                }
            }
            """
        )
        return [
            DataRoomDescription(**item) for item in data["publishedDataRooms"]["nodes"]
        ]

    def get_data_room_description(
        self, data_room_hash, enclave_specs
    ) -> Optional[DataRoomDescription]:
        """
        Get a single data room description.
        """
        driver_spec = enclave_specs["decentriq.driver"]
        attestation_proto = driver_spec["proto"]
        driver_attestation_hash = hashlib.sha256(
            serialize_length_delimited(attestation_proto)
        ).hexdigest()
        return self._get_data_room_by_hash(data_room_hash, driver_attestation_hash)

    def _get_data_room_kind(
        self,
        data_room_id: str,
    ) -> DataRoomKind:
        """
        Get the kind of data room.
        """
        data = self._graphql.post(
            """
            query GetPublishedDataRoomType($dataRoomId: String!) {
                publishedDataRoom(id: $dataRoomId) {
                    kind
                }
            }
            """,
            {
                "dataRoomId": data_room_id,
            },
        )
        return data["publishedDataRoom"]["kind"]

    def _get_data_room_by_hash(
        self, data_room_hash: str, driver_attestation_hash: str
    ) -> Optional[DataRoomDescription]:
        data = self._graphql.post(
            """
            query GetPublishedDataRoom($dataRoomHash: String!) {
                publishedDataRoom(id: $dataRoomHash) {
                    id
                    title
                    driverAttestationHash
                    isStopped
                    createdAt
                    updatedAt
                    owner {
                        email
                    }
                    kind
                }
            }
            """,
            {
                "dataRoomHash": data_room_hash,
                "driverAttestationHash": driver_attestation_hash,
            },
        )
        result = data.get("publishedDataRoom")
        if result is not None:
            dcr: DataRoomDescription = result
            if dcr["driverAttestationHash"] != driver_attestation_hash:
                raise Exception(
                    f"Driver attestation hash for request dataroom doesn't match '{dcr['driverAttestationHash']}' != {driver_attestation_hash})"
                )
            return dcr
        else:
            return None

    def _get_user_certificate(self, email: str, csr_pem: str) -> str:
        data = self._graphql.post(
            """
            query getUserCertificate($input: UserCsrInput!) {
                certificateAuthority {
                    userCertificate(input: $input)
                }
            }
            """,
            {
                "input": {
                    "csrPem": csr_pem,
                    "email": email,
                }
            },
        )
        cert_chain_pem = data["certificateAuthority"]["userCertificate"]
        return cert_chain_pem

    def _get_data_rooms_with_published_dataset(
        self, manifest_hash
    ) -> List[DataRoomDescription]:
        data = self._graphql.post(
            """
                query GetDatasetPublications($manifestHash: HexString!) {
                    datasetByManifestHash(manifestHash: $manifestHash) {
                        publications {
                            nodes {
                                dataRoom {
                                    id
                                    title
                                    driverAttestationHash
                                    isStopped
                                    createdAt
                                    updatedAt
                                    owner {
                                        email
                                    }
                                    kind
                                }
                            }
                        }
                    }
                }
                """,
            {
                "manifestHash": manifest_hash,
            },
        )
        publications = data["datasetByManifestHash"]["publications"]["nodes"]

        if publications:
            dcrs = [publication["dataRoom"] for publication in publications]
            deduplicated_dcrs = ({dcr["id"]: dcr for dcr in dcrs}).values()
            return list(deduplicated_dcrs)
        else:
            return []

    def _get_data_room_ids_for_publication(self, manifest_hash) -> List[str]:
        data_rooms = self._get_data_rooms_with_published_dataset(manifest_hash)
        if data_rooms:
            return [data_room["id"] for data_room in data_rooms]
        else:
            return []

    def _get_scope(self, scope_id: str):
        data = self._graphql.post(
            """
            query GetScope($scopeId: String!) {
                scope(id: $scopeId) {
                    id
                    organization {
                        id
                        name
                    }
                    owner {
                        id
                        email
                    }
                    scopeType
                    manifestHash
                    dataRoomHash
                    driverAttestationHash
                    createdAt
                }
            }
            """,
            {"scopeId": scope_id},
        )
        return data["scope"]

    def get_keychain_instance(self) -> Optional[KeychainInstance]:
        data = self._graphql.post(
            """
            query GetKeychain {
                myself {
                    keychain {
                        userId
                        salt
                        encrypted
                        casIndex
                    }
                }
            }
            """
        )
        keychain = data["myself"]["keychain"]
        if keychain:
            keychain["encrypted"] = b64decode(keychain["encrypted"])
        return keychain

    def create_keychain_instance(self, salt: str, encrypted: bytes) -> KeychainInstance:
        data = self._graphql.post(
            """
            mutation CreateKeychain($inner: CreateKeychainInput!) {
                keychain {
                    create(inner: $inner) {
                    userId
                    salt
                    encrypted
                    casIndex
                    }
                }
            }
            """,
            {
                "inner": {
                    "salt": salt,
                    "encrypted": b64encode(encrypted).decode("ascii"),
                }
            },
        )
        keychain = data["keychain"]["create"]
        keychain["encrypted"] = b64decode(keychain["encrypted"])
        return keychain

    def compare_and_swap_keychain(
        self,
        cas_index: int,
        salt: Optional[str] = None,
        encrypted: Optional[bytes] = None,
    ) -> bool:
        data = self._graphql.post(
            """
            mutation CompareAndSwapKeychain($inner: CompareAndSwapKeychainInput!) {
                keychain {
                    compareAndSwap(inner: $inner)
                }
            }
            """,
            {
                "inner": {
                    "salt": salt,
                    "encrypted": (
                        b64encode(encrypted).decode("ascii")
                        if encrypted is not None
                        else None
                    ),
                    "casIndex": cas_index,
                }
            },
        )
        return data["keychain"]["compareAndSwap"]

    def reset_keychain(self):
        _ = self._graphql.post(
            """
            mutation ResetKeychain {
                keychain {
                    reset
                }
            }
            """
        )
        return

    def list_data_labs(
        self, filter: Optional[DataLabListFilter] = None
    ) -> List[DataLabDefinition]:
        """
        Return a list of DataLabs based on the `filter` criteria.

        **Parameters**:
        - `filter`: Criteria used to filter the list. Can be one of the following values:
            - NONE: Display all DataLabs.
            - VALIDATED: Display DataLabs that have been validated.
            - UNVALIDATED: Display DataLabs that have not been validated.
        """
        data = self._graphql.post(
            """
            query ListDataLabIds() {
                dataLabs {
                    nodes {
                        id
                        name
                        datasets {
                            name
                            dataset {
                                id
                                manifestHash
                                name
                            }
                        }
                        usersDataset {
                            id
                            manifestHash
                            name
                        }
                        segmentsDataset {
                            id
                            manifestHash
                            name
                        }
                        demographicsDataset {
                            id
                            manifestHash
                            name
                        }
                        embeddingsDataset  {
                            id
                            manifestHash
                            name
                        }
                        requireDemographicsDataset
                        requireEmbeddingsDataset
                        isValidated
                        numEmbeddings
                        matchingIdFormat
                        matchingIdHashingAlgorithm
                        validationComputeJobId
                        statisticsComputeJobId
                        jobsDriverAttestationHash
                        highLevelRepresentationAsString
                        createdAt
                        updatedAt
                    }
                }
            }
            """,
        )
        data_labs = data["dataLabs"]["nodes"]
        if filter is None:
            return [lab for lab in data_labs]
        elif filter == DataLabListFilter.VALIDATED:
            return [lab for lab in data_labs if lab["isValidated"] == True]
        elif filter == DataLabListFilter.UNVALIDATED:
            return [lab for lab in data_labs if lab["isValidated"] == False]
        else:
            raise Exception(f"Unknown DataLab filter {filter}")

    def get_data_lab(
        self,
        id: str,
    ) -> DataLabDefinition:
        """
        Return the DataLab with the given ID.

        **Parameters**:
        - `id`: ID of the DataLab to get.
        """
        data = self._graphql.post(
            """
            query GetDataLab($id: String!) {
                dataLab(id: $id) {
                    id
                    name
                    datasets {
                        name
                        dataset {
                            id
                            manifestHash
                            name
                        }
                    }
                    usersDataset {
                        id
                        manifestHash
                        name
                    }
                    segmentsDataset {
                        id
                        manifestHash
                        name
                    }
                    demographicsDataset {
                        id
                        manifestHash
                        name
                    }
                    embeddingsDataset {
                        id
                        manifestHash
                        name
                    }
                    statistics
                    requireSegmentsDataset
                    requireDemographicsDataset
                    requireEmbeddingsDataset
                    isValidated
                    numEmbeddings
                    matchingIdFormat
                    matchingIdHashingAlgorithm
                    validationComputeJobId
                    statisticsComputeJobId
                    jobsDriverAttestationHash
                    highLevelRepresentationAsString
                }
            }
            """,
            {"id": id},
        )
        return data["dataLab"]

    def _publish_data_lab_from_existing(
        self,
        data_lab: Dict[str, str],
    ) -> str:
        """
        Publish a DataLab from an existing high level representation.

        **Parameters**:
        - `data_lab`: DataLab high level representation
        """
        data = self._graphql.post(
            """
            mutation PublishDataLab($input: CreateDataLabFromExistingInput!) {
                dataLab {
                    createFromExisting(input: $input) {
                        record {
                            id
                        }
                    }
                }
            }
            """,
            {"input": {"dataLab": data_lab}},
        )
        return data["dataLab"]["createFromExisting"]["record"]["id"]

    def _get_enclave_spec_from_hash(self, hash: str) -> Optional[EnclaveSpecification]:
        available_specs = self._get_enclave_specifications()
        for spec in available_specs:
            hashed_attestation_spec = hashlib.sha256(
                serialize_length_delimited(spec["proto"])
            ).hexdigest()
            if hashed_attestation_spec == hash:
                return spec
        return None

    def _get_lmdcr_driver_attestation_hash(
        self,
        id: str,
    ) -> str:
        """
        Get the driver attestation hash for the Lookalike Media DCR with the given ID.

        **Parameters**:
        - `id`: ID of the Lookalike Media DCR.
        """
        data = self._graphql.post(
            """
            query GetLookalikeMediaDcr($id: String!) {
                publishedLookalikeMediaDataRoom(id: $id) {
                    driverAttestationHash
                }
            }
            """,
            {"id": id},
        )
        return data["publishedLookalikeMediaDataRoom"]["driverAttestationHash"]

    def _get_midcr_driver_attestation_hash(
        self,
        id: str,
    ) -> str:
        """
        Get the driver attestation hash for the Media Insights DCR with the given ID.

        **Parameters**:
        - `id`: ID of the Media Insights DCR.
        """
        data = self._graphql.post(
            """
            query GetMediaInsightsDcr($id: String!) {
                publishedMediaInsightsDcr(id: $id) {
                    driverAttestationHash
                }
            }
            """,
            {"id": id},
        )
        return data["publishedMediaInsightsDcr"]["driverAttestationHash"]

    def get_lookalike_media_data_rooms(
        self,
    ) -> List[DataRoom]:
        """
        Get all Lookalike Media data clean rooms.
        """
        data = self._graphql.post(
            """
            query GetAllLookalikeMediaDcrs($filter: DataRoomFilter, $sortBy: DataRoomSortBy) {
                dataRooms(filter: $filter, sortBy: $sortBy) {
                    nodes {
                        id
                        title
                        kind
                        createdAt
                        updatedAt
                        owner {
                            id
                            email
                        }
                    }
                    totalCount
                }
            }
            """,
            {"filter": None, "sortBy": None},
        )
        data_rooms = data["dataRooms"]["nodes"]
        lookalike_media_data_rooms = [
            data_room
            for data_room in data_rooms
            if data_room["kind"] == "LOOKALIKE_MEDIA"
        ]
        return lookalike_media_data_rooms

    def _create_media_compute_job(
        self,
        input: CreateMediaComputeJobInput,
    ) -> MediaComputeJob:
        """
        Create a compute job for the Lookalike Media DCR.
        """
        data = self._graphql.post(
            """
            mutation CreateMediaComputeJob($input: CreateMediaComputeJobInput!) {
                mediaComputeJob {
                    create(input: $input) {
                        record {
                            jobIdHex
                            publishedDataRoomId
                            computeNodeName
                            jobType
                            cacheKey
                            createdAt
                        }
                    }
                }
            }
            """,
            {"input": input},
        )
        return data["mediaComputeJob"]["create"]["record"]

    def _get_media_compute_job(
        self,
        input: MediaComputeJobFilterInput,
    ) -> MediaComputeJob:
        """
        Get a compute job for the Lookalike Media DCR.
        """
        data = self._graphql.post(
            """
            query GetMediaComputeJob($input: MediaComputeJobFilterInput!) {
                mediaComputeJob (input: $input) {
                    jobIdHex
                    publishedDataRoomId
                    computeNodeName
                    jobType
                    cacheKey
                    createdAt
                }
            }
            """,
            {"input": input},
        )
        return data["mediaComputeJob"]

    def _provision_data_lab(
        self,
        data_room_id: str,
        data_lab_id: str,
    ) -> DataLabDefinition:
        """
        Provision a DataLab to a DCR.

        **Parameters**:
        - `data_room_id`: ID of the DCR to provision to.
        - `data_lab_id`: ID of the DataLab to be provisioned.
        """
        data = self._graphql.post(
            """
            mutation ProvisionDataLab($input: ProvisionDataLabInput!) {
                dataLab {
                    provisionDataLab(input: $input) {
                        publishedDataLab {
                            id
                            name
                            datasets {
                                name
                                dataset {
                                    id
                                    manifestHash
                                    name
                                }
                            }
                            usersDataset {
                                id
                                manifestHash
                                name
                            }
                            segmentsDataset {
                                id
                                manifestHash
                                name
                            }
                            demographicsDataset {
                                id
                                manifestHash
                                name
                            }
                            embeddingsDataset {
                                id
                                manifestHash
                                name
                            }
                            statistics
                            requireDemographicsDataset
                            requireEmbeddingsDataset
                            isValidated
                            numEmbeddings
                            matchingIdFormat
                            matchingIdHashingAlgorithm
                            validationComputeJobId
                            statisticsComputeJobId
                            jobsDriverAttestationHash
                            highLevelRepresentationAsString
                        }
                    }
                }
            }
            """,
            {
                "input": {
                    "dataRoomId": data_room_id,
                    "dataLabId": data_lab_id,
                }
            },
        )
        return data["dataLab"]["provisionDataLab"]["publishedDataLab"]

    def _deprovision_data_lab(self, data_room_id: str) -> DataLabDefinition:
        """
        Deprovision a DataLab from a DCR.

        **Parameters**:
        - `data_room_id`: ID of the DCR to deprovision from.
        """
        data = self._graphql.post(
            """
            mutation DeprovisionDataLab($input: String!) {
                dataLab {
                    deprovisionDataLab(lookalikeMediaDcrId: $input) {
                        publishedDataLab {
                            id
                            name
                            datasets {
                                name
                                dataset {
                                    id
                                    manifestHash
                                    name
                                }
                            }
                            usersDataset {
                                id
                                manifestHash
                                name
                            }
                            segmentsDataset {
                                id
                                manifestHash
                                name
                            }
                            demographicsDataset {
                                id
                                manifestHash
                                name
                            }
                            embeddingsDataset {
                                id
                                manifestHash
                                name
                            }
                            statistics
                            requireDemographicsDataset
                            requireEmbeddingsDataset
                            isValidated
                            numEmbeddings
                            matchingIdFormat
                            matchingIdHashingAlgorithm
                            validationComputeJobId
                            statisticsComputeJobId
                            jobsDriverAttestationHash
                            highLevelRepresentationAsString
                        }
                    }
                }
            }
            """,
            {
                "input": data_room_id,
            },
        )
        return data["dataLab"]["deprovisionDataLab"]["publishedDataLab"]

    def retrieve_analytics_dcr(
        self,
        dcr_id,
        enclave_specs: Optional[List[EnclaveSpecification]] = None,
    ) -> AnalyticsDcr:
        """
        Retrieve an existing Analytics DCR.

        **Parameters**:
        - `dcr_id`: Data Clean Room ID.
        - `enclave_specs`: The enclave specifications that are considered
          to be trusted. If not specified, all enclave specifications known
          to this version of the SDK will be used.
        """
        return AnalyticsDcr._from_existing(
            dcr_id, client=self, enclave_specs=enclave_specs
        )

    def publish_analytics_dcr(
        self,
        dcr_definition: AnalyticsDcrDefinition,
        *,
        enclave_specs: Optional[Dict[str, EnclaveSpecification]] = None,
    ) -> AnalyticsDcr:
        """
        Publish an Analytics DCR.

        **Parameters**:
        - `dcr_definition`: Definition of the Analytics DCR.
        - `enclave_specs`: The enclave specifications that are considered
          to be trusted. If not specified, all enclave specifications known
          to this version of the SDK will be used.
        """
        data_room = DataScienceDataRoom.model_validate(
            dcr_definition._get_high_level_representation()
        )
        compiled_data_room = compiler.compile_data_science_data_room(data_room)
        self.compile_context = compiled_data_room.compile_context

        low_level_data_room = ProtoDataRoom()
        parse_length_delimited(compiled_data_room.data_room, low_level_data_room)

        # Get a new session.
        # Determine which driver enclave spec (as given by the enclave_specs value)
        # to use. If this is not explicitly specified, try to check whether it was
        # already set on the builder that constructed the DCR definition.
        # If this is also not specified, simply use the latest specifications known to this SDK.
        specs = (
            enclave_specs
            or dcr_definition.enclave_specs
            or enclave_specifications.latest()
        )
        auth, _ = self.create_auth_using_decentriq_pki(specs)
        session = self.create_session(auth, specs)

        dcr_id = session.publish_data_room(
            low_level_data_room,
            kind=CreateDcrKind.DATASCIENCE,
            high_level_representation=compiled_data_room.datascience_data_room_encoded,
        )

        # Now that we've published the DCR the simplest way to construct
        # the DCR is using the `from_existing` method. This takes care
        # of correctly constructing all the node definitions.
        published_ds_dcr = AnalyticsDcr._from_existing(
            dcr_id=dcr_id, client=self, enclave_specs=list(specs.values())
        )
        return published_ds_dcr

    def retrieve_media_dcr(
        self,
        dcr_id,
        enclave_specs: Optional[List[EnclaveSpecification]] = None,
    ) -> MediaDcr:
        """
        Retrieve an existing Media DCR.

        **Parameters**:
        - `dcr_id`: Data Clean Room ID.
        - `enclave_specs`: The enclave specifications that are considered
          to be trusted. If not specified, all enclave specifications known
          to this version of the SDK will be used.
        """
        return MediaDcr._from_existing(
            dcr_id, client=self, enclave_specs=enclave_specs
        )

    def publish_media_dcr(
        self,
        dcr_definition: MediaDcrDefinition,
        *,
        enclave_specs: Optional[Dict[str, EnclaveSpecification]] = None,
    ) -> MediaDcr:
        """
        Publish a Media DCR.

        **Parameters**:
        - `dcr_definition`: Definition of the Media DCR.
        - `enclave_specs`: The enclave specifications that are considered
          to be trusted. If not specified, all enclave specifications known
          to this version of the SDK will be used.
        """
        dcr = MediaInsightsDcrSchema.model_validate_json(
            dcr_definition._high_level
        )
        # Ensure we create the latest known version of the DCR.
        dcr_latest = compiler.upgrade_media_insights_dcr_to_latest(dcr)

        compiled_serialized = compiler.compile_media_insights_dcr(dcr_latest)
        low_level_dcr = ProtoDataRoom()
        parse_length_delimited(compiled_serialized, low_level_dcr)

        # Get a new session.
        # Determine which driver enclave spec (as given by the enclave_specs value)
        # to use. If this is not explicitly specified, try to check whether it was
        # already set on the builder that constructed the DCR definition.
        # If this is also not specified, simply use the latest specifications known to this SDK.
        specs = (
            enclave_specs
            or dcr_definition._enclave_specs
            or enclave_specifications.latest()
        )
        auth, _ = self.create_auth_using_decentriq_pki(specs)
        session = self.create_session(auth, specs)

        dcr_id = session.publish_data_room(
            low_level_dcr,
            kind=CreateDcrKind.MEDIA_INSIGHTS,
            high_level_representation=dcr_latest.model_dump_json(
                by_alias=True
            ).encode(),
        )
        existing_dcr = MediaDcr._from_existing(
            dcr_id=dcr_id,
            client=self,
            enclave_specs=list(specs.values()),
        )
        return existing_dcr

    def _provision_data_lab_to_midcr(
        self,
        data_room_id: str,
        data_lab_id: str,
    ) -> DataLabDefinition:
        """
        Provision a DataLab to a Media DCR.

        **Parameters**:
        - `data_room_id`: ID of the DCR to provision to.
        - `data_lab_id`: ID of the DataLab to be provisioned.
        """
        data = self._graphql.post(
            """
            mutation ProvisionDataLabToMediaInsightsDcr($input: ProvisionDataLabInput!) {
                dataLab {
                    provisionDataLabToMediaInsightsDcr(input: $input) {
                        publishedDataLab {
                            id
                            name
                            datasets {
                                name
                                dataset {
                                    id
                                    manifestHash
                                    name
                                }
                            }
                            usersDataset {
                                id
                                manifestHash
                                name
                            }
                            segmentsDataset {
                                id
                                manifestHash
                                name
                            }
                            demographicsDataset {
                                id
                                manifestHash
                                name
                            }
                            embeddingsDataset {
                                id
                                manifestHash
                                name
                            }
                            statistics
                            requireDemographicsDataset
                            requireEmbeddingsDataset
                            isValidated
                            numEmbeddings
                            matchingIdFormat
                            matchingIdHashingAlgorithm
                            validationComputeJobId
                            statisticsComputeJobId
                            jobsDriverAttestationHash
                            highLevelRepresentationAsString
                        }
                    }
                }
            }
            """,
            {
                "input": {
                    "dataRoomId": data_room_id,
                    "dataLabId": data_lab_id,
                }
            },
        )
        return data["dataLab"]["provisionDataLabToMediaInsightsDcr"]["publishedDataLab"]

    def _deprovision_data_lab_from_midcr(self, data_room_id: str) -> DataLabDefinition:
        """
        Deprovision a DataLab from a Media DCR.

        **Parameters**:
        - `data_room_id`: ID of the DCR to deprovision from.
        """
        data = self._graphql.post(
            """
            mutation DeprovisionDataLabFromMediaInsightsDcr($input: String!) {
                dataLab {
                    deprovisionDataLabFromMediaInsightsDcr(mediaInsightsDcrId: $input) {
                        publishedDataLab {
                            id
                            name
                            datasets {
                                name
                                dataset {
                                    id
                                    manifestHash
                                    name
                                }
                            }
                            usersDataset {
                                id
                                manifestHash
                                name
                            }
                            segmentsDataset {
                                id
                                manifestHash
                                name
                            }
                            demographicsDataset {
                                id
                                manifestHash
                                name
                            }
                            embeddingsDataset {
                                id
                                manifestHash
                                name
                            }
                            statistics
                            requireDemographicsDataset
                            requireEmbeddingsDataset
                            isValidated
                            numEmbeddings
                            matchingIdFormat
                            matchingIdHashingAlgorithm
                            validationComputeJobId
                            statisticsComputeJobId
                            jobsDriverAttestationHash
                            highLevelRepresentationAsString
                        }
                    }
                }
            }
            """,
            {
                "input": data_room_id,
            },
        )
        return data["dataLab"]["deprovisionDataLabFromMediaInsightsDcr"][
            "publishedDataLab"
        ]


def create_client(
    user_email: str,
    api_token: str,
    *,
    client_id: str = DECENTRIQ_CLIENT_ID,
    api_host: str = DECENTRIQ_HOST,
    api_port: int = DECENTRIQ_PORT,
    api_use_tls: bool = DECENTRIQ_USE_TLS,
    request_timeout: Optional[int] = None,
    unsafe_disable_known_root_ca_check: bool = _DECENTRIQ_UNSAFE_DISABLE_KNOWN_ROOT_CA_CHECK,
) -> Client:
    """
    The primary way to create a `Client` object.

    **Parameters**:
    - `api_token`: An API token with which to authenticate oneself.
        The API token can be obtained in the user
        account settings in the Decentriq UI.
    - `user_email`: The email address of the user that generated the given API token.
    """
    api = Api(
        api_token,
        client_id,
        api_host,
        api_port,
        api_prefix="",
        use_tls=api_use_tls,
        timeout=request_timeout,
    )

    graphql = GqlClient(api, path=Endpoints.GRAPHQL)

    return Client(
        user_email,
        api,
        graphql,
        request_timeout=request_timeout,
        unsafe_disable_known_root_ca_check=unsafe_disable_known_root_ca_check,
    )


class BoundedExecutor:
    def __init__(self, bound, max_workers):
        self.executor = futures.ThreadPoolExecutor(max_workers=max_workers)
        self.semaphore = BoundedSemaphore(bound + max_workers)

    def submit(self, fn, *args, **kwargs):
        def done_callback(f):
            error = f.exception()
            if error:
                logger.error(f"Error in future: {error}")
            self.semaphore.release()

        self.semaphore.acquire()
        try:
            future = self.executor.submit(fn, *args, **kwargs)
        except:
            self.semaphore.release()
            raise
        else:
            future.add_done_callback(done_callback)
            return future

    def shutdown(self, wait=True):
        self.executor.shutdown(wait)
