from typing import BinaryIO, List, Dict, Optional, Tuple
from .endorsement import Endorser

import hashlib
import json
import os
from threading import BoundedSemaphore
from concurrent import futures
from base64 import b64decode, b64encode

from .api import Api
from .authentication import Auth, generate_key, generate_self_signed_certificate
from .config import (
        DECENTRIQ_CLIENT_ID,
        DECENTRIQ_HOST,
        DECENTRIQ_PORT,
        DECENTRIQ_USE_TLS,
)
from .session import LATEST_WORKER_PROTOCOL_VERSION, Session
from .storage import Key, Chunker, create_encrypted_chunk, StorageCipher
from .types import (
    DatasetUsage,
    EnclaveSpecification,
    DatasetDescription,
    DataRoomDescription,
    KeychainInstance,
)
from .api import NotFoundError
from .proto import (
    AttestationSpecification,
    parse_length_delimited,
    serialize_length_delimited,
    AuthenticationMethod,
    PkiPolicy
)
from .api import (
    Endpoints,
    retry
)
from .graphql import GqlClient

import base64


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

    def __init__(
            self,
            user_email: str,
            api: Api,
            graphql: GqlClient,
            request_timeout: int = None
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

    def check_enclave_availability(self, specs: Dict[str, EnclaveSpecification]):
        """
        Check whether the selected enclaves are deployed at this moment.
        If one of the enclaves is not deployed, an exception will be raised.
        """
        available_specs =\
            [spec["proto"].SerializeToString() for spec in self._get_enclave_specifications()]
        for spec in specs.values():
            if spec["proto"].SerializeToString() not in available_specs:
                raise Exception(
                    "No available enclave deployed for attestation spec '{name}' (version {version})".\
                        format(name=spec["name"], version=spec["version"])
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
            spec_length_delimited = base64.b64decode(spec_json["spec"])
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
                "Unable to find a specification for the driver enclave" +
                f" named 'decentriq.driver', you can get these specifications" +
                " from the main package."
            )
        driver_spec = enclaves["decentriq.driver"]

        if "clientProtocols" not in driver_spec or driver_spec["clientProtocols"] is None:
            raise Exception(
                "Missing client supported protocol versions"
            )
        attestation_proto = driver_spec["proto"]
        client_protocols = driver_spec["clientProtocols"]

        attestation_specification_hash =\
            hashlib.sha256(serialize_length_delimited(attestation_proto)).hexdigest()

        data = self._graphql.post(
            """
            mutation CreateSession($input: CreateSessionInput!) {
                session {
                    create(input: $input) {
                        record {
                            id
                        }
                    }
                }
            }
            """,
            {
                "input": {
                    "enclaveAttestationHash": attestation_specification_hash,
                }
            }
        )
        session_id = data["session"]["create"]["record"]["id"]
        session = Session(
            self,
            session_id,
            attestation_proto,
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
            {
                "input": payload
            }
        )
        scope = data["scope"]["getOrCreateDatasetScope"]["record"]
        return scope["id"]

    def _ensure_dcr_data_scope(
            self,
            data_room_hash: str,
            driver_attestation_hash: str,
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
                    "driverAttestationHash": driver_attestation_hash,
                }
            }
        )
        scope = data["scope"]["getOrCreateDcrDataScope"]["record"]
        return scope["id"]

    def upload_dataset(
            self,
            data: BinaryIO,
            key: Key,
            file_name: str,
            /, *,
            description: str = "",
            chunk_size: int = 8 * 1024 ** 2,
            parallel_uploads: int = 8,
            usage: DatasetUsage = DatasetUsage.PUBLISHED
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
        - `organization`: The name of the organization under which this dataset
            should be uploaded. This option is useful if the current user's own parent
            organization does not currently have a license with Decentriq and therefore
            is not able to provide resources for user-uploaded datasets.
            Note that even using this feature, the specified organization will not be
            able to read the uploaded dataset.
        """
        uploader = BoundedExecutor(
                bound=parallel_uploads * 2,
                max_workers=parallel_uploads
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
                chunk_uploads_futures,
                None,
                futures.FIRST_EXCEPTION
            )
        # re-raise exception
        for future in completed: future.result()
        uploader.shutdown(wait=False)

        # create manifest and upload
        manifest_hash, manifest_encrypted = create_encrypted_chunk(
            key.material,
            os.urandom(16),
            json.dumps(chunk_hashes).encode("utf-8"),
            content_size=chunker.content_size,
            chunk_content_sizes=chunk_content_sizes,
        )
        scope_id = self._ensure_dataset_scope(
            manifest_hash.hex(),
        )
        manifest_hash = self._finalize_upload(
            scope_id=scope_id,
            upload_id=upload_id,
            name=file_name,
            manifest_hash=manifest_hash,
            manifest_encrypted=manifest_encrypted,
            chunks=chunk_hashes,
            description=description,
            usage=usage,
        )

        return manifest_hash

    def _encrypt_and_upload_chunk(
            self,
            chunk_hash: bytes,
            chunk_data: bytes,
            key: bytes,
            upload_id: str
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
            self,
            chunk_hash: bytes,
            chunk_data_encrypted: bytes,
            upload_id: str
    ):
        url = Endpoints.USER_UPLOAD_CHUNKS \
            .replace(":uploadId", upload_id) \
            .replace(":chunkHash", chunk_hash.hex())
        try:
            self._api.put(
                url,
                chunk_data_encrypted,
                {"Content-type": "application/octet-stream"},
                retry=retry,
            )
        except Exception as e:
            print(e)
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
            {
                "id": upload_id
            }
        )

    def _finalize_upload(
            self,
            scope_id: str,
            upload_id: str,
            name: str,
            manifest_hash: bytes,
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
                    "manifestHash": manifest_hash.hex(),
                    "name": name,
                    "description": description,
                    "usage": usage,
                    "chunkHashes": chunks,
                    "scopeId": scope_id
                }
            },
            retry=retry
        )

        dataset = data["upload"]["finalizeUploadAndCreateDataset"]["record"]
        manifest_hash = dataset["manifestHash"]

        return manifest_hash

    def get_dataset(
            self,
            manifest_hash: str
    ) -> Optional[DatasetDescription]:
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
                {
                    "manifestHash": manifest_hash
                }
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
        data_rooms_ids_with_dataset = self._get_data_room_ids_for_publication(manifest_hash)
        if data_rooms_ids_with_dataset:
            id_list = "\n".join([f"- {dcr_id}" for dcr_id in data_rooms_ids_with_dataset])
            if force:
                print(
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
            }
        )

    @property
    def decentriq_ca_root_certificate(self) -> bytes:
        """
        Returns the root certificate used by the Decentriq identity provider.
        Note that when using this certificate in any authentication scheme,
        you trust Decentriq as an identity provider!
        """
        data = self._graphql.post("""
            {
                certificateAuthority {
                    rootCertificate
                }
            }
        """)
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
        return AuthenticationMethod(
            dqPki=PkiPolicy(rootCertificatePem=root_pki)
        )

    def create_auth_using_decentriq_pki(
        self,
        enclaves: Dict[str, EnclaveSpecification]
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
                    }
                }
            }
            """
        )
        return [DataRoomDescription(**item) for item in data["publishedDataRooms"]["nodes"]]

    def get_data_room_description(
            self,
            data_room_hash,
            enclave_specs
    ) -> Optional[DataRoomDescription]:
        """
        Get a single data room description.
        """
        driver_spec = enclave_specs["decentriq.driver"]
        attestation_proto = driver_spec["proto"]
        driver_attestation_hash = hashlib.sha256(
            serialize_length_delimited(attestation_proto)
        ).hexdigest()
        return self._get_data_room_by_hash(
            data_room_hash,
            driver_attestation_hash
        )

    def _get_data_room_by_hash(
            self,
            data_room_hash: str,
            driver_attestation_hash: str
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
                }
            }
            """,
            {
                "dataRoomHash": data_room_hash,
                "driverAttestationHash": driver_attestation_hash,
            }
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
        data = self._graphql.post("""
            query getUserCertificate($input: UserCsrInput!) {
                certificateAuthority {
                    userCertificate(input: $input)
                }
            }
            """, {
                "input": {
                    "csrPem": csr_pem,
                    "email": email,
                }
            }
        )
        cert_chain_pem = data["certificateAuthority"]["userCertificate"]
        return cert_chain_pem

    def _get_data_rooms_with_published_dataset(self, manifest_hash) -> List[DataRoomDescription]:
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
                                }
                            }
                        }
                    }
                }
                """,
                {
                    "manifestHash": manifest_hash,
                }
            )
            publications = data["datasetByManifestHash"]["publications"]["nodes"]

            if publications:
                dcrs = [publication["dataRoom"] for publication in publications]
                deduplicated_dcrs = ({ dcr["id"]: dcr for dcr in dcrs }).values()
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
            {
                "scopeId": scope_id
            }
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
                    "encrypted": b64encode(encrypted).decode('ascii')
                }
            }
        )
        keychain = data["keychain"]["create"]
        keychain["encrypted"] = b64decode(keychain["encrypted"])
        return keychain

    def compare_and_swap_keychain(
            self,
            cas_index: int,
            salt: Optional[str] = None,
            encrypted: Optional[bytes] = None,
    ) -> KeychainInstance:
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
                    "encrypted": b64encode(encrypted).decode('ascii'),
                    "casIndex": cas_index,
                }
            }
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


def create_client(
        user_email: str,
        api_token: str,
        *,
        client_id: str = DECENTRIQ_CLIENT_ID,
        api_host: str = DECENTRIQ_HOST,
        api_port: int = DECENTRIQ_PORT,
        api_use_tls: bool = DECENTRIQ_USE_TLS,
        request_timeout: Optional[int] = None
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
        timeout=request_timeout
    )

    graphql = GqlClient(api, path=Endpoints.GRAPHQL)

    return Client(
        user_email,
        api,
        graphql,
        request_timeout=request_timeout
    )


class BoundedExecutor:
    def __init__(self, bound, max_workers):
        self.executor = futures.ThreadPoolExecutor(max_workers=max_workers)
        self.semaphore = BoundedSemaphore(bound + max_workers)

    def submit(self, fn, *args, **kwargs):
        def done_callback(f):
            error = f.exception()
            if error:
                print(f"Error in future: {error}")
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
