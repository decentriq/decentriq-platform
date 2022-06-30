import hashlib
import json
import os
from threading import BoundedSemaphore
from concurrent import futures
from base64 import b64encode
from typing import BinaryIO, List, Dict, Optional
from .api import API, Endpoints
from .authentication import Auth
from .config import (
        DECENTRIQ_CLIENT_ID,
        DECENTRIQ_HOST, DECENTRIQ_PORT, DECENTRIQ_USE_TLS,
        DECENTRIQ_API_PLATFORM_HOST,
        DECENTRIQ_API_PLATFORM_PORT,
        DECENTRIQ_API_PLATFORM_USE_TLS,
        DECENTRIQ_API_CORE_HOST,
        DECENTRIQ_API_CORE_PORT,
        DECENTRIQ_API_CORE_USE_TLS,
)
from .session import Session
from .storage import Key, Chunker, create_encrypted_chunk, StorageCipher
from .types import (
    EnclaveSpecification, EnclaveSpecificationResponse,
    DatasetDescription, FinalizeUpload,
    CreateSessionRequest, SessionJsonResponse,
    UploadDescription, ChunkWrapper,
    CreateScopeRequest, ScopeJson, ScopeTypes
)
from .proto import AttestationSpecification, parse_length_delimited, serialize_length_delimited
from .platform import ClientPlatformFeatures
from .api import ServerError
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

    _api: API
    _platform: Optional[ClientPlatformFeatures]

    def __init__(
            self,
            user_email: str,
            api: API,
            platform: Optional[ClientPlatformFeatures] = None,
            request_timeout: int = None
    ):
        """
        Create a client instance.

        Rather than creating `Client` instances directly using this constructor, use the function
        `create_client`.
        """
        self.user_email = user_email
        self._api = api
        self._platform = platform
        self.request_timeout = request_timeout

    def check_enclave_availability(self, specs: Dict[str, EnclaveSpecification]):
        """
        Check whether the selected enclaves are deployed at this moment.
        If one of the enclaves is not deployed, an exception will be raised.
        """
        available_specs =\
            {spec["proto"].SerializeToString() for spec in self._get_enclave_specifications()}
        for s in specs:
            if s["proto"].SerializeToString() not in available_specs:
                raise Exception(
                    "No available enclave deployed for attestation spec '{name}' (version {version})".\
                        format(name=s["name"], version=s["version"])
                )

    def _get_enclave_specifications(self) -> List[EnclaveSpecification]:
        url = Endpoints.SYSTEM_ATTESTATION_SPECS
        response: EnclaveSpecificationResponse = self._api.get(url).json()
        enclave_specs = []

        for spec_json in response["attestationSpecs"]:
            attestation_specification = AttestationSpecification()
            spec_length_delimited = base64.b64decode(spec_json["spec"])
            parse_length_delimited(spec_length_delimited, attestation_specification)
            enclave_spec = EnclaveSpecification(
                name=spec_json["name"],
                version=spec_json["version"],
                proto=attestation_specification,
                decoder=None,
                workerProtocols=[0],
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
        url = Endpoints.SESSIONS
        if "decentriq.driver" not in enclaves:
            raise Exception(
                "Unable to find a specification for the driver enclave" +
                f" named 'decentriq.driver', you can get these specifications" +
                " from the main package."
            )
        driver_spec = enclaves["decentriq.driver"]

        if "clientProtocols" not in driver_spec:
            raise Exception(
                "Missing client supported protocol versions"
            )
        attestation_proto = driver_spec["proto"]
        client_protocols = driver_spec["clientProtocols"]

        attestation_specification_hash =\
            hashlib.sha256(serialize_length_delimited(attestation_proto)).hexdigest()

        req_body = CreateSessionRequest(
            attestationSpecificationHash=attestation_specification_hash
        )
        response: SessionJsonResponse = self._api.post(
                url,
                json.dumps(req_body),
                {"Content-type": "application/json"}
        ).json()

        platform_api =\
            self.platform._platform_api if self.is_integrated_with_platform else None

        session = Session(
                self,
                response["sessionId"],
                attestation_proto,
                client_protocols,
                auth=auth,
                platform_api=platform_api,
        )

        return session

    def _create_scope(self, email: str, metadata: Dict[str, str]) -> str:
        url = Endpoints.USER_SCOPES_COLLECTION.replace(":userId", email)
        req_body = CreateScopeRequest(metadata=metadata)
        response: ScopeJson = self._api.post(
                url,
                json.dumps(req_body),
                {"Content-type": "application/json"}
        ).json()
        return response["scopeId"]

    def get_scope(self, email: str, scope_id: str) -> ScopeJson:
        url = Endpoints.USER_SCOPE \
                .replace(":userId", email) \
                .replace(":scopeId", scope_id)
        response: ScopeJson = self._api.get(url).json()
        return response

    def get_scope_by_metadata(self, email: str, metadata: Dict[str, str]) -> Optional[str]:
        url = Endpoints.USER_SCOPES_COLLECTION.replace(":userId", email)
        response: List[ScopeJson] = self._api.get(
                url,
                params={"metadata": json.dumps(metadata)}
            ).json()
        if len(response) == 0:
            return None
        else:
            scope = response[0]
            return scope["scopeId"]

    def _ensure_scope_with_metadata(self, email: str, metadata: Dict[str, str]) -> str:
        scope = self.get_scope_by_metadata(email, metadata)
        if scope is None:
            scope = self._create_scope(email, metadata)
        return scope

    def delete_scope(self, email: str, scope_id: str):
        url = Endpoints.USER_SCOPE \
            .replace(":userId", email) \
            .replace(":scopeId", scope_id)
        self._api.delete(url)

    def upload_dataset(
            self,
            data: BinaryIO,
            key: Key,
            file_name: str,
            /, *,
            description: str = "",
            chunk_size: int = 8 * 1024 ** 2,
            parallel_uploads: int = 8,
            owner_email: Optional[str] = None,
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
        - `owner_email`: Owner of the file if different from the one already specified
            when creating the client object.
        """
        uploader = BoundedExecutor(
                bound=parallel_uploads * 2,
                max_workers=parallel_uploads
        )
        email = owner_email if owner_email else self.user_email
        # create and upload chunks
        chunker = Chunker(data, chunk_size=chunk_size)
        chunk_hashes: List[str] = []
        chunk_uploads_futures = []
        upload_description = self._create_upload(email)
        for chunk_hash, chunk_data in chunker:
            chunk_uploads_futures.append(
                uploader.submit(
                    self._encrypt_and_upload_chunk,
                    chunk_hash,
                    chunk_data,
                    key.material,
                    email,
                    upload_description["uploadId"]
                )
            )
            chunk_hashes.append(chunk_hash.hex())

        # check chunks uploads were successful
        completed, pending = futures.wait(
                chunk_uploads_futures,
                None,
                futures.FIRST_EXCEPTION
            )
        if len(pending):
            # re-raise exception
            for future in completed: future.result()
        uploader.shutdown(wait=False)

        # create manifest and upload
        manifest_hash, manifest_encrypted = create_encrypted_chunk(
                key.material,
                os.urandom(16),
                json.dumps(chunk_hashes).encode("utf-8")
        )
        scope_id = self._ensure_scope_with_metadata(email, {"type": ScopeTypes.USER_FILE, "manifest_hash": manifest_hash.hex() })
        self._finalize_upload(
            user_id=email,
            scope_id=scope_id,
            upload_id=upload_description["uploadId"],
            name=file_name,
            manifest_hash=manifest_hash,
            manifest_encrypted=manifest_encrypted,
            chunks=chunk_hashes
        )

        manifest_hash_hex = manifest_hash.hex()

        if self.is_integrated_with_platform:
            self.platform._platform_api.save_dataset_metadata(
                manifest_hash_hex,
                file_name=file_name,
                description=description,
                owner_email=self.user_email
            )

        return manifest_hash_hex

    def _encrypt_and_upload_chunk(
            self,
            chunk_hash: bytes,
            chunk_data: bytes,
            key: bytes,
            user_id: str,
            upload_id: str
    ):
        cipher = StorageCipher(key)
        chunk_data_encrypted = cipher.encrypt(chunk_data)
        self._upload_chunk(chunk_hash, chunk_data_encrypted, user_id, upload_id)

    def _create_upload(self, user_id: str) -> UploadDescription:
        url = Endpoints.USER_UPLOADS_COLLECTION.replace(":userId", user_id)
        response = self._api.post(url, {}, {"Content-type": "application/json"})
        upload_description: UploadDescription = response.json()
        return upload_description

    def _upload_chunk(
            self,
            chunk_hash: bytes,
            chunk_data_encrypted: bytes,
            user_id: str,
            upload_id: str
    ):
        url = Endpoints.USER_UPLOAD_CHUNKS \
            .replace(":userId", user_id) \
            .replace(":uploadId", upload_id)
        wrapped_chunk= ChunkWrapper(
            hash=chunk_hash.hex(),
            data=b64encode(chunk_data_encrypted).decode("ascii")
        )
        self._api.post(url, json.dumps(wrapped_chunk), {"Content-type": "application/json"})

    def _delete_user_upload(self, email: str, upload_id: str):
        url = Endpoints.USER_UPLOAD \
            .replace(":userId", email) \
            .replace(":uploadId", upload_id)
        self._api.delete(url)

    def _get_user_upload(self, email: str, upload_id: str) -> UploadDescription:
        url = Endpoints.USER_UPLOAD.replace(
                ":userId", email
            ).replace(":uploadId", upload_id)
        response = self._api.get(url)
        return response.json()

    def _get_user_uploads_collection(self, email: str) -> List[UploadDescription]:
        url = Endpoints.USER_UPLOADS_COLLECTION.replace(":userId", email)
        response = self._api.get(url)
        return response.json()

    def _finalize_upload(
            self,
            user_id: str,
            scope_id: str,
            upload_id: str,
            name: str,
            manifest_hash: bytes,
            manifest_encrypted: bytes,
            chunks: List[str]
    ) -> DatasetDescription:
        url = Endpoints.USER_FILES \
            .replace(":userId", user_id)
        payload = FinalizeUpload(
            uploadId=upload_id,
            manifest=b64encode(manifest_encrypted).decode("ascii"),
            manifestHash=manifest_hash.hex(),
            name=name,
            chunks=chunks,
            scopeId=scope_id
        )
        dataset_description: DatasetDescription = self._api.post(
            url,
            json.dumps(payload),
            {"Content-type": "application/json"}
        ).json()
        return dataset_description

    def get_dataset(
            self,
            manifest_hash: str
    ) -> Optional[DatasetDescription]:
        """
        Returns information about a user file given a dataset id.
        """
        url = Endpoints.USER_FILE \
            .replace(":userId", self.user_email) \
            .replace(":manifestHash", manifest_hash)
        try:
            response = self._api.get(url).json()
            return DatasetDescription(
                datasetId=response["manifestHash"],
                name=response["filename"],
                creationDate=response["creationDate"],
            )
        except ServerError:
            return None

    def get_all_datasets(self) -> List[DatasetDescription]:
        """
        Returns the list of files uploaded by the user.
        """
        url = Endpoints.USER_FILES \
            .replace(":userId", self.user_email)
        response = self._api.get(url)
        data = response.json()
        result = []
        for dataset in data:
            result.append(
                DatasetDescription(
                    datasetId=dataset["manifestHash"],
                    name=dataset["filename"],
                    creationDate=dataset["creationDate"],
                )
            )
        return result

    def delete_dataset(self, manifest_hash: str, force: bool = False):
        """
        Deletes the dataset with the given id from the Decentriq platform.

        In case the dataset is still published to one or more data rooms,
        an exception will be thrown and the dataset will need to be
        unpublished manually from the respective data rooms using
        `Session.remove_published_dataset`.
        This behavior can be circumvented by using the `force` flag.
        Note, however, that this might put some data rooms in a broken
        state as they might try to read data that does not exist anymore.
        """
        if self.is_integrated_with_platform:
            data_room_ids = self.platform._platform_api.\
                get_data_rooms_with_published_dataset(manifest_hash)
            if data_room_ids:
                list_of_ids = "\n".join([f"- {dcr_id}" for dcr_id in data_room_ids])
                if force:
                    print(
                        "This dataset is published to the following data rooms."
                        " These data rooms might be in a broken state now:"
                        f"\n{list_of_ids}"
                    )
                else:
                    raise Exception(
                        "This dataset is published to the following data rooms"
                        " and needs to be unpublished before it can be deleted!"
                        f"\n{list_of_ids}"
                    )

        url = Endpoints.USER_FILE \
            .replace(":userId", self.user_email) \
            .replace(":manifestHash", manifest_hash)
        self._api.delete(url)

        if self.is_integrated_with_platform:
            try:
                self.platform._platform_api.delete_dataset_metadata(manifest_hash)
            except Exception as e:
                print(f"Error when deleting dataset: {e}")

    @property
    def platform(self) -> ClientPlatformFeatures:
        """
        Provider of a list of convenience methods to interact with the Decentriq platform.

        This field exposes an object that provides a set of features known from the Decentriq
        web platform.
        """
        if self._platform:
            return self._platform
        else:
            raise Exception(
                "This field is not set as the client has not been configured with integration"
                " with the web platform."
            )

    @property
    def is_integrated_with_platform(self) -> bool:
        """Whether this client has been created with platform integration."""
        return self._platform is not None


def create_client(
        user_email: str,
        api_token: str,
        *,
        integrate_with_platform: bool,
        client_id: str = DECENTRIQ_CLIENT_ID,
        api_host: str = DECENTRIQ_HOST,
        api_port: int = DECENTRIQ_PORT,
        api_use_tls: bool = DECENTRIQ_USE_TLS,
        api_core_host: Optional[str] = DECENTRIQ_API_CORE_HOST,
        api_core_port: Optional[int] = DECENTRIQ_API_CORE_PORT,
        api_core_use_tls: Optional[bool] = DECENTRIQ_API_CORE_USE_TLS,
        api_platform_host: Optional[str] = DECENTRIQ_API_PLATFORM_HOST,
        api_platform_port: Optional[int] = DECENTRIQ_API_PLATFORM_PORT,
        api_platform_use_tls: Optional[bool] = DECENTRIQ_API_PLATFORM_USE_TLS,
        request_timeout: Optional[int] = None
) -> Client:
    """
    The primary way to create a `Client` object.

    Client objects created using this method can optionally be integrated with the
    Decentriq UI.
    This means that certain additional features, such as being able to retrieve the list
    of data rooms that you participate in, will be made available via the `Client.platform` field.
    This flag also needs to be set if you want to use the authentication objects that let
    Decentriq act as the root CA that controls access to data rooms.

    In order to provide these features, the client will communicate directly with an API
    that exists outside of the confidential computing environment. This setting will only
    affect how metadata about data rooms (such as their name and id) is stored and retrieved,
    it will not in any way compromise the security of how your data is uploaded to the
    enclaves or how computed results are retrieved.

    **Parameters**:
    - `api_token`: An API token with which to authenticate oneself.
        The API token can be obtained in the user
        account settings in the Decentriq UI.
    - `user_email`: The email address of the user that generated the given API token.
    - `integrate_with_platform`: Whether to configure the client to integrate itself with our web platform.
        When this setting is set to False, none of the features provided via the
        `platform` field will be available.
    """
    api = API(
        api_token,
        client_id,
        api_core_host if api_core_host is not None else api_host,
        api_core_port if api_core_port is not None else api_port,
        api_prefix="/api/core",
        use_tls=api_core_use_tls if api_core_use_tls is not None else api_use_tls,
        timeout=request_timeout
    )

    if integrate_with_platform:
        platform = ClientPlatformFeatures(
            api_token,
            user_email,
            http_api=api,
            client_id=client_id,
            api_host=api_platform_host if api_platform_host is not None else api_host,
            api_port=api_platform_port if api_platform_port is not None else api_port,
            api_use_tls=api_platform_use_tls if api_platform_use_tls is not None else api_use_tls
        )
    else:
        platform = None

    return Client(
        user_email, api, platform, request_timeout=request_timeout
    )


class BoundedExecutor:
    def __init__(self, bound, max_workers):
        self.executor = futures.ThreadPoolExecutor(max_workers=max_workers)
        self.semaphore = BoundedSemaphore(bound + max_workers)

    def submit(self, fn, *args, **kwargs):
        self.semaphore.acquire()
        try:
            future = self.executor.submit(fn, *args, **kwargs)
        except:
            self.semaphore.release()
            raise
        else:
            future.add_done_callback(lambda _: self.semaphore.release())
            return future

    def shutdown(self, wait=True):
        self.executor.shutdown(wait)
