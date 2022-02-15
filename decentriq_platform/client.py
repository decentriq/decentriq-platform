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
        DECENTRIQ_CLIENT_ID, DECENTRIQ_HOST, DECENTRIQ_PORT, DECENTRIQ_USE_TLS,
)
from .session import Session
from .storage import Key, Chunker, create_encrypted_chunk, StorageCipher
from .types import (
    EnclaveSpecification, EnclaveSpecificationResponse,
    DatasetDescription, FinalizeUpload,
    CreateSessionRequest, SessionJsonResponse,
    UploadDescription, ChunkWrapper,
    CreateScopeRequest, ScopeJson, ScopeTypes,
)
from .proto import AttestationSpecification, parse_length_delimited, serialize_length_delimited
from .platform import ClientPlatformFeatures
import base64


class Client:
    """
    A `Client` object allows you to upload datasets and to create `Session` objects that
    can communicate with enclaves and perform essential operations such as publishing
    data rooms and execute computations and retrieve results.

    Objects of this class can be used to create and run data rooms, as well as to securely
    upload data and retrieve computation results.

    Objects of this class should be created using the `create_client` function.
    this class.
    """

    _api: API
    _platform: Optional[ClientPlatformFeatures]

    def __init__(
            self,
            user_email: str,
            api: API,
            platform: Optional[ClientPlatformFeatures] = None
    ):
        """
        Create a client instance.

        Rather than creating `Client` instances directly using this constructor, use the function
        `create_client`.
        """
        self.user_email = user_email
        self._api = api
        self._platform = platform

    def create_enclave_spec_set(
            self,
            specs: List[EnclaveSpecification],
            check_availability: bool = True
    ) -> Dict[str, EnclaveSpecification]:
        """
        Create an enclave spec set from a list of `EnclaveSpecification`s, optionally checking
        whether corresponding enclaves are deployed at this moment.

        **Parameters**:
        - `specs`: A list of enclave specs obtained by concatenating the specs found in
            the compute packages.
        - `check_availability`: Whether to check if there are currently enclaves running that
            match the chosen enclave specs. If this is not the case, an exception will be thrown.

        **Returns**:
        An enclave spec set that can be used together with `create_session` or `DataRoomBuilder`.
        """
        if check_availability:
            available_specs =\
                {spec["proto"].SerializeToString() for spec in self._get_enclave_specifications()}
            for s in specs:
                if s["proto"].SerializeToString() not in available_specs:
                    raise Exception(
                        "No available enclave deployed for attestation spec '{name}' (version {version})".\
                            format(name=s["name"], version=s["version"])
                    )

        return { spec["name"]: spec for spec in specs }

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
                proto=attestation_specification
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
        with an enclave service with the specified identifier.

        Messages sent thorugh this session will be authenticated
        with the authentication object identifier specified during a call.
        """
        url = Endpoints.SESSIONS
        attestation_proto = enclaves["decentriq.driver"]["proto"]

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

        session = Session(
                self,
                response["sessionId"],
                attestation_proto,
                auth,
                auth.user_id
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

    def _get_scope(self, email: str, scope_id: str) -> ScopeJson:
        url = Endpoints.USER_SCOPE \
                .replace(":userId", email) \
                .replace(":scopeId", scope_id)
        response: ScopeJson = self._api.get(url).json()
        return response

    def _get_scope_by_metadata(self, email: str, metadata: Dict[str, str]) -> Optional[str]:
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
        scope = self._get_scope_by_metadata(email, metadata)
        if scope is None:
            scope = self._create_scope(email, metadata)
        return scope

    def _delete_scope(self, email: str, scope_id: str):
        url = Endpoints.USER_SCOPE \
            .replace(":userId", email) \
            .replace(":scopeId", scope_id)
        self._api.delete(url)

    def upload_dataset(
            self,
            file_input_stream: BinaryIO,
            key: Key,
            /, *,
            description: str,
            chunk_size: int = 8 * 1024 ** 2,
            parallel_uploads: int = 8,
            owner_email: Optional[str] = None,
    ) -> str:
        """
        Uploads `file_input_stream` as a file usable by enclaves and returns the
        corresponding manifest hash

        **Parameters**:
        - `owner_email`: owner of the file
        - `file_input_stream`: file content
        - `description`: file description
        - `key`: key used to encrypt the file
        """
        uploader = BoundedExecutor(
                bound=parallel_uploads * 2,
                max_workers=parallel_uploads
        )
        email = owner_email if owner_email else self.user_email
        # create and upload chunks
        chunker = Chunker(file_input_stream, chunk_size=chunk_size)
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
        scope_id = self._ensure_scope_with_metadata(email, {"type": ScopeTypes.USER_FILE})
        self._finalize_upload(
            user_id=email,
            scope_id=scope_id,
            upload_id=upload_description["uploadId"],
            name=description,
            manifest_hash=manifest_hash,
            manifest_encrypted=manifest_encrypted,
            chunks=chunk_hashes
        )
        return manifest_hash.hex()

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
        url = Endpoints.USER_FILES_COLLECTION \
            .replace(":userId", user_id) \
            .replace(":scopeId", scope_id)
        payload = FinalizeUpload(
            uploadId=upload_id,
            manifest=b64encode(manifest_encrypted).decode("ascii"),
            manifestHash=manifest_hash.hex(),
            name=name,
            chunks=chunks
        )
        dataset_description: DatasetDescription = self._api.post(
            url,
            json.dumps(payload),
            {"Content-type": "application/json"}
        ).json()
        return dataset_description

    def get_dataset(
            self,
            email: str,
            manifest_hash: str
    ) -> DatasetDescription:
        """
        Returns informations about a user file
        """
        scope_id = self._ensure_scope_with_metadata(email, {"type": ScopeTypes.USER_FILE})
        url = Endpoints.USER_FILE \
            .replace(":userId", email) \
            .replace(":scopeId", scope_id) \
            .replace(":manifestHash", manifest_hash)
        response = self._api.get(url)
        return response.json()

    def get_all_datasets(
            self,
            email: str,
    ) -> List[DatasetDescription]:
        """
        Returns the list of files uploaded by a user
        """
        scope_id = self._ensure_scope_with_metadata(email, {"type": ScopeTypes.USER_FILE})
        url = Endpoints.USER_FILES_COLLECTION \
            .replace(":userId", email) \
            .replace(":scopeId", scope_id)
        response = self._api.get(url)
        data = response.json()

        return data

    def delete_dataset(self, email: str, manifest_hash: str):
        """
        Deletes a user file from the decentriq platform
        """
        scope_id = self._ensure_scope_with_metadata(email, {"type": ScopeTypes.USER_FILE})
        url = Endpoints.USER_FILE \
            .replace(":userId", email) \
            .replace(":scopeId", scope_id) \
            .replace(":manifestHash", manifest_hash)
        self._api.delete(url)

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
        """Whether this client has been created with platform integration"""
        return self._platform is not None


def create_client(
        user_email: str,
        api_token: str,
        *,
        integrate_with_platform: bool,
        client_id: str = DECENTRIQ_CLIENT_ID,
        api_core_host: str = DECENTRIQ_HOST,
        api_core_port: int = DECENTRIQ_PORT,
        api_core_use_tls: bool = DECENTRIQ_USE_TLS
) -> Client:
    """
    The primary way to create a `Client` object.

    Client objects created using this method can optionally be integrated with the
    Decentriq web platform (<http://platform.decentriq.ch>).
    This needs to be set if you want to use the authentication objects that let Decentriq
    act as the root CA that controls access to data rooms.

    **Parameters**:
    - `api_token`: An API token with which to authenticate onself.
        The API token can be obtained in the user
        panel of the decentriq platform <https://platform.decentriq.com/tokens>.
    - `user_email`: The email address of the user that generated the given API token.
    - `integrate_with_platform`: Whether to configure the client to integrate itself with our web platform.
        When this setting is set to False, none of the features provided via the
        `platform` field will be available.
    """
    api = API(
        api_token,
        client_id,
        api_core_host,
        api_core_port,
        api_prefix="/api/core",
        use_tls=api_core_use_tls
    )

    if integrate_with_platform:
        platform = ClientPlatformFeatures(
            user_email,
            http_api=api,
        )
    else:
        platform = None

    return Client(user_email, api, platform)


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
