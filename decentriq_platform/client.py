import json
import io
import queue
import os
from concurrent import futures
from typing_extensions import TypedDict
from typing import List, TypeVar, Dict, Tuple
from .session import Session, SessionOptions
from .config import (
        DECENTRIQ_CLIENT_ID, DECENTRIQ_HOST, DECENTRIQ_PORT, DECENTRIQ_USE_TLS
)
from .api import API, Endpoints
from .authentication import generate_csr, generate_key, Auth
from base64 import b64encode
from .proto.waterfront_pb2 import (
    DatasetManifest,
)
from .storage import (
    Key, Schema,
    create_encrypted_json_object_chunk,
    create_encrypted_protobuf_object_chunk,
    CsvChunker,
    ChunkWrapper,
    FileDescription,
    UploadDescription,
    DatasetManifestMetadata,
    StorageCipher
)

class UserResponse(TypedDict):
    id: str
    email: str


class UserCsrRequest(TypedDict):
    csrPem: str

class UserCsrResponse(TypedDict):
    certChainPem: str

class EnclaveIdentifier(TypedDict):
    enclaveIdentifier: str
    version: str

class EnclaveIdentifiersResponse(TypedDict):
    enclaveIdentifiers: List[EnclaveIdentifier]

class SystemCaResponse(TypedDict):
    rootCertificate: str

class CreateSessionRequest(TypedDict):
    enclaveIdentifier: str

class SessionJsonResponse(TypedDict):
    sessionId: str
    enclaveIdentifier: str

class FinalizeUpload(TypedDict):
    uploadId: str
    manifest: str
    name: str
    manifestHash: str
    chunks: List[str]

class Client:
    def __init__(
            self,
            api_token: str,
            client_id: str = DECENTRIQ_CLIENT_ID,
            host: str = DECENTRIQ_HOST,
            port: int = DECENTRIQ_PORT,
            use_tls: bool = DECENTRIQ_USE_TLS,
    ):
        self.api = API(
            api_token,
            client_id,
            host,
            port,
            use_tls
        )

    def get_ca_root_certificate(self) -> bytes:
        url = Endpoints.SYSTEM_CERTIFICATE_AUTHORITY
        response = self.api.get(url).json()
        return response["rootCertificate"].encode("utf-8")

    def get_enclave_identifiers(self) -> List[EnclaveIdentifier]:
        url = Endpoints.SYSTEM_ENCLAVE_IDENTIFIERS
        response: EnclaveIdentifiersResponse = self.api.get(url).json()
        return response["enclaveIdentifiers"]

    def create_auth(self, email: str, access_token: str = None) -> Auth:
        keypair = generate_key()
        csr = generate_csr(email, keypair)
        url = Endpoints.USER_CERTIFICATE.replace(":userId", email)
        csr_req = UserCsrRequest(csrPem=csr.decode("utf-8"))
        resp: UserCsrResponse = self.api.post(url, req_body=json.dumps(csr_req)).json()
        cert_chain_pem = resp["certChainPem"].encode("utf-8")
        auth = Auth(cert_chain_pem, keypair, email, access_token)
        return auth

    def create_session(
            self,
            enclave_identifier: EnclaveIdentifier,
            auth: Dict[str, Auth],
            options: SessionOptions
    ) -> Session:
        url = Endpoints.SESSIONS
        req_body = CreateSessionRequest(enclaveIdentifier=enclave_identifier["enclaveIdentifier"])
        response: SessionJsonResponse = self.api.post(
                url,
                json.dumps(req_body),
                {"Content-type": "application/json"}
        ).json()
        session = Session(
                self,
                response["sessionId"],
                response["enclaveIdentifier"],
                auth,
                options
        )
        return session

    S = TypeVar("S", bound=io.TextIOBase)

    # Uploads csv_input_stream as a dataset usable by enclaves
    def upload_dataset(
            self,
            email: str,
            name: str,
            csv_input_stream: S,
            schema: Schema,
            key: Key,
            chunk_size: int = 8 * 1024 ** 2,
            parallel_uploads: int = 8
    ) -> bytes:
        uploader = ThreadPoolExecutorWithQueueSizeLimit(max_workers=parallel_uploads, maxsize=parallel_uploads * 2)
        column_types = [named_column.columnType for named_column in schema.proto_schema.namedColumns]

        # create and upload chunks
        chunker = CsvChunker(csv_input_stream, column_types, chunk_size=chunk_size)
        chunk_hashes = []
        chunk_uploads_futures = []
        upload_description = self._create_upload(email)
        for chunk_hash, chunk_data in chunker:
            chunk_uploads_futures.append(
                uploader.submit(
                    self._encrypt_and_upload_chunk,
                    chunk_hash,
                    chunk_data,
                    key.material,
                    key.id,
                    email,
                    upload_description["uploadId"]
                )
            )
            chunk_hashes.append(chunk_hash.hex())

        # create digest chunks list and upload
        digest_hash, digest_encrypted = \
            create_encrypted_json_object_chunk(key.id, key.material, os.urandom(16), chunk_hashes)
        chunk_uploads_futures.append(
            uploader.submit(
                self._upload_chunk,
                digest_hash,
                digest_encrypted,
                email,
                upload_description["uploadId"]
            )
        )
        # check chunks uploads were successful
        completed, pending = futures.wait(chunk_uploads_futures, None, futures.FIRST_EXCEPTION)
        if len(pending):
            # reraise exception
            for future in completed: future.result()
        uploader.shutdown(wait=False)

        # create manifest and upload
        manifest = DatasetManifest()
        manifest.digestHash = digest_hash
        manifest.schema.CopyFrom(schema.proto_schema)
        manifest_hash, manifest_encrypted = \
            create_encrypted_protobuf_object_chunk(key.id, key.material, os.urandom(16), manifest)
        self._finalize_upload(
            user_id=email,
            upload_id=upload_description["uploadId"],
            name=name,
            manifest_hash=manifest_hash,
            manifest_encrypted=manifest_encrypted,
            # HACK!!! We include the digest hash as a "chunk".
            # This is temporary to avoid changes in the backend logic.
            chunks=chunk_hashes + [digest_hash.hex()]
        )
        return manifest_hash

    def _encrypt_and_upload_chunk(
            self,
            chunk_hash: bytes,
            chunk_data: bytes,
            key: bytes,
            key_id: bytes,
            user_id: str,
            upload_id: str
    ):
        cipher = StorageCipher(key, key_id)
        chunk_data_encrypted = cipher.encrypt(chunk_data)
        self._upload_chunk(chunk_hash, chunk_data_encrypted, user_id, upload_id)

    def _create_upload(self, user_id: str) -> UploadDescription:
        url = Endpoints.USER_UPLOADS_COLLECTION.replace(":userId", user_id)
        response = self.api.post(url, {}, {"Content-type": "application/json"})
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
        self.api.post(url, json.dumps(wrapped_chunk), {"Content-type": "application/json"})

    def _delete_user_upload(self, email: str, upload_id: str):
        url = Endpoints.USER_UPLOAD \
            .replace(":userId", email) \
            .replace(":uploadId", upload_id)
        self.api.delete(url)

    def _get_user_upload(self, email: str, upload_id: str) -> UploadDescription:
        url = Endpoints.USER_UPLOAD.replace(":userId", email).replace(":uploadId", upload_id)
        response = self.api.get(url)
        return response.json()

    def _get_user_uploads_collection(self, email: str) -> List[UploadDescription]:
        url = Endpoints.USER_UPLOADS_COLLECTION.replace(":userId", email)
        response = self.api.get(url)
        return response.json()

    def _finalize_upload(
            self,
            user_id: str,
            upload_id: str,
            name: str,
            manifest_hash: bytes,
            manifest_encrypted: bytes,
            chunks: List[str]
    ) -> FileDescription:
        url = Endpoints.USER_FILES_COLLECTION.replace(":userId", user_id)
        payload = FinalizeUpload(
            uploadId=upload_id,
            manifest=b64encode(manifest_encrypted).decode("ascii"),
            manifestHash=manifest_hash.hex(),
            name=name,
            chunks=chunks
        )
        file_description: FileDescription = self.api.post(
            url,
            json.dumps(payload),
            {"Content-type": "application/json"}
        ).json()
        return file_description


    def delete_user_file(self, email: str, manifest_hash: str):
        url = Endpoints.USER_FILE \
            .replace(":userId", email) \
            .replace(":manifestHash", manifest_hash)
        self.api.delete(url)

    def get_user_file(self, email: str, manifest_hash: str) -> FileDescription:
        url = Endpoints.USER_FILE.replace(":userId", email).replace(":manifestHash", manifest_hash)
        response = self.api.get(url)
        return response.json()

    def get_user_files_collection(self, email: str) -> List[FileDescription]:
        url = Endpoints.USER_FILES_COLLECTION.replace(":userId", email)
        response = self.api.get(url)
        return response.json()

class ThreadPoolExecutorWithQueueSizeLimit(futures.ThreadPoolExecutor):
    def __init__(self, maxsize=50, *args, **kwargs):
        super(ThreadPoolExecutorWithQueueSizeLimit, self).__init__(*args, **kwargs)
        self._work_queue = queue.Queue(maxsize=maxsize) # type: ignore
