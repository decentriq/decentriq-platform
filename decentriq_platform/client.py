import json
import io
import queue
import os
from concurrent import futures
from typing_extensions import TypedDict
from typing import List, TypeVar, Dict
from .session import B64EncodedMessage, Session, SessionOptions
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
    FileDescription,
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

class EnclaveIdentifiersResponse(TypedDict):
    enclaveIdentifiers: List[str]

class SystemCaResponse(TypedDict):
    rootCertificate: str

class CreateSessionRequest(TypedDict):
    enclaveIdentifier: str

class SessionJsonResponse(TypedDict):
    sessionId: str
    enclaveIdentifier: str

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

    def get_enclave_identifiers(self) -> List[str]:
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
            enclave_identifier: str,
            auth: Dict[str, Auth],
            options: SessionOptions
    ) -> Session:
        url = Endpoints.SESSIONS
        req_body = CreateSessionRequest(enclaveIdentifier=enclave_identifier)
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
        chunker = CsvChunker(csv_input_stream, column_types, os.urandom(16), chunk_size=chunk_size)
        # create manifest
        chunk_hashes = [hash.hex() for hash, _ in chunker]
        digest_hash, digest_encrypted = \
            create_encrypted_json_object_chunk(key.id, key.material, os.urandom(16), chunk_hashes)

        manifest = DatasetManifest()
        manifest.digestHash = digest_hash
        manifest.schema.CopyFrom(schema.proto_schema)

        manifest_hash, manifest_encrypted = \
            create_encrypted_protobuf_object_chunk(key.id, key.material, os.urandom(16), manifest)
        manifest_metadata = DatasetManifestMetadata(
            name=name,
            manifestHash=manifest_hash.hex(),
            # HACK!!! We include the digest hash as a "chunk".
            # This is temporary to avoid changes in the backend logic.
            chunks=chunk_hashes + [digest_hash.hex()]
        )
        file_description = self._upload_manifest(email, manifest_encrypted, manifest_metadata)
        # upload chunks
        chunker.reset()
        for chunk in chunker:
            uploader.submit(
                self._encrypt_and_upload_chunk, chunk[0], chunk[1], key.material, key.id, email,
                file_description["fileId"]
            )
        uploader.submit(self._upload_chunk, digest_hash, digest_encrypted, email, file_description["fileId"])
        uploader.shutdown(wait=True)
        return manifest_hash

    def _encrypt_and_upload_chunk(
            self,
            chunk_hash: bytes,
            chunk_data: bytes,
            key: bytes,
            key_id: bytes,
            user_id: str,
            file_id: str
    ):
        cipher = StorageCipher(key, key_id)
        chunk_data_encrypted = cipher.encrypt(chunk_data)
        self._upload_chunk(chunk_hash, chunk_data_encrypted, user_id, file_id)

    def _upload_chunk(
            self,
            chunk_hash: bytes,
            chunk_data_encrypted: bytes,
            user_id: str,
            file_id: str
    ):
        url = Endpoints.USER_FILE_CHUNK \
            .replace(":userId", user_id) \
            .replace(":fileId", file_id) \
            .replace(":chunkHash", chunk_hash.hex())
        wrapped_chunk= B64EncodedMessage(
                data=b64encode(chunk_data_encrypted).decode("ascii")
        )
        self.api.post(url, json.dumps(wrapped_chunk), {"Content-type": "application/json"})

    def _upload_manifest(
            self,
            user_id: str,
            manifest_encrypted: bytes,
            manifest_metadata: DatasetManifestMetadata
    ) -> FileDescription:
        manifest_metadata_json = json.dumps(dict(manifest_metadata))
        url = Endpoints.USER_FILES_COLLECTION.replace(":userId", user_id)
        parts = {
            "manifest": b64encode(manifest_encrypted).decode("ascii"),
            "metadata": b64encode(bytes(manifest_metadata_json, "utf-8")).decode("ascii")
        }
        response = self.api.post(url, json.dumps(parts), {"Content-type": "application/json"})
        file_description: FileDescription = response.json()
        return file_description

    def delete_user_file(self, email: str, file_id: str):
        url = Endpoints.USER_FILE \
            .replace(":userId", email) \
            .replace(":fileId", file_id)
        self.api.delete(url)

    def get_user_file(self, email: str, file_id: str) -> FileDescription:
        url = Endpoints.USER_FILE.replace(":userId", email).replace(":fileId", file_id)
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
