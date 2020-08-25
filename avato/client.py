from concurrent.futures import ThreadPoolExecutor, wait
import json
from typing import List
from .config import AVATO_HOST, AVATO_PORT, AVATO_USE_SSL
from .api import API, Endpoints
from .storage import FileFormat, FileManifestBuilder, ChunkerBuilder, FileDescription, FileManifestMetadata, \
    FileManifest, StorageCipher


class Client:
    class UnknownInstanceTypeError(Exception):
        """Raised when the instance type requested is not supported"""
        pass

    class UnknownUserEmail(Exception):
        """Raised when the user email doesn't exist"""
        pass

    class FileUploadError(Exception):
        """Raised when file upload fails"""
        pass

    def __init__(
        self,
        api_token,
        instance_types=[],
        backend_host=AVATO_HOST,
        backend_port=AVATO_PORT,
        use_ssl=AVATO_USE_SSL,
        http_proxy=None,
        https_proxy=None,
    ):
        self.registered_instances = instance_types
        self.api = API(
            api_token,
            backend_host,
            backend_port,
            use_ssl,
            http_proxy,
            https_proxy,
        )

    def get_instances(self):
        url = Endpoints.INSTANCES_COLLECTION
        response = self.api.get(url)
        return response.json()

    def _instance_from_type(self, type):
        for instance in self.registered_instances:
            if instance.type == type:
                return instance
        raise Client.UnknownInstanceTypeError

    def _get_user_id(self, email: str):
        url = f"{Endpoints.USERS_COLLECTION}?email={email}"
        response = self.api.get(url)
        users = response.json()
        if len(users) != 1:
            raise Client.UnknownUserEmail
        user_id = users[0]["id"]
        return user_id

    def get_instance(self, id):
        url = Endpoints.INSTANCE.replace(":instanceId", id)
        response = self.api.get(url)
        instance_info = response.json()
        instance_constructor = self._instance_from_type(instance_info["type"])
        return instance_constructor(
            self,
            id,
            instance_info["name"],
            instance_info["owner"],
        )

    def create_instance(self, name, type, participants):
        url = Endpoints.INSTANCES_COLLECTION
        data = {
            "name": name,
            "type": type,
            "participants": list(map(lambda x: {"id": self._get_user_id(x)}, participants)),
        }
        data_json = json.dumps(data)
        response = self.api.post(url, data_json, {"Content-type": "application/json"})
        response_json = response.json()
        instance_constructor = self._instance_from_type(type)
        return instance_constructor(self, response_json["id"], name, response_json["owner"])

    def upload_user_file(
        self,
        email: str,
        file_name: str,
        file_path: str,
        file_format: FileFormat,
        key=None,
        parallel_uploads=2
    ) -> FileDescription:
        user_id = self._get_user_id(email)
        uploader = ThreadPoolExecutor(max_workers=parallel_uploads)
        with ChunkerBuilder(file_path, file_format) as chunker:
            # create manifest
            file_manifest_builder = FileManifestBuilder(file_name, file_format, key is not None)
            for chunk_hash, _ in chunker:
                file_manifest_builder.add_chunk(chunk_hash)
            (manifest, manifest_metadata) = file_manifest_builder.build()
            print("manifest chunks:")
            print(file_manifest_builder.chunks)
            cipher = None
            if key is not None:
                cipher = StorageCipher(key)
                manifest.content = cipher.encrypt(manifest.content)
            file_description = self._upload_manifest(user_id, manifest, manifest_metadata)
            # upload chunks
            chunker.reset()
            uploading = []
            for chunk_hash, chunk_data in chunker:
                url = Endpoints.USER_FILE_CHUNK \
                        .replace(":userId", user_id) \
                        .replace(":fileId", file_description.get("id")) \
                        .replace(":chunkHash", chunk_hash)
                if cipher is not None:
                    chunk_data = cipher.encrypt(chunk_data)
                uploading.append(uploader.submit(self.api.post, url, chunk_data, {"Content-type": "application/octet-stream"}))
            wait(uploading)
        return self.get_user_file(email, file_description.get("id"))

    def _upload_manifest(self, user_id: str, manifest: FileManifest, manifest_metadata: FileManifestMetadata) -> FileDescription:
        manifest_metadata_json = json.dumps(dict(manifest_metadata))
        url = Endpoints.USER_FILES_COLLECTION.replace(":userId", user_id)
        parts = {
                "manifest": manifest.content,
                "metadata": manifest_metadata_json
                }
        response = self.api.post_multipart(url, parts)
        file_description: FileDescription = response.json()
        return file_description

    def delete_user_file(self, email: str, file_id: str):
        url = Endpoints.USER_FILE \
            .replace(":userId", self._get_user_id(email)) \
            .replace(":fileId", file_id)
        self.api.delete(url)

    def get_user_file(self, email: str, file_id: str) -> FileDescription:
        url = Endpoints.USER_FILE.replace(":userId", self._get_user_id(email)).replace(":fileId", file_id)
        response = self.api.get(url)
        return response.json()

    def get_user_files_collection(self, email: str) -> List[FileDescription]:
        url = Endpoints.USER_FILES_COLLECTION.replace(":userId", self._get_user_id(email))
        response = self.api.get(url)
        return response.json()
