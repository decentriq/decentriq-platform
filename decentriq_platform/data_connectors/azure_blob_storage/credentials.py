import json
from typing import BinaryIO
import io


class AzureBlobStorageCredentials:
    def __init__(
        self,
        storage_account: str,
        storage_container: str,
        blob_name: str,
        sas_token: str,
    ) -> None:
        self.storage_account = storage_account
        self.storage_container = storage_container
        self.blob_name = blob_name
        self.sas_token = sas_token

    def as_binary_io(self) -> BinaryIO:
        credentials = {
            "storageAccount": self.storage_account,
            "storageContainer": self.storage_container,
            "blobName": self.blob_name,
            "sasToken": self.sas_token,
        }
        return io.BytesIO(json.dumps(credentials).encode())
