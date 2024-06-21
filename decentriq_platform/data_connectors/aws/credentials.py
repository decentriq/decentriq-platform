import io, json
from typing import BinaryIO

class AwsCredentials:
    def __init__(self, access_key: str, secret_key: str) -> None:
        self.access_key = access_key
        self.secret_key = secret_key

    def as_binary_io(self) -> BinaryIO:
        credentials = {
            "accessKey": self.access_key,
            "secretKey": self.secret_key,
        }
        return io.BytesIO(json.dumps(credentials).encode())