from __future__ import annotations

import io
from typing import BinaryIO


class GcsCredentials:
    def __init__(self, credentials_json: str) -> None:
        self.credentials_json = credentials_json

    def as_binary_io(self) -> BinaryIO:
        return io.BytesIO(self.credentials_json.encode())
