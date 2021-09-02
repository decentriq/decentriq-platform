from typing import List
from typing_extensions import TypedDict

__all__ = ["EnclaveIdentifier", "FileDescription"]

class UserResponse(TypedDict):
    id: str
    email: str

class UserCsrRequest(TypedDict):
    csrPem: str

class UserCsrResponse(TypedDict):
    certChainPem: str

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

class EnclaveIdentifier(TypedDict):
    """
    This class identifies an enclave service type and version
    """
    enclaveIdentifier: str
    version: str

class ChunkWrapper(TypedDict):
    hash: str
    data: str

class EnclaveIdentifiersResponse(TypedDict):
    enclaveIdentifiers: List[EnclaveIdentifier]

class UploadDescription(TypedDict):
    uploadId: str

class ChunkDescription(TypedDict):
    chunkHash: str

class DataRoomDescription(TypedDict):
    dataRoomId: str
    tableName: str

class PartialFileDescription(TypedDict):
    dataRoomIds: List[DataRoomDescription]

class FileDescription(TypedDict):
    """
    This class includes information about an uploaded dataset
    """
    manifestHash: str
    filename: str
    chunks: List[ChunkDescription]
    dataRoomIds: List[DataRoomDescription]

class SignatureResponse(TypedDict):
    type: str
    data: List[int]


class B64EncodedMessage(TypedDict):
    data: str

class FatquoteResBody(TypedDict):
    signature: SignatureResponse
    response: str
    certificate: str

class DatasetManifestMetadata(TypedDict):
    name: str
    manifestHash: str
    chunks: List[str]

