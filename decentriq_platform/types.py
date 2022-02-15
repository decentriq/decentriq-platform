from .proto import AttestationSpecification
from typing import List, Dict
from typing_extensions import TypedDict
from enum import Enum


class JobId:
    """
    Class for identifying running or already run jobs.

    Objects of this class can be used to retrieve results for processed computations.
    """
    def __init__(self, job_id: str, compute_node_name: str):
        self.id = job_id
        """The identifier of the job that processed a particular computation."""

        self.compute_node_name = compute_node_name
        """The name of the computation that was processed."""


class ScopeTypes(str, Enum):
    USER_FILE = "user_file",
    DATA_ROOM_DEFINITION = "dataroom_definition",
    DATA_ROOM_INTERMEDIATE_DATA = "dataroom_intermediate_data"


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
    attestationSpecificationHash: str


class SessionJsonResponse(TypedDict):
    sessionId: str
    attestationSpecificationHash: str


class FinalizeUpload(TypedDict):
    uploadId: str
    manifest: str
    name: str
    manifestHash: str
    chunks: List[str]


class ChunkWrapper(TypedDict):
    hash: str
    data: str


class UploadDescription(TypedDict):
    uploadId: str


class ChunkDescription(TypedDict):
    chunkHash: str


class DataRoomDescription(TypedDict):
    dataRoomId: str
    name: str
    description: str
    mrenclave: str
    ownerEmail: str
    status: str


class DatasetDescription(TypedDict):
    """
    This class includes information about an uploaded dataset
    """
    manifestHash: str
    """"""
    filename: str
    """"""
    description: str
    ownerEmail: str
    chunks: List[ChunkDescription]


class SignatureResponse(TypedDict):
    type: str
    data: List[int]


class EnclaveMessage(TypedDict):
    data: str


class FatquoteResBody(TypedDict):
    fatquoteBase64: str


class DatasetManifestMetadata(TypedDict):
    name: str
    manifestHash: str
    chunks: List[str]


class EnclaveSpecification(TypedDict):
    """
    This class includes information about an enclave deployed in the platform.
    Please refer to `decentriq_platform.EnclaveSpecifications` for a detailed explaination.
    """
    name: str
    """The name of the enclave."""
    version: str
    """The version of the enclave."""
    proto: AttestationSpecification
    """The Protobuf object."""


class CreateScopeRequest(TypedDict):
    metadata: Dict[str, str]


class ScopeJson(TypedDict):
    scopeId: str
    metadata: Dict[str, str]


class EnclaveSpecificationJson(TypedDict):
    name: str
    version: str
    spec: str


class EnclaveSpecificationResponse(TypedDict):
    attestationSpecs: List[EnclaveSpecificationJson]


class Tcb(TypedDict):
    sgxtcbcomp01svn: int
    sgxtcbcomp02svn: int
    sgxtcbcomp03svn: int
    sgxtcbcomp04svn: int
    sgxtcbcomp05svn: int
    sgxtcbcomp06svn: int
    sgxtcbcomp07svn: int
    sgxtcbcomp08svn: int
    sgxtcbcomp09svn: int
    sgxtcbcomp10svn: int
    sgxtcbcomp11svn: int
    sgxtcbcomp12svn: int
    sgxtcbcomp13svn: int
    sgxtcbcomp14svn: int
    sgxtcbcomp15svn: int
    sgxtcbcomp16svn: int


class TcbLevel(TypedDict):
    tcb: Tcb
    tcbStatus: str


class TcbInfo(TypedDict):
    version: int
    issueDate: str
    nextUpdate: str
    fmspc: str
    pceId: str
    tcbType: int
    tcbEvaluationDataNumber: int
    tcbLevels: List[TcbLevel]


class TcbInfoContainer(TypedDict):
    tcbInfo: TcbInfo
    signature: str


class IasResponse(TypedDict):
    isvEnclaveQuoteBody: str
    isvEnclaveQuoteStatus: str
