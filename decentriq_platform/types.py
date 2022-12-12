from google.protobuf.json_format import MessageToDict
from .proto import AttestationSpecification, ComputeNodeProtocol, DriverTaskConfig
from typing import List, Dict, Optional, Any
from typing_extensions import TypedDict
from enum import Enum
from .proto.length_delimited import parse_length_delimited
from .proto.compute_sql_pb2 import SqlWorkerConfiguration
from .container.proto.compute_container_pb2 import ContainerWorkerConfiguration


__all__ = [
    "EnclaveSpecification",
    "JobId",
    "DataRoomDescription",
    "DatasetDescription",
]


class JobId:
    """
    Class for identifying running or already run jobs.

    Objects of this class can be used to retrieve results for processed computations.
    """
    def __init__(self, job_id: str, compute_node_id: str):
        self.id = job_id
        """The identifier of the job that processed a particular computation."""

        self.compute_node_id = compute_node_id
        """The id of the computation that was processed."""


class ScopeTypes(str, Enum):
    DATASET = "DATASET",
    DCR_DATA = "DCR_DATA"


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
    scopeId: str


class ChunkWrapper(TypedDict):
    hash: str
    data: str


class UploadDescription(TypedDict):
    uploadId: str


class ChunkDescription(TypedDict):
    chunkHash: str


class UserDescription(TypedDict):
    id: str
    email: str


class DataRoomDescription(TypedDict):
    """The identifier of the data room"""
    id: str
    """The title that was given to the data room"""
    title: str
    """The hex-encoded hash of the driver attestation specification"""
    driverAttestationHash: str
    """Whether the data room has been stopped"""
    isStopped: bool
    """When the data room was created"""
    createdAt: str
    """When the data room was last updated"""
    updatedAt: str


class DatasetDescription(TypedDict):
    """
    This class includes information about an uploaded dataset
    """
    id: str
    """The identifier of this dataset"""
    manifestHash: str
    """The data set id as a hex-encoded string. This id is also called the manifest hash."""
    name: str
    """The name of this dataset"""
    description: str
    """An optional description"""
    createdAt: str
    """When the dataset was uploaded"""


class SignatureResponse(TypedDict):
    type: str
    data: List[int]


class FatquoteResBody(TypedDict):
    fatquoteBase64: str


class DatasetManifestMetadata(TypedDict):
    name: str
    manifestHash: str
    chunks: List[str]


class EnclaveSpecification(TypedDict):
    """
    This class includes information about an enclave deployed in the platform.
    Please refer to `decentriq_platform.EnclaveSpecifications` for a detailed explanation.
    """
    name: str
    """The name of the enclave."""
    proto: AttestationSpecification
    """The Protobuf object."""
    workerProtocols: List[int]
    """The worker protocol versions supported by the node"""
    decoder: Optional[Any]
    """
    Decoder object that can be used to decode the binary configs belonging
    to enclaves of this type.
    """
    clientProtocols: Optional[List[int]]
    """The client protocol versions supported by the node"""


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
    pcesvn: int


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
