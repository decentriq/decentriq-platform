from enum import Enum
from typing import Any, Dict, List, Optional, TypeAlias

from typing_extensions import TypedDict

from .proto import AttestationSpecification
from .storage import Key

JSONType: TypeAlias = dict[str, "JSONType"] | list["JSONType"] | str | int | float | bool | None

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
    DATASET = "DATASET"
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


class DataRoomKind(str, Enum):
    EXPERT = "EXPERT"
    DATA_SCIENCE = "DATA_SCIENCE"
    MEDIA = "MEDIA"
    LOOKALIKE_MEDIA = "LOOKALIKE_MEDIA"


class Owner(TypedDict):
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
    """Email address of the data room owner"""
    owner: Owner
    """The kind of data room"""
    kind: DataRoomKind


class DatasetUsage(str, Enum):
    PUBLISHED = "PUBLISHED"
    TEST = "TEST"


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
    size: int
    """Size of the dataset"""
    usage: DatasetUsage
    """Usage"""
    encryptionKeySecretId: Optional[str]
    """Secret store entry id for the encryption key"""
    metadataSecretId: Optional[str]
    """Secret store entry id for the metadata"""


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
    version: str

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


class TestDataset(TypedDict):
    manifest_hash: str
    key: Key


class DryRunOptions(TypedDict):
    test_datasets: Dict[str, TestDataset]


# The matching ID specified by the user.
class MatchingId(str, Enum):
    """
    The type of Matching ID to use.
    """

    STRING = "STRING"
    EMAIL = "EMAIL"
    HASHED_EMAIL = "HASHED_EMAIL"
    PHONE_NUMBER = "PHONE_NUMBER"
    HASHED_PHONE_NUMBER = "HASHED_PHONE_NUMBER"


# Internal Matching ID used by the SDK.
# Maps to the above user specified `MatchingId`.
class MatchingIdFormat(str, Enum):
    STRING = "STRING"
    EMAIL = "EMAIL"
    HASH_SHA256_HEX = "HASH_SHA256_HEX"
    PHONE_NUMBER_E164 = "PHONE_NUMBER_E164"


class TableColumnHashingAlgorithm(str, Enum):
    SHA256_HEX = "SHA256_HEX"


class DataLabDatasetType(Enum):
    EMBEDDINGS = 1
    DEMOGRAPHICS = 2
    MATCH = 3
    SEGMENTS = 4


class Dataset(TypedDict):
    id: str
    manifestHash: str
    name: str


class DataLabDataset(TypedDict):
    name: str
    dataset: Dataset


class DataLabDefinition(TypedDict):
    id: str
    name: str
    datasets: List[DataLabDataset]
    usersDataset: Dataset
    segmentsDataset: Dataset
    demographicsDataset: Dataset
    embeddingsDataset: Dataset
    statistics: str
    requireDemographicsDataset: bool
    requireEmbeddingsDataset: bool
    isValidated: bool
    numEmbeddings: int
    matchingIdFormat: MatchingIdFormat
    matchingIdHashingAlgorithm: TableColumnHashingAlgorithm
    validationComputeJobId: str
    statisticsComputeJobId: str
    jobsDriverAttestationHash: str
    highLevelRepresentationAsString: str
    createdAt: str
    updatedAt: str


class DataLabListFilter(Enum):
    VALIDATED = 1  # List validated DataLabs
    UNVALIDATED = 2  # List un-validated DataLabs


class DataRoom(TypedDict):
    id: str
    title: str
    kind: DataRoomKind
    createdAt: str
    updatedAt: str
    owner: UserResponse


class CreateMediaComputeJobInput(TypedDict):
    publishedDataRoomId: str
    computeNodeName: str
    cacheKey: str
    jobType: str
    jobIdHex: str


class MediaComputeJobFilterInput(TypedDict):
    publishedDataRoomId: str
    jobType: str
    cacheKey: str


class MediaComputeJob(TypedDict):
    jobIdHex: str
    publishedDataRoomId: str
    computeNodeName: str
    jobType: str
    cacheKey: str
    createdAt: str


class PublishedDataset(TypedDict):
    leafId: str
    user: str
    timestamp: int
    datasetHash: bytes


class OverlapInsightsCacheKey(TypedDict):
    dataRoomId: str
    advertiserDatasetHash: Optional[str]
    publisherUsersDatasetHash: Optional[str]
    publisherSegmentsDatasetHash: Optional[str]
    publisherDemographicsDatasetHash: Optional[str]
    publisherEmbeddingsDatasetHash: Optional[str]
    publishedDatasets: List[PublishedDataset]


MATCHING_ID_INTERNAL_LOOKUP = {
    MatchingId.STRING: (MatchingIdFormat.STRING, None),
    MatchingId.EMAIL: (MatchingIdFormat.EMAIL, None),
    MatchingId.HASHED_EMAIL: (
        MatchingIdFormat.EMAIL,
        TableColumnHashingAlgorithm.SHA256_HEX,
    ),
    MatchingId.PHONE_NUMBER: (MatchingIdFormat.PHONE_NUMBER_E164, None),
    MatchingId.HASHED_PHONE_NUMBER: (
        MatchingIdFormat.PHONE_NUMBER_E164,
        TableColumnHashingAlgorithm.SHA256_HEX,
    ),
}

class OrganizationUser(TypedDict):
    id: str
    email: str
    migrationCompletedAt: Optional[str]
    needsMigration: bool
