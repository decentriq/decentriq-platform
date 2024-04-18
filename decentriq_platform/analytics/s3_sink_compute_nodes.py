from __future__ import annotations

import json
from enum import Enum
from typing import TYPE_CHECKING, Dict, Optional

from decentriq_dcr_compiler.schemas.data_science_data_room import S3SinkComputationNode
from typing_extensions import Self

from ..session import Session
from .high_level_node import ComputationNode
from .node_definitions import NodeDefinition

if TYPE_CHECKING:
    from ..client import Client


class S3Provider(str, Enum):
    AWS = "Aws"
    GCS = "Gcs"


class S3SinkComputeNodeDefinition(NodeDefinition):
    """
    Class representing an S3 Sink Computation node.
    """

    def __init__(
        self,
        name: str,
        credentials_dependency_id: str,
        endpoint: str,
        region: str,
        dependency: str,
        provider: S3Provider = S3Provider.AWS,
        id: Optional[str] = None,
    ) -> None:
        """
        Initialise a `S3SinkComputeNodeDefinition`:

        **Parameters**:
        `name`: Name of the `S3SinkComputeNodeDefinition`.
        `credentials_dependency_id`: ID of the `S3SinkComputeNodeDefinition` dependency.
        `endpoint`: Endpoint where data will be uploaded.
        `region`: Region where the data will be uploaded.
        `dependency`: Node that the `S3SinkComputeNodeDefinition` depends on.
        `provider`: Type of S3 provider (AWS/GCS).
        `id`: Optional ID of the `S3SinkComputeNodeDefinition`.
        """
        super().__init__(name=name, id=id or name)
        self.credentials_dependency_id = credentials_dependency_id
        self.endpoint = endpoint
        self.region = region
        self.dependency = dependency
        self.provider = provider
        self.specification_id = "decentriq.s3-sink-worker"

    @property
    def required_workers(self):
        return [self.specification_id]

    def _get_high_level_representation(self) -> Dict[str, str]:
        """
        Retrieve the high level representation of the `S3SinkComputeNodeDefinition`.
        """
        computation_node = {
            "id": self.id,
            "name": self.name,
            "kind": {
                "computation": {
                    "kind": {
                        "s3Sink": {
                            "credentialsDependencyId": self.credentials_dependency_id,
                            "endpoint": self.endpoint,
                            "region": self.region,
                            "s3Provider": self.provider.value,
                            "specificationId": self.specification_id,
                            "uploadDependencyId": self.dependency,
                        }
                    }
                },
            },
        }
        return computation_node

    @classmethod
    def _from_high_level(cls, id: str, name: str, node: S3SinkComputationNode) -> Self:
        """
        Instantiate a `S3SinkComputeNodeDefinition` from its high level representation.

        **Parameters**:
        - `name`: Name of the `S3SinkComputeNodeDefinition`.
        - `node`: Pydantic model of the `S3SinkComputeNode`.
        """
        s3_sink_node = json.loads(node.model_dump_json())
        return cls(
            name=name,
            credentials_dependency_id=s3_sink_node["credentialsDependencyId"],
            endpoint=s3_sink_node["endpoint"],
            region=s3_sink_node["region"],
            dependency=s3_sink_node["uploadDependencyId"],
            provider=s3_sink_node["s3Provider"],
            id=id,
        )

    def build(
        self,
        dcr_id: str,
        node_definition: NodeDefinition,
        client: Client,
        session: Session,
    ) -> S3SinkComputeNode:
        """
        Construct a S3SinkComputeNode from the Node Definition.

        **Parameters**:
        - `dcr_id`: ID of the DCR the node is a member of.
        - `node_definition`: Definition of the S3 Sink Compute Node.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        """
        return S3SinkComputeNode(
            name=self.name,
            dcr_id=dcr_id,
            credentials_dependency_id=self.credentials_dependency_id,
            endpoint=self.endpoint,
            region=self.region,
            dependency=self.dependency,
            client=client,
            session=session,
            node_definition=node_definition,
            id=self.id,
            provider=self.provider,
        )


class S3SinkComputeNode(ComputationNode):
    """
    Class representing an S3 Sink Computation node.
    """

    def __init__(
        self,
        id: str,
        name: str,
        dcr_id: str,
        credentials_dependency_id: str,
        endpoint: str,
        region: str,
        dependency: str,
        client: Client,
        session: Session,
        node_definition: NodeDefinition,
        provider: Optional[S3Provider] = S3Provider.AWS,
    ) -> None:
        """
        Initialise a `S3SinkComputeNode`:

        **Parameters**:
        - `id`: ID of the `S3SinkComputeNode`.
        - `name`: Name of the `S3SinkComputeNode`.
        - `dcr_id`: ID of the DCR the node is a member of.
        - `credentials_dependency_id`: ID of the `S3SinkComputeNode` dependency.
        - `endpoint`: Endpoint where data will be uploaded.
        - `region`: Region where the data will be uploaded.
        - `dependency`: Node that the `S3SinkComputeNode` depends on.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        - `node_definition`: Definition of the Raw Data Node.
        - `provider`: Type of S3 provider (AWS/GCS).
        """
        super().__init__(
            name=name,
            client=client,
            session=session,
            dcr_id=dcr_id,
            id=id,
            definition=node_definition,
        )
        self.credentials_dependency_id = credentials_dependency_id
        self.endpoint = endpoint
        self.region = region
        self.upload_dependency_id = dependency
        self.provider = provider
        self.specification_id = "decentriq.s3-sink-worker"

    def _get_computation_id(self) -> str:
        """
        Retrieve the ID of the node corresponding to the computation.
        """
        return self.id
