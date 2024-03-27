from __future__ import annotations

from decentriq_dcr_compiler.schemas.data_science_data_room import PreviewComputationNode
from .high_level_node import ComputationNode
from typing import Dict, List, Optional
from .node_definitions import NodeDefinition
from ..session import Session
from typing_extensions import Self
import json


class PreviewComputeNodeDefinition(NodeDefinition):
    """
    Class representing a Preview (Airlock) Compute Node Definition.
    """

    def __init__(
        self,
        name: str,
        dependency: str,
        quota_bytes: Optional[int] = 0,
        id: Optional[str] = None,
    ) -> None:
        """
        Initialise a `PreviewComputeNodeDefinition`:

        **Parameters**:
        `name`: Name of the `PreviewComputeNodeDefinition`.
        `dependency`: Node that the `PreviewComputeNodeDefinition` depends on.
        `quota_bytes`: Threshold for amount of data that can be previewed.
        """
        super().__init__(name=name, id=id or name)
        self.quota_bytes = quota_bytes
        self.specification_id = "decentriq.python-ml-worker-32-64"
        self.dependency = dependency

    def _get_high_level_representation(self) -> Dict[str, str]:
        """
        Retrieve the high level representation of the `PreviewComputeNodeDefinition`.
        """
        computation_node = {
            "id": self.id,
            "name": self.name,
            "kind": {
                "computation": {
                    "kind": {
                        "preview": {
                            "dependency": self.dependency,
                            "quotaBytes": self.quota_bytes,
                        }
                    }
                },
            },
        }
        return computation_node

    @staticmethod
    def _from_high_level(id: str, name: str, node: PreviewComputationNode) -> Self:
        """
        Instantiate a `PreviewComputeNodeDefinition` from its high level representation.

        **Parameters**:
        - `name`: Name of the `PreviewComputeNodeDefinition`.
        - `node`: Pydantic model of the `PreviewComputeNode`.
        """
        preview_node = json.loads(node.model_dump_json())
        return PreviewComputeNodeDefinition(
            id=id,
            name=name,
            dependency=preview_node["dependency"],
            quota_bytes=preview_node["quotaBytes"],
        )

    def build(
        self,
        dcr_id: str,
        node_definition: NodeDefinition,
        client: Client,
        session: Session,
    ) -> PreviewComputeNode:
        """
        Construct a PreviewComputeNode from the Node Definition.

        **Parameters**:
        - `dcr_id`: ID of the DCR the node is a member of.
        - `node_definition`: Definition of the Matching Node.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        """
        return PreviewComputeNode(
            name=self.name,
            dcr_id=dcr_id,
            dependency=self.dependency,
            client=client,
            session=session,
            node_definition=node_definition,
            quota_bytes=self.quota_bytes,
            id=self.id,
        )


class PreviewComputeNode(ComputationNode):
    """
    Class representing a Preview (Airlock) Computation node.
    """

    def __init__(
        self,
        id: str,
        name: str,
        dcr_id: str,
        dependency: str,
        client: Client,
        session: Session,
        node_definition: NodeDefinition,
        quota_bytes: Optional[int] = 0,
    ) -> None:
        """
        Initialise a `PreviewComputeNode`:

        **Parameters**:
        - `name`: Name of the `PreviewComputeNode`.
        - `dcr_id`: ID of the DCR this node is part of.
        - `dependency`: Node that the `PreviewComputeNode` depends on.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.o
        - `node_definition`: Definition of the Preview Node.
        - `quota_bytes`: Threshold for amount of data that can be previewed.
        - `id`: ID of the `PreviewComputeNode`.
        """
        super().__init__(
            name=name,
            client=client,
            session=session,
            dcr_id=dcr_id,
            id=id,
            definition=node_definition,
        )
        self.dependency = dependency
        self.quota_bytes = quota_bytes
        self.specification_id = "decentriq.python-ml-worker-32-64"
        self.node_definition = node_definition

    def _get_computation_id(self) -> str:
        """
        Retrieve the ID of the node corresponding to the computation.
        """
        return self.id
