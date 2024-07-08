from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Dict, List, Optional

from decentriq_dcr_compiler.schemas import (
    MatchingComputationNode,
)
from typing_extensions import Self

from ..session import Session
from .high_level_node import ContainerComputationNode
from .node_definitions import NodeDefinition

if TYPE_CHECKING:
    from ..client import Client


@dataclass
class MatchingComputeNodeConfig:
    query: List[str]
    round: int
    epsilon: int
    sensitivity: int
    dependency_paths: List[str]


class MatchingComputeNodeDefinition(NodeDefinition):
    """
    Class definining the structure of a MatchingComputeNode.

    A MatchingComputeNode can be used to join two datasets based on common
    columns.
    """

    def __init__(
        self,
        name: str,
        config: MatchingComputeNodeConfig,
        dependencies: List[str],
        enable_logs_on_error: bool = False,
        enable_logs_on_success: bool = False,
        output: Optional[str] = "/output",
        id: Optional[str] = None,
    ) -> None:
        """
        Initialise a `MatchingComputeNodeDefinition`:

        **Parameters**:
        `name`: Name of the `MatchingComputeNodeDefinition`.
        `config`: Configuration of the `MatchingComputeNodeDefinition`.
        `dependencies`: Nodes that the `MatchingComputeNodeDefinition` depends on.
        `enable_logs_on_error`: Enable logs in the event of an error.
        `enable_logs_on_success`: Enable logs when the computation is successful.
        `output`: Directory where the results will be written.
        """
        super().__init__(name=name, id=id or name)
        self.config = config
        self.dependencies = dependencies
        self.enable_logs_on_error = enable_logs_on_error
        self.enable_logs_on_success = enable_logs_on_success
        self.output = output
        self.specification_id = "decentriq.python-ml-worker-32-64"
        self.static_content_specification_id = "decentriq.driver"

    @property
    def required_workers(self):
        return [self.specification_id, self.static_content_specification_id]

    def _get_high_level_representation(self) -> Dict[str, str]:
        """
        Retrieve the high level representation of the `MatchingComputeNodeDefinition`.
        """
        dependencies = [] if not self.dependencies else self.dependencies
        computation_node = {
            "id": self.id,
            "name": self.name,
            "kind": {
                "computation": {
                    "kind": {
                        "match": {
                            "config": json.dumps(asdict(self.config)),
                            "dependencies": dependencies,
                            "enableLogsOnError": self.enable_logs_on_error,
                            "enableLogsOnSuccess": self.enable_logs_on_success,
                            "output": self.output,
                            "specificationId": self.specification_id,
                            "staticContentSpecificationId": self.static_content_specification_id,
                        }
                    }
                },
            },
        }
        return computation_node

    @classmethod
    def _from_high_level(
        cls, id: str, name: str, node: MatchingComputationNode
    ) -> Self:
        """
        Instantiate a `MatchingComputeNode` from its high level representation.

        **Parameters**:
        - `name`: Name of the `MatchingComputeNode`.
        - `node`: Pydantic model of the `MatchingComputeNode`.
        """
        matching_node = json.loads(node.model_dump_json())
        return cls(
            name=name,
            config=json.loads(matching_node["config"]),
            dependencies=matching_node["dependencies"],
            enable_logs_on_error=matching_node["enableLogsOnError"],
            enable_logs_on_success=matching_node["enableLogsOnSuccess"],
            output=matching_node["output"],
            id=id,
        )

    def build(
        self,
        dcr_id: str,
        node_definition: NodeDefinition,
        client: Client,
        session: Session,
    ) -> MatchingComputeNode:
        """
        Construct a MatchingComputeNode from the Node Definition.

        **Parameters**:
        - `dcr_id`: ID of the DCR the node is a member of.
        - `node_definition`: Definition of the Matching Node.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        """
        return MatchingComputeNode(
            name=self.name,
            dcr_id=dcr_id,
            config=self.config,
            dependencies=self.dependencies,
            client=client,
            session=session,
            node_definition=node_definition,
            enable_logs_on_error=self.enable_logs_on_error,
            enable_logs_on_success=self.enable_logs_on_success,
            id=self.id,
        )


class MatchingComputeNode(ContainerComputationNode):
    """
    Class representing a Matching Compute Node.

    A MatchingComputeNode can be used to join two datasets based on common
    columns.
    """

    def __init__(
        self,
        id: str,
        name: str,
        dcr_id: str,
        config: MatchingComputeNodeConfig,
        dependencies: List[str],
        client: Client,
        session: Session,
        node_definition: NodeDefinition,
        enable_logs_on_error: bool = False,
        enable_logs_on_success: bool = False,
        output: Optional[str] = "/output",
    ) -> None:
        """
        Initialise a `MatchingComputeNode`:

        **Parameters**:
        - `name`: Name of the `MatchingComputeNode`.
        - `dcr_id`: ID of the DCR this node is part of.
        - `config`: Configuration of the `MatchingComputeNode`.
        - `dependencies`: Nodes that the `MatchingComputeNode` depends on.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        - `node_definition`: Definition with which this node was built.
        `enable_logs_on_error`: Enable logs in the event of an error.
        `enable_logs_on_success`: Enable logs when the computation is successful.
        `output`: Directory where the results will be written.
        `id`: Optional ID of the `MatchingComputeNode`.
        """
        super().__init__(
            name=name,
            client=client,
            session=session,
            dcr_id=dcr_id,
            id=id,
            definition=node_definition,
        )
        self.config = config
        self.dependencies = dependencies
        self.enable_logs_on_error = enable_logs_on_error
        self.enable_logs_on_success = enable_logs_on_success
        self.output = output
        self.specification_id = "decentriq.python-ml-worker-32-64"
        self.static_content_specification_id = "decentriq.driver"

    def _get_computation_id(self) -> str:
        """
        Retrieve the ID of the node corresponding to the computation.
        """
        return f"{self.id}_match_filter_node"
