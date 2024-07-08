from __future__ import annotations

import json
from typing import TYPE_CHECKING, Dict, List, Optional

from decentriq_dcr_compiler.schemas import SqliteComputationNode
from typing_extensions import Self

from ..session import Session
from .high_level_node import StructuredOutputNode
from .node_definitions import NodeDefinition

if TYPE_CHECKING:
    from ..client import Client


class SqliteComputeNodeDefinition(NodeDefinition):
    """
    Class representing an SQLite Computation Node Definition.
    """

    def __init__(
        self,
        name: str,
        query: str,
        dependencies: Optional[List[str]] = None,
        enable_logs_on_error: bool = False,
        enable_logs_on_success: bool = False,
        id: Optional[str] = None,
    ) -> None:
        """
        Initialise a `SqliteComputeNodeDefinition`:

        **Parameters**:
        - `name`: Name of the `SqliteComputeNodeDefinition`.
        - `query`: SQLite query string.
        - `dependencies`: Mappings between node id and the table name under
          which they should be made available.
        - `enable_logs_on_error`: Enable logs in the event of an error.
        - `enable_logs_on_success`: Enable logs when the computation is successful.
        - `id`: Optional ID of the `SqliteComputeNodeDefinition`.
        """
        super().__init__(name=name, id=id or name)
        self.query = query
        self.dependencies = dependencies
        self.enable_logs_on_error = enable_logs_on_error
        self.enable_logs_on_success = enable_logs_on_success
        # SQLite computations use the Python worker under the hood.
        self.specification_id = "decentriq.python-ml-worker-32-64"
        self.static_content_specification_id = "decentriq.driver"

    @property
    def required_workers(self):
        return [self.static_content_specification_id, self.specification_id]

    def _get_high_level_representation(self) -> Dict[str, str]:
        """
        Retrieve the high level representation of the `SqliteComputeNodeDefinition`.
        """
        dependencies = []
        if self.dependencies:
            for dependency in self.dependencies:
                dependencies.append(
                    {
                        "nodeId": dependency,
                        "tableName": dependency,
                    }
                )
        computation_node = {
            "id": self.id,
            "name": self.name,
            "kind": {
                "computation": {
                    "kind": {
                        "sqlite": {
                            "dependencies": dependencies,
                            "enableLogsOnError": self.enable_logs_on_error,
                            "enableLogsOnSuccess": self.enable_logs_on_success,
                            "sqliteSpecificationId": self.specification_id,
                            "statement": self.query,
                            "staticContentSpecificationId": self.static_content_specification_id,
                        }
                    }
                },
            },
        }
        return computation_node

    @classmethod
    def _from_high_level(cls, id: str, name: str, node: SqliteComputationNode) -> Self:
        """
        Instantiate a `SqliteComputeNodeDefinition` from its high level representation.

        **Parameters**:
        - `id`: ID of the `SqliteComputeNode`.
        - `name`: Name of the `SqliteComputeNode`.
        - `node`: Pydantic model of the `SqliteComputeNode`.
        """
        sqlite_node = json.loads(node.model_dump_json())
        return cls(
            id=id,
            name=name,
            query=sqlite_node["statement"],
            dependencies=sqlite_node["dependencies"],
            enable_logs_on_error=sqlite_node["enableLogsOnError"],
            enable_logs_on_success=sqlite_node["enableLogsOnSuccess"],
        )

    def build(
        self,
        dcr_id: str,
        node_definition: NodeDefinition,
        client: Client,
        session: Session,
    ) -> SqliteComputeNode:
        """
        Construct a SqliteComputeNode from the Node Definition.

        **Parameters**:
        - `dcr_id`: ID of the DCR the node is a member of.
        - `node_definition`: Definition of the SQLite Compute Node.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        """
        return SqliteComputeNode(
            name=self.name,
            dcr_id=dcr_id,
            query=self.query,
            client=client,
            session=session,
            node_definition=node_definition,
            dependencies=self.dependencies,
            enable_logs_on_error=self.enable_logs_on_error,
            enable_logs_on_success=self.enable_logs_on_success,
            id=self.id,
        )


class SqliteComputeNode(StructuredOutputNode):
    """
    Class representing an SQLite Computation node.
    """

    def __init__(
        self,
        id: str,
        name: str,
        dcr_id: str,
        query: str,
        client: Client,
        session: Session,
        node_definition: NodeDefinition,
        dependencies: Optional[List[str]] = None,
        enable_logs_on_error: bool = False,
        enable_logs_on_success: bool = False,
    ) -> None:
        """
        Initialise a `SqliteComputeNode`:

        **Parameters**:
        - `id`: ID of the `SqliteComputeNode`.
        - `name`: Name of the `SqliteComputeNode`.
        - `dcr_id`: ID of the DCR the node is a member of.
        - `query`: SQLite query string.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        - `dependencies`: Nodes that the `SqliteComputeNode` depends on.
        - `enable_logs_on_error`: Enable logs in the event of an error.
        - `enable_logs_on_success`: Enable logs when the computation is successful.
        """
        super().__init__(
            name=name,
            client=client,
            session=session,
            dcr_id=dcr_id,
            id=id,
            definition=node_definition,
        )
        self.query = query
        self.dependencies = dependencies
        self.enable_logs_on_error = enable_logs_on_error
        self.enable_logs_on_success = enable_logs_on_success
        # SQLite computations use the Python worker under the hood.
        self.specification_id = "decentriq.python-ml-worker-32-64"
        self.static_content_specification_id = "decentriq.driver"

    def _get_computation_id(self) -> str:
        """
        Retrieve the ID of the node corresponding to the computation.
        """
        return f"{self.id}_container"
