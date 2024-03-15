from __future__ import annotations

from decentriq_dcr_compiler.schemas.data_science_data_room import SqlComputationNode
from .high_level_node import StructuredOutputNode
from typing import Dict, List, Optional
from .node_definitions import NodeDefinition
from ..session import Session
from dataclasses import dataclass
from typing_extensions import Self
from decentriq_dcr_compiler.schemas.data_science_data_room import (
    SqlComputationNode,
)
import json


@dataclass
class TableMapping:
    node_id: str
    table_name: str


class SqlComputeNodeDefinition(NodeDefinition):
    """
    Class representing an SQL Computation Node Definition.
    """

    def __init__(
        self,
        name: str,
        query: str,
        dependencies: Optional[List[TableMapping]] = None,
        minimum_rows_count: Optional[int] = None,
        id: Optional[str] = None,
    ) -> None:
        """
        Initialise a `SqlComputeNodeDefinition`:

        **Parameters**:
        `name`: Name of the `SqlComputeNodeDefinition`.
        `query`: SQL query string.
        `dependencies`: Nodes that the `SqlComputeNodeDefinition` depends on.
        `minimum_rows_count`: Minimum number of rows required by the `SqlComputeNodeDefinition`.
        `id`: Optional ID of the `SqlComputeNodeDefinition`.
        """
        super().__init__(name=name, id=id or name)
        self.query = query
        self.dependencies = dependencies
        self.minimum_rows_count = minimum_rows_count
        self.specification_id = "decentriq.sql-worker"

    def _get_high_level_representation(self) -> Dict[str, str]:
        """
        Retrieve the high level representation of the `SqlComputeNodeDefinition`.
        """
        dependencies = []
        if self.dependencies:
            for dependency in self.dependencies:
                dependencies.append(
                    {
                        "nodeId": dependency.node_id,
                        "tableName": dependency.table_name,
                    }
                )

        sql = {
            "dependencies": dependencies,
            "specificationId": self.specification_id,
            "statement": self.query,
        }
        if self.minimum_rows_count:
            sql["privacyFilter"]["minimumRowsCount"] = self.minimum_rows_count

        computation_node = {
            "id": self.id,
            "name": self.name,
            "kind": {
                "computation": {
                    "kind": {
                        "sql": sql,
                    }
                },
            },
        }
        return computation_node

    @staticmethod
    def _from_high_level(id: str, name: str, node: SqlComputationNode) -> Self:
        """
        Instantiate a `SqlComputeNodeDefinition` from its high level representation.

        **Parameters**:
        - `name`: Name of the `SqlComputeNodeDefinition`.
        - `node`: Pydantic model of the `SqlComputeNode`.
        """
        sql_node = json.loads(node.model_dump_json())
        minimum_rows_count = (
            None
            if not sql_node["privacyFilter"]
            else sql_node["privacyFilter"]["minimumRowsCount"]
        )
        return SqlComputeNodeDefinition(
            id=id,
            name=name,
            query=sql_node["statement"],
            dependencies=sql_node["dependencies"],
            minimum_rows_count=minimum_rows_count,
        )

    def build(
        self,
        dcr_id: str,
        node_definition: NodeDefinition,
        client: Client,
        session: Session,
    ) -> SqlComputeNode:
        """
        Construct a SqlComputeNode from the Node Definition.

        **Parameters**:
        - `dcr_id`: ID of the DCR the node is a member of.
        - `node_definition`: Definition of the SQL Compute Node.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        """
        return SqlComputeNode(
            name=self.name,
            dcr_id=dcr_id,
            query=self.query,
            client=client,
            session=session,
            node_definition=node_definition,
            dependencies=self.dependencies,
            minimum_rows_count=self.minimum_rows_count,
            id=self.id,
        )


class SqlComputeNode(StructuredOutputNode):
    """
    Class representing an SQL Computation Node.
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
        *,
        dependencies: Optional[List[TableMapping]] = None,
        minimum_rows_count: Optional[int] = None,
    ) -> None:
        """
        Initialise a `SqlComputeNode`:

        **Parameters**:
        - `id`: ID of the `SqlComputeNode`.
        - `name`: Name of the `SqlComputeNode`.
        - `dcr_id`: ID of the DCR the node is a member of.
        - `query`: SQL query string.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        - `dependencies`: Nodes that the `SqlComputeNode` depends on.
        - `minimum_rows_count`: Minimum number of rows required by the `SqlComputeNode`.
        """
        super().__init__(
            name=name,
            client=client,
            session=session,
            dcr_id=dcr_id,
            id=id,
            definition=node_definition,
        )
        self.statement = query
        self.dependencies = dependencies
        self.minimum_rows_count = minimum_rows_count
        self.specification_id = "decentriq.sql-worker"

    def _get_computation_id(self) -> str:
        """
        Retrieve the ID of the node corresponding to the computation.
        """
        return self.id
