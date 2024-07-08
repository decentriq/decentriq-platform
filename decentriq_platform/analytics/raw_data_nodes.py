from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional, cast

from decentriq_dcr_compiler.schemas import RawLeafNode
from typing_extensions import Self

from ..session import Session
from .high_level_node import DataNode
from .node_definitions import NodeDefinition

if TYPE_CHECKING:
    from ..client import Client


class RawDataNodeDefinition(NodeDefinition):
    def __init__(
        self,
        name: str,
        is_required: bool,
        id: Optional[str] = None,
    ) -> None:
        """
        Initialise a `RawDataNodeDefinition`:

        **Parameters**:
        - `name`: Name of the `RawDataNodeDefinition`.
        - `is_required`: Defines if the `RawDataNodeDefinition` is required.
        - `id`: Optional id of the `RawDataNodeDefinition`.
        """
        super().__init__(name, id=id or name)
        self.is_required = is_required

    def _get_high_level_representation(self) -> Dict:
        """
        Retrieve the high level representation of the `RawDataNodeDefinition`.
        """
        raw_node = {
            "id": self.id,
            "name": self.name,
            "kind": {"leaf": {"isRequired": self.is_required, "kind": {"raw": {}}}},
        }
        return raw_node

    @classmethod
    def _from_high_level(
        cls,
        id: str,
        name: str,
        _node: RawLeafNode,
        is_required: bool,
    ) -> Self:
        """
        Instantiate a `RawDataNodeDefinition` from its high level representation.

        **Parameters**:
        - `name`: Name of the `RawDataNodeDefinition`.
        - `_node`: Pydantic model of the `RawDataNodeDefinition`.
        - `is_required`: Flag determining if the `RawDataNodeDefinition` must be present for dependent computations.
        """
        return cls(
            id=id,
            name=name,
            is_required=is_required,
        )

    @property
    def required_workers(self):
        return []

    def build(
        self,
        dcr_id: str,
        node_definition: NodeDefinition,
        client: Client,
        session: Session,
    ) -> RawDataNode:
        """
        Construct a RawDataNode from the Node Definition.

        **Parameters**:
        - `dcr_id`: ID of the DCR the node is a member of.
        - `node_definition`: Definition of the Raw Data Node.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        """
        return RawDataNode(
            name=self.name,
            is_required=self.is_required,
            dcr_id=dcr_id,
            node_definition=cast(RawDataNodeDefinition, node_definition),
            client=client,
            session=session,
            id=self.id,
        )


class RawDataNode(DataNode):
    """
    Class representing a Raw Data node.

    Data that is provisioned to a Raw Data Node is assumed to be unstructured. This means that any of the
    SQL node types cannot read from such a Data Node. This is the preferred node type for data such as images
    or binary data. It can, of course, also be used for tabular data files such as CSV or Excel. In this case,
    however, the code reading from the Data Node will have to interpret the data correctly.
    """

    def __init__(
        self,
        id: str,
        name: str,
        is_required: bool,
        dcr_id: str,
        client: Client,
        session: Session,
        node_definition: RawDataNodeDefinition,
    ) -> None:
        """
        Initialise a `RawDataNode` instance.

        **Parameters**:
        - 'id': ID of the `RawDataNode`.
        - `name`: Name of the `RawDataNode`
        - `is_required`: Flag determining if the `RawDataNode` must be present for dependent computations.
        - `dcr_id`: ID of the DCR the node is a member of.
        - `node_definition`: Definition of the Raw Data Node.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        - `node_definition`: Definition of the Raw Data Node.
        """
        super().__init__(
            name=name,
            dcr_id=dcr_id,
            client=client,
            session=session,
            is_required=is_required,
            id=id,
            definition=node_definition,
        )
