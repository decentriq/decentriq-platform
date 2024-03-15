from __future__ import annotations

from typing import Dict, List, Optional, Union, Any
from .high_level_node import DataNode, ComputationNode
from ..session import Session
from .existing_builder import ExistingAnalyticsDcrBuilder
from ..attestation import enclave_specifications
from typing_extensions import Self
from .node_definitions import NodeDefinition
from typing_extensions import Self


class AnalyticsDcrDefinition:
    """
    A class representing an Analytics DCR Definition.
    """

    def __init__(self, name: str, high_level: Dict[str, Any]) -> None:
        self.name = name
        self.high_level = high_level

    def _get_high_level_representation(self) -> Dict[str, Any]:
        return self.high_level


class AnalyticsDcr:
    """
    A class representing an Analytics DCR.
    """

    def __init__(
        self,
        session: Session,
        dcr_id: str,
        high_level: Dict[str, str],
        nodes: List[NodeDefinition],
        *,
        client: Client,
    ):
        """
        Initialise an Analytics DCR.

        **Parameters**:
        - `session`: A `Session` object which can be used for communication with the enclave.
        - `dcr_id`: ID of the Analytics DCR.
        - `high_level`: High level representation of the Analytics DCR.
        - `nodes`: List of Data Node Definitions in the Analytics DCR.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        """
        self.client = client
        self.session = session
        self.high_level = high_level
        self.node_definitions = nodes
        self.id = dcr_id

    def get_node(self, name: str) -> Optional[Union[ComputationNode, DataNode]]:
        """
        Retrieve a node with the given name.

        **Parameters**:
        - `name`: Node name.
        """
        for node_def in self.node_definitions:
            if node_def.name == name:
                node = node_def.build(
                    dcr_id=self.id,
                    node_definition=node_def,
                    client=self.client,
                    session=self.session,
                )
                return node
        return None

    @staticmethod
    def _from_existing(
        dcr_id: str,
        *,
        client: Client,
        enclave_specs: Optional[List[EnclaveSpecification]] = None,
    ) -> Self:
        """
        Construct a Analytics DCR from an existing DCR with the given ID.

        **Parameters**:
        - `dcr_id`: Data Clean Room ID.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `enclave_specs`: Determines the types of enclaves that are supported by this Data Clean Room.
            If not specified, the latest enclave specifications will be used.
        """
        data_room_descriptions = client.get_data_room_descriptions()
        existing_data_room_description = [
            description
            for description in data_room_descriptions
            if description["id"] == dcr_id
        ]
        if len(existing_data_room_description) != 1:
            raise Exception(
                f"Unable to retrieve data room description for data room with ID {dcr_id}"
            )
        specs = enclave_specs if enclave_specs else enclave_specifications.all()
        session = client.create_session_from_data_room_description(
            existing_data_room_description[0], specs
        )
        existing_dcr_builder = ExistingAnalyticsDcrBuilder(dcr_id, client, session)
        cfg = existing_dcr_builder.get_configuration()
        dcr = AnalyticsDcr(
            client=client,
            session=session,
            dcr_id=dcr_id,
            high_level=existing_dcr_builder.high_level,
            nodes=cfg.node_definitions,
        )
        return dcr
