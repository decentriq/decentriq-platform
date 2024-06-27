from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from typing_extensions import Self

from ..attestation import enclave_specifications
from ..session import Session
from ..types import EnclaveSpecification
from .existing_builder import ExistingAnalyticsDcrBuilder
from .high_level_node import ComputationNode, DataNode
from .node_definitions import NodeDefinition
from .version import DATA_SCIENCE_DCR_SUPPORTED_VERSION

if TYPE_CHECKING:
    from ..client import Client


class AnalyticsDcrDefinition:
    """
    A class representing an Analytics DCR Definition.
    """

    def __init__(
        self,
        name: str,
        high_level: Dict[str, Any],
        enclave_specs: Optional[Dict[str, EnclaveSpecification]] = None,
    ) -> None:
        self.name = name
        self.high_level = high_level
        self.enclave_specs = enclave_specs

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

    def retrieve_audit_log(self) -> str:
        """
        Retrieve the Analytics DCR audit log.
        """
        return self.session.retrieve_audit_log(self.id).log.decode("utf-8")

    def stop(self):
        """
        Stop the Analytics DCR.
        """
        self.session.stop_data_room(self.id)

    @classmethod
    def _from_existing(
        cls,
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
        dcr = cls(
            client=client,
            session=session,
            dcr_id=dcr_id,
            high_level=existing_dcr_builder.high_level,
            nodes=cfg.node_definitions,
        )
        return dcr

    def participants(self) -> List[str]:
        """
        Retrieve the participants of the Analytics DCR as a list.
        """
        keys = list(self.high_level.keys())
        if len(keys) != 1:
            raise Exception(
                f"Unable to extract Analytics DCR version. Expected a single top-level property indicating the DCR version."
            )
        dcr_version = keys[0]

        dcr = self.high_level[dcr_version]
        keys = list(dcr.keys())
        if len(keys) != 1:
            raise Exception(
                f"Unable to extract the interactivity type for the Analytics DCR. Expected a single top-level property indicating the interactivity type."
            )

        dcr_type = keys[0]
        if dcr_type == "interactive":
            participants = dcr[dcr_type]["initialConfiguration"]["participants"]
        elif dcr_type == "static":
            participants = dcr[dcr_type]["participants"]
        else:
            raise Exception(
                f'Unknown DCR type {dcr_type}. Expected "interactive" or "static" type.'
            )
        return [participant["user"] for participant in participants]
