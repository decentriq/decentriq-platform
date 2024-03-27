from __future__ import annotations

import base64
from enum import Enum
from typing import Dict, List, Optional
from typing_extensions import Self
import uuid
from ..attestation import enclave_specifications
from decentriq_dcr_compiler import compiler
from decentriq_dcr_compiler.schemas.data_science_data_room import DataScienceDataRoom
from ..session import (
    LATEST_WORKER_PROTOCOL_VERSION,
    Session,
)
from ..proto.length_delimited import serialize_length_delimited
from .version import DATA_SCIENCE_DCR_SUPPORTED_VERSION
from .node_definitions import NodeDefinition
from .analytics_dcr import AnalyticsDcrDefinition


__all__ = [
    "AnalyticsDcrBuilder",
]


class AnalyticsDcrType(str, Enum):
    STATIC = "STATIC"
    INTERACTIVE = "INTERACTIVE"


class ParticipantPermission(Enum):
    DATA_OWNER = 1
    ANALYST = 2


class AnalyticsDcrBuilder:
    """
    A builder for constructing Analytics Data Clean Rooms.
    """

    def __init__(
        self,
        *,
        client: Client,
        enclave_specs: Optional[Dict[str, EnclaveSpecification]] = None,
    ) -> None:
        """
        Initialise an Analytics DCR builder.

        **Parameters**:
        - `client`: A `Client` object that can be used to retrieve information about the platform.
        - `enclave_specs`: Determines the types of enclaves that will supported by this Data Clean Room.
            If not specified, the latest enclave specifications known to this
            SDK version will be used.
        """
        self.client = client
        self.enclave_specs = (
            enclave_specs if enclave_specs else enclave_specifications.latest()
        )
        self.name = None
        self.description = ""
        self.owner = None
        self.dcr_id = None
        self.enable_development = False
        self.enable_airlock = False
        self.enable_auto_merge_feature = False
        self.compile_context = None
        self.node_definitions = []
        """The current list of Node Definitions that will be added to the Data Clean Room."""
        self.permissions = []
        """The list of permissions that will be added to the Data Clean Room."""

    def with_name(self, name: str) -> Self:
        """
        Set the name of the Data Clean Room.

        **Parameters**:
        - `name`: Name to be used for the Data Clean Room.
        """
        self.name = name
        return self

    def with_description(self, description: str) -> Self:
        """
        Set the description of the Data Clean Room.

        **Parameters**:
        - `description`: Description of the Data Clean Room.
        """
        self.description = description
        return self

    def add_participant(
        self,
        email: str,
        *,
        analyst_of: List[str] = [],
        data_owner_of: List[str] = [],
    ) -> Self:
        """
        Add a participant to the DCR being built.

        If the participant isn't assigned a role, the user can still view the
        DCR but cannot interact with it.

        **Parameters**:
        - `email`: The email address of the participant.
        - `analyst_of`: The names of the Compute Nodes that the user can run.
        - `data_owner_of`: The names of the Data Nodes to which the user can
          connect a dataset.
        """
        anaylst_permissions = [{"analyst": {"nodeId": node}} for node in analyst_of]
        data_owner_permissions = [
            {"dataOwner": {"nodeId": node}} for node in data_owner_of
        ]
        self.permissions.append(
            {"user": email, "permissions": anaylst_permissions + data_owner_permissions}
        )
        return self

    def with_auto_merge(self) -> Self:
        """
        Allow auto-merging of commits.
        This allows non-conflicting changes to be merged without rebasing.
        """
        self.enable_auto_merge_feature = True
        return self

    def with_owner(self, email: str) -> Self:
        """
        Set the owner of the Data Clean Room.

        **Parameters**:
        - `email`: The email address of the owner of the Data Clean Room.
        """
        self.owner = email
        return self

    def with_development_mode(self) -> Self:
        """
        Enable Development Mode in the Data Clean Room.

        This allows Development Computations to be executed in the Data Clean Room.
        Development Computations are not yet part of the Data Clean Room, but allow users
        to run new computations on top of existing DCRs.
        The driver enclave makes sure that only data to which the user already has access
        can be read.
        """
        self.enable_development = True
        return self

    def with_airlock(self) -> Self:
        """
        Enable the Airlock feature in the Data Clean Room.

        This requires Development Mode to be enabled.
        The Airlock feature allows the addition of Preview Nodes that allow
        restricting the amount of data that can be read from specific Data Nodes.
        """
        self.enable_airlock = True
        return self

    def add_node_definition(self, definition: NodeDefinition) -> Self:
        """
        Add a single node definition to this builder.

        A node definition defines how a Compute or Data Node
        should be constructed.
        """
        self.add_node_definitions([definition])
        return self

    def add_node_definitions(self, definitions: List[NodeDefinition]) -> Self:
        """
        Add a list of node definitions to this builder.

        Each node definition defines how the respective Compute or Data Node
        should be constructed.
        """
        self.node_definitions.extend(definitions)
        return self

    def build(self) -> AnalyticsDcrDefinition:
        """
        Build the Data Clean Room.

        In order to use the DCR, the output of this method should be passed to
        `client.publish_analytics_dcr`.
        """
        if not self.owner:
            raise Exception("The Data Room owner must be specified")
        if not self.name:
            raise Exception("The Data Room name must be specified")

        nodes = [
            node._get_high_level_representation() for node in self.node_definitions
        ]
        permissions = self._add_owner_permissions()
        hl_dcr = {
            DATA_SCIENCE_DCR_SUPPORTED_VERSION: {
                # Only interactive DCRs are supported.
                "interactive": {
                    "commits": [],
                    "enableAutomergeFeature": self.enable_auto_merge_feature,
                    "initialConfiguration": {
                        "description": self.description,
                        "enableAirlock": self.enable_airlock,
                        "enableAllowEmptyFilesInValidation": False,
                        "enableDevelopment": self.enable_development,
                        "enablePostWorker": False,
                        "enableSafePythonWorkerStacktrace": True,
                        "enableServersideWasmValidation": True,
                        "enableSqliteWorker": False,
                        "enableTestDatasets": False,
                        "enclaveRootCertificatePem": self.client.decentriq_ca_root_certificate.decode(),
                        "enclaveSpecifications": self._get_hl_specs(),
                        "id": self._generate_id(),
                        "nodes": nodes,
                        "participants": permissions,
                        "title": self.name,
                    },
                }
            }
        }
        return AnalyticsDcrDefinition(name=self.name, high_level=hl_dcr)

    def _add_owner_permissions(self):
        for entry in self.permissions:
            if entry["user"] == self.owner:
                permissions = entry["permissions"]
                permissions.append({"manager": {}})
                entry["permissions"] = permissions
                return self.permissions

        # Entry wasn't found for existing user, so add a new one.
        self.permissions.append(
            {"user": self.owner, "permissions": [{"manager": {}}]}
        )
        return self.permissions

    def _get_hl_specs(self):
        specs = [
            {
                "attestationProtoBase64": base64.b64encode(
                    serialize_length_delimited(spec["proto"])
                ).decode(),
                "id": name,
                "workerProtocol": LATEST_WORKER_PROTOCOL_VERSION,
            }
            for name, spec in self.enclave_specs.items()
        ]
        return specs

    @staticmethod
    def _generate_id():
        return str(uuid.uuid4())
