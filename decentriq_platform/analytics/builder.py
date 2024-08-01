from __future__ import annotations

import base64
import functools
import uuid
from enum import Enum
from typing import TYPE_CHECKING, Dict, List, Optional

from typing_extensions import Self

from ..attestation import enclave_specifications
from ..proto.length_delimited import serialize_length_delimited
from ..session import LATEST_WORKER_PROTOCOL_VERSION
from ..types import EnclaveSpecification
from .analytics_dcr import AnalyticsDcrDefinition
from .node_definitions import NodeDefinition
from .version import DATA_SCIENCE_DCR_SUPPORTED_VERSION

if TYPE_CHECKING:
    from ..client import Client


__all__ = [
    "AnalyticsDcrBuilder",
]


class AnalyticsDcrType(str, Enum):
    STATIC = "STATIC"
    INTERACTIVE = "INTERACTIVE"


class ParticipantPermission(Enum):
    DATA_OWNER = 1
    ANALYST = 2


def _get_hl_specs(enclave_specs: Dict[str, EnclaveSpecification]):
    specs = [
        {
            "attestationProtoBase64": base64.b64encode(
                serialize_length_delimited(spec["proto"])
            ).decode(),
            "id": name,
            "workerProtocol": spec.get(
                "workerProtocol", LATEST_WORKER_PROTOCOL_VERSION
            ),
        }
        for name, spec in enclave_specs.items()
    ]
    return specs


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
        self.compile_context = None
        self.node_definitions = []
        """The current list of Node Definitions that will be added to the Data Clean Room."""
        self.permissions = []
        """The list of permissions that will be added to the Data Clean Room."""
        self._force_spark_validation = False
        """Whether to force validation pipelines to use spark."""

    def _with_force_spark_validation(self, use_spark: bool) -> Self:
        """
        Whether to force the any validation pipeline part of this DCR
        to use spark. If this is false, the validation pipeline will decide
        based on the file size whether to use spark or not.

        **Parameters**:
        - `use_spark`: Force validation to use spark.
        """
        self._force_spark_validation = use_spark
        return self

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
        if any(permissions["user"] == email for permissions in self.permissions):
            raise Exception(f"Participant with email {email} has already been added.")

        anaylst_permissions = [{"analyst": {"nodeId": node}} for node in analyst_of]
        data_owner_permissions = [
            {"dataOwner": {"nodeId": node}} for node in data_owner_of
        ]
        self.permissions.append(
            {"user": email, "permissions": anaylst_permissions + data_owner_permissions}
        )
        return self

    def with_owner(self, email: str) -> Self:
        """
        Set the owner of the Data Clean Room.

        **Parameters**:
        - `email`: The email address of the owner of the Data Clean Room.
        """
        self.owner = email
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
        required_workers = functools.reduce(
            lambda a, b: a.union(b),
            [set(node.required_workers) for node in self.node_definitions],
            {"decentriq.driver"},
        )
        used_enclave_specs = {}
        for worker in required_workers:
            if worker in self.enclave_specs:
                used_enclave_specs[worker] = self.enclave_specs[worker]
            else:
                raise Exception(
                    f"One of the nodes you added requires a worker of type '{worker}',"
                    " but no enclave specification matching this worker is known to this builder."
                )
        used_hl_enclave_specs = _get_hl_specs(used_enclave_specs)
        permissions = self._add_owner_permissions()
        hl_dcr = {
            DATA_SCIENCE_DCR_SUPPORTED_VERSION: {
                # Only interactive DCRs are supported.
                "interactive": {
                    "commits": [],
                    "enableAutomergeFeature": True,
                    "initialConfiguration": {
                        "description": self.description,
                        "enableAirlock": True,
                        "enableAllowEmptyFilesInValidation": True,
                        "enableDevelopment": True,
                        "enablePostWorker": True,
                        "enableSafePythonWorkerStacktrace": True,
                        "enableServersideWasmValidation": True,
                        "enableSqliteWorker": True,
                        "enableTestDatasets": True,
                        "enclaveRootCertificatePem": self.client.decentriq_ca_root_certificate.decode(),
                        "enclaveSpecifications": used_hl_enclave_specs,
                        "enableForceSparkValidation": self._force_spark_validation,
                        "id": self._generate_id(),
                        "nodes": nodes,
                        "participants": permissions,
                        "title": self.name,
                    },
                }
            }
        }
        return AnalyticsDcrDefinition(
            name=self.name, high_level=hl_dcr, enclave_specs=self.enclave_specs
        )

    def _add_owner_permissions(self):
        for entry in self.permissions:
            if entry["user"] == self.owner:
                permissions = entry["permissions"]
                permissions.append({"manager": {}})
                entry["permissions"] = permissions
                return self.permissions

        # Entry wasn't found for existing user, so add a new one.
        self.permissions.append({"user": self.owner, "permissions": [{"manager": {}}]})
        return self.permissions

    @staticmethod
    def _generate_id():
        return str(uuid.uuid4())
