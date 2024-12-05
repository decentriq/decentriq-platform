from __future__ import annotations

from typing import TYPE_CHECKING
from typing_extensions import Self

from ...analytics.node_definitions import NodeDefinition
from ...analytics.high_level_node import ComputationNode
from ...session import Session
from decentriq_dcr_compiler._schemas.data_science_data_room import (
    GcsConfig,
    ExportNodeDependency as ExportNodeDependencySchema,
)
from ..export_dependency_types import *
from ..export_dependency_types import _get_export_node_dependency_from_high_level

if TYPE_CHECKING:
    from ...client import Client


class GcsExportConnectorDefinition(NodeDefinition):
    def __init__(
        self,
        name: str,
        bucket: str,
        credentials_dependency: str,
        node_dependency: ExportNodeDependency,
    ) -> None:
        """
        Initialise a `GcsExportConnectorDefinition`.
        This class is used in order to construct a `GcsExportConnector`.

        **Parameters**:
        - `name`: Name of the `GcsExportConnectorDefinition`.
        - `bucket`: The name of the bucket that will store the object.
        - `credentials_dependency`: Name of the credentials node.
        - `node_dependency`: The name of the node who's data will be exported to GCS.
                This also defines the type of upload (raw, single file in a zip, entire zip contents).
        """
        super().__init__(name, id=name)
        self.bucket = bucket
        self.credentials_dependency = credentials_dependency
        self.node_dependency = node_dependency
        self.specification_id = "decentriq.s3-sink-worker"

    def _get_high_level_representation(self) -> dict[str, str]:
        """
        Retrieve the high level representation of the `GcsExportConnectorDefinition`.
        """
        return {
            "id": self.id,
            "name": self.name,
            "kind": {
                "computation": {
                    "kind": {
                        "exportConnector": {
                            "credentialsDependency": {
                                "user": self.credentials_dependency,
                            },
                            "kind": {
                                "gcs": {
                                    "bucket": self.bucket,
                                    "objectKey": self.node_dependency.object_key,
                                }
                            },
                            "dependency": self.node_dependency.high_level,
                            "specificationId": self.specification_id,
                        },
                    },
                }
            },
        }

    def build(
        self,
        dcr_id: str,
        node_definition: NodeDefinition,
        client: Client,
        session: Session,
    ) -> GcsExportConnector:
        """
        Construct a GcsExportConnector from the definition.

        **Parameters**:
        - `dcr_id`: ID of the DCR the connector is a member of.
        - `node_definition`: Definition of the GCS export connector.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        """
        return GcsExportConnector(
            name=self.name,
            dcr_id=dcr_id,
            client=client,
            session=session,
            connector_definition=node_definition,
        )

    @property
    def required_workers(self):
        return [self.specification_id]

    @classmethod
    def _from_high_level(
        cls,
        name: str,
        config: GcsConfig,
        credentials_dependency: str,
        node_dependency: ExportNodeDependencySchema,
    ) -> Self:
        """
        Instantiate a `GcsExportConnectorDefinition` from its high level representation.

        **Parameters**:
        - `name`: Name of the `GcsExportConnectorDefinition`.
        - `config`: Pydantic model of the `GcsConfig`.
        - `credentials_dependency`: Name of the node storing the GCS credentials.
        - `node_dependency`: Name of the node whose data should be exported.
        """
        node_dep = _get_export_node_dependency_from_high_level(
            node_dependency, config.objectKey
        )
        return cls(
            name=name,
            bucket=config.bucket,
            credentials_dependency=credentials_dependency,
            node_dependency=node_dep,
        )


class GcsExportConnector(ComputationNode):
    """
    A GcsExportConnector which can export data to GCS.
    """

    def __init__(
        self,
        name: str,
        dcr_id: str,
        client: Client,
        session: Session,
        connector_definition: NodeDefinition,
    ) -> None:
        """
        Initialise a `GcsExportConnector`.

        **Parameters**:
        - `name`: Name of the `GcsExportConnector`.
        - `dcr_id`: ID of the DCR the connector is a member of.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        - `connector_definition`: Definition of the GCS export connector.
        """
        super().__init__(
            name=name,
            client=client,
            session=session,
            dcr_id=dcr_id,
            id=name,
            definition=connector_definition,
        )
        self.definition = connector_definition

    def _get_computation_id(self) -> str:
        """
        Retrieve the ID of the node corresponding to the computation.
        """
        return self.id
