from __future__ import annotations

from typing import TYPE_CHECKING
from typing_extensions import Self

from ...analytics.node_definitions import NodeDefinition
from ...analytics.high_level_node import ComputationNode
from ...session import Session
from decentriq_dcr_compiler._schemas.data_science_data_room import (
    GcsConfig,
)
from ..export_dependency_types import *
from ..export_dependency_types import _get_export_node_dependency_from_high_level

if TYPE_CHECKING:
    from ...client import Client


class GcsImportConnectorDefinition(NodeDefinition):
    def __init__(
        self,
        name: str,
        object_key: str,
        bucket: str,
        credentials_dependency: str,
    ) -> None:
        """
        Initialise a `GcsImportConnectorDefinition`.
        This class is used in order to construct GcsImportConnectors.

        **Parameters**:
        - `name`: Name of the `GcsImportConnectorDefinition`.
        - `object_key`: Name of the object to be imported.
        - `bucket`: The name of the bucket where the object will be imported from.
        - `credentials_dependency`: Name of the credentials node.
        """
        super().__init__(name, id=name)
        self.bucket = bucket
        self.object_key = object_key
        self.credentials_dependency = credentials_dependency
        self.specification_id = "decentriq.data-source-s3-worker"

    def _get_high_level_representation(self) -> dict[str, str]:
        """
        Retrieve the high level representation of the `GcsImportConnectorDefinition`.
        """
        return {
            "id": self.id,
            "name": self.name,
            "kind": {
                "computation": {
                    "kind": {
                        "importConnector": {
                            "credentialsDependency": self.credentials_dependency,
                            "kind": {
                                "gcs": {
                                    "bucket": self.bucket,
                                    "objectKey": self.object_key,
                                }
                            },
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
    ) -> GcsImportConnector:
        """
        Construct a GcsImportConnector from the Node Definition.

        **Parameters**:
        - `dcr_id`: ID of the DCR the node is a member of.
        - `node_definition`: Definition of the Import Connector Node.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        """
        return GcsImportConnector(
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
    ) -> Self:
        """
        Instantiate a `GcsImportConnectorDefinition` from its high level representation.

        **Parameters**:
        - `name`: Name of the `GcsImportConnectorDefinition`.
        - `config`: Pydantic model of the `GcsConfig`.
        - `credentials_dependency`: Name of the credentials dependency node.
        """
        return cls(
            name=name,
            object_key=config.objectKey,
            bucket=config.bucket,
            credentials_dependency=credentials_dependency,
        )


class GcsImportConnector(ComputationNode):
    """
    A GcsImportConnector which can import data from GCS.
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
        Initialise a `GcsImportConnector`.

        **Parameters**:
        - `name`: Name of the `GcsImportConnector`.
        - `dcr_id`: ID of the DCR the connector is a member of.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        - `connector_definition`: Definition of the GCS import connector.
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
        Retrieve the ID of the node corresponding to the connector.
        """
        return self.id
