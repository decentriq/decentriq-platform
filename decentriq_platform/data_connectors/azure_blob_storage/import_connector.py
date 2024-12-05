from __future__ import annotations

from typing import TYPE_CHECKING

from ...analytics.node_definitions import NodeDefinition
from ...analytics.high_level_node import ComputationNode
from ...session import Session
from typing_extensions import Self
from ..export_dependency_types import *


if TYPE_CHECKING:
    from ...client import Client


class AzureBlobStorageImportConnectorDefinition(NodeDefinition):
    def __init__(
        self,
        name: str,
        credentials_dependency: str,
    ) -> None:
        """
        Initialise an `AzureBlobStorageImportConnectorDefinition`.
        This class is used in order to construct AzureBlobStorageImportConnectors.

        **Parameters**:
        - `name`: Name of the `AzureBlobStorageImportConnectorDefinition`.
        - `credentials_dependency`: Name of the credentials node.
        """
        super().__init__(name, id=name)
        self.credentials_dependency = credentials_dependency
        self.specification_id = "decentriq.azure-blob-storage-worker"

    def _get_high_level_representation(self) -> dict[str, str]:
        """
        Retrieve the high level representation of the `AzureBlobStorageImportConnectorDefinition`.
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
                                "azure": (),
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
    ) -> AzureBlobStorageImportConnector:
        """
        Construct an AzureBlobStorageImportConnector from the Node Definition.

        **Parameters**:
        - `dcr_id`: ID of the DCR the node is a member of.
        - `node_definition`: Definition of the Import Connector Node.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        """
        return AzureBlobStorageImportConnector(
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
        credentials_dependency: str,
    ) -> Self:
        """
        Instantiate an `AzureBlobStorageImportConnectorDefinition` from its high level representation.

        **Parameters**:
        - `name`: Name of the connector node.
        - `credentials_dependency`: Name of the credentials dependency node.
        """
        return cls(
            name=name,
            credentials_dependency=credentials_dependency,
        )


class AzureBlobStorageImportConnector(ComputationNode):
    """
    An AzureBlobStorageImportConnector which can import data from Azure.
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
        Initialise an `AzureBlobStorageImportConnector`.

        **Parameters**:
        - `name`: Name of the import connector.
        - `dcr_id`: ID of the DCR the connector is a member of.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        - `connector_definition`: Definition of the Azure import connector.
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

