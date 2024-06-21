from __future__ import annotations

from ...analytics.node_definitions import NodeDefinition
from ...analytics.high_level_node import ComputationNode
from ...session import Session
from typing import Dict
from dataclasses import dataclass
from decentriq_dcr_compiler._schemas.data_science_data_room import (
    AwsConfig,
    ExportNodeDependency as ExportNodeDependencySchema,
)
from typing import TypeAlias
from typing_extensions import Self

from ..export_dependency_types import *
from ..export_dependency_types import _get_export_node_dependency_from_high_level

ImportConnectorDefinition: TypeAlias = NodeDefinition


class AwsImportConnectorDefinition(ImportConnectorDefinition):
    def __init__(
        self,
        name: str,
        object_key: str,
        bucket: str,
        region: str,
        credentials_dependency: str,
    ) -> None:
        """
        Initialise an `AwsImportConnectorDefinition`.
        This class is used in order to construct AwsImportConnectors.

        **Parameters**:
        - `name`: Name of the `AwsImportConnectorDefinition`.
        - `object_key`: Name of the object to be imported.
        - `bucket`: The name of the bucket where the object will be imported from.
        - `region`: The geographic region of the bucket.
        - `credentials_dependency`: Name of the credentials node.
        """
        super().__init__(name, id=name)
        self.bucket = bucket
        self.region = region
        self.object_key = object_key
        self.credentials_dependency = credentials_dependency
        self.specification_id = "decentriq.data-source-s3-worker"

    def _get_high_level_representation(self) -> Dict[str, str]:
        """
        Retrieve the high level representation of the `AwsImportConnectorDefinition`.
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
                                "aws": {
                                    "bucket": self.bucket,
                                    "objectKey": self.object_key,
                                    "region": self.region,
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
        node_definition: ImportConnectorDefinition,
        client: Client,
        session: Session,
    ) -> AwsImportConnector:
        """
        Construct an AwsImportConnector from the Node Definition.

        **Parameters**:
        - `dcr_id`: ID of the DCR the node is a member of.
        - `node_definition`: Definition of the Import Connector Node.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        """
        return AwsImportConnector(
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
        config: AwsConfig,
        credentials_dependency: str,
    ) -> Self:
        """
        Instantiate an `AwsImportConnectorDefinition` from its high level representation.

        **Parameters**:
        - `name`: Name of the `AwsImportConnectorDefinition`.
        - `config`: Pydantic model of the `AwsConfig`.
        - `credentials_dependency`: Name of the credentials dependency node.
        """
        return cls(
            name=name,
            object_key=config.objectKey,
            bucket=config.bucket,
            region=config.region,
            credentials_dependency=credentials_dependency,
        )


class AwsImportConnector(ComputationNode):
    """
    An AwsImportConnector which can import data from AWS.
    """

    def __init__(
        self,
        name: str,
        dcr_id: str,
        client: Client,
        session: Session,
        connector_definition: AwsImportConnectorDefinition,
    ) -> None:
        """
        Initialise an `AwsImportConnector`.

        **Parameters**:
        - `name`: Name of the `AwsImportConnector`.
        - `dcr_id`: ID of the DCR the connector is a member of.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        - `connector_definition`: Definition of the AWS import connector.
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


ExportConnectorDefinition: TypeAlias = NodeDefinition


class AwsExportConnectorDefinition(ExportConnectorDefinition):
    def __init__(
        self,
        name: str,
        bucket: str,
        region: str,
        credentials_dependency: str,
        node_dependency: ExportNodeDependency,
    ) -> None:
        """
        Initialise an `AwsExportConnectorDefinition`.
        This class is used in order to construct an `AwsExportConnector`.

        **Parameters**:
        - `name`: Name of the `AwsExportConnectorDefinition`.
        - `bucket`: The name of the bucket that will store the object.
        - `region`: The geographic region of the bucket.
        - `credentials_dependency`: Name of the credentials node.
        - `node_dependency`: The name of the node who's data will be exported to AWS. 
                This also defines the type of upload (raw, single file in a zip, entire zip contents).
        """
        super().__init__(name, id=name)
        self.bucket = bucket
        self.region = region
        self.credentials_dependency = credentials_dependency
        self.node_dependency = node_dependency
        self.specification_id = "decentriq.s3-sink-worker"

    def _get_high_level_representation(self) -> Dict[str, str]:
        """
        Retrieve the high level representation of the `AwsExportConnectorDefinition`.
        """
        return {
            "id": self.id,
            "name": self.name,
            "kind": {
                "computation": {
                    "kind": {
                        "exportConnector": {
                            "credentialsDependency": self.credentials_dependency,
                            "kind": {
                                "aws": {
                                    "bucket": self.bucket,
                                    "objectKey": self.node_dependency.object_key,
                                    "region": self.region,
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
        node_definition: ExportConnectorDefinition,
        client: Client,
        session: Session,
    ) -> AwsExportConnector:
        """
        Construct an AwsExportConnector from the definition.

        **Parameters**:
        - `dcr_id`: ID of the DCR the connector is a member of.
        - `node_definition`: Definition of the Aws export connector.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        """
        return AwsExportConnector(
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
        config: AwsConfig,
        credentials_dependency: str,
        node_dependency: ExportNodeDependencySchema,
    ) -> Self:
        """
        Instantiate an `AwsExportConnectorDefinition` from its high level representation.

        **Parameters**:
        - `name`: Name of the `AwsExportConnectorDefinition`.
        - `config`: Pydantic model of the `AwsConfig`.
        - `credentials_dependency`: Name of the node storing the AWS credentials.
        - `node_dependency`: Name of the node whose data should be exported.
        """
        node_dep = _get_export_node_dependency_from_high_level(
            node_dependency, config.objectKey
        )
        return cls(
            name=name,
            bucket=config.bucket,
            region=config.region,
            credentials_dependency=credentials_dependency,
            node_dependency=node_dep,
        )


class AwsExportConnector(ComputationNode):
    """
    An AwsExportConnector which can export data to AWS.
    """

    def __init__(
        self,
        name: str,
        dcr_id: str,
        client: Client,
        session: Session,
        connector_definition: ExportConnectorDefinition,
    ) -> None:
        """
        Initialise an `AwsExportConnector`.

        **Parameters**:
        - `name`: Name of the `AwsExportConnector`.
        - `dcr_id`: ID of the DCR the connector is a member of.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        - `connector_definition`: Definition of the AWS export connector.
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
