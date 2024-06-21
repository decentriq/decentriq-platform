from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple, Union

from decentriq_dcr_compiler import (
    upgrade_data_science_data_room_to_latest,
    verify_data_room,
)
from decentriq_dcr_compiler.schemas.data_science_commit import DataScienceCommitV6
from decentriq_dcr_compiler.schemas.data_science_data_room import (
    ComputationNodeV6,
    DataScienceDataRoom,
    DataScienceDataRoomConfigurationV6,
    LeafNodeV2,
    Participant,
    ScriptingLanguage,
)

from ..proto import serialize_length_delimited
from ..session import Session
from .matching_compute_nodes import MatchingComputeNodeDefinition
from .node_definitions import NodeDefinition
from .preview_compute_nodes import PreviewComputeNodeDefinition
from .python_compute_nodes import PythonComputeNodeDefinition
from .r_compute_nodes import RComputeNodeDefinition
from .raw_data_nodes import RawDataNodeDefinition
from .s3_sink_compute_nodes import S3SinkComputeNodeDefinition
from .sql_compute_nodes import SqlComputeNodeDefinition
from .sqlite_compute_nodes import SqliteComputeNodeDefinition
from .synthetic_compute_nodes import SyntheticDataComputeNodeDefinition
from .table_data_nodes import TableDataNodeDefinition
from ..data_connectors import AwsImportConnectorDefinition, AwsExportConnectorDefinition
from .dataset_sink_compute_nodes import DatasetSinkComputeNodeDefinition
from .version import DATA_SCIENCE_DCR_SUPPORTED_VERSION

if TYPE_CHECKING:
    from ..client import Client


@dataclass
class ExistingConfiguration:
    name: str
    description: str
    owner: Optional[str]
    node_definitions: List
    dcr_id: str
    enable_development: bool
    enable_airlock: bool
    participants: List
    enable_auto_merge_feature: bool


class ExistingAnalyticsDcrBuilder:
    """
    Builder for retrieving configuration information from an existing Analytics Data Clean Room.
    """

    def __init__(self, dcr_id: str, client: Client, session: Session) -> None:
        self.dcr_id = dcr_id
        self.client = client
        self.session = session
        existing_dcr = self.session.retrieve_data_room(self.dcr_id)
        self.high_level = json.loads(existing_dcr.highLevelRepresentation.decode())

    def get_configuration(self) -> ExistingConfiguration:
        """
        Retrieve the configuration information for the existing Analytics Data Clean Room.
        """
        dcr_config, commits, enable_auto_merge_feature = self._get_data_room()
        model_participants = self._get_participants(dcr_config)
        participants = [participant.user for participant in model_participants]
        owner = self._get_owner(model_participants)
        node_definitions = self._get_nodes(dcr_config, commits)

        enable_development = dcr_config.enableDevelopment
        enable_airlock = dcr_config.enableAirlock
        name = dcr_config.title
        description = dcr_config.description

        return ExistingConfiguration(
            name,
            description,
            owner,
            node_definitions,
            self.dcr_id,
            enable_development,
            enable_airlock,
            participants,
            enable_auto_merge_feature,
        )

    def _get_data_room(
        self,
    ) -> Tuple[(DataScienceDataRoomConfigurationV6, List[DataScienceCommitV6], bool)]:
        # Verify that the LL and HL match
        existing_dcr = self.session.retrieve_data_room(self.dcr_id)
        existing_dcr.highLevelRepresentation.decode()
        verify_data_room(
            serialize_length_delimited(existing_dcr.dataRoom),
            [serialize_length_delimited(c) for c in existing_dcr.commits],
            existing_dcr.highLevelRepresentation,
        )
        # HL was verified, continue parsing the HL
        high_level = DataScienceDataRoom.model_validate(self.high_level)
        latest_high_level = upgrade_data_science_data_room_to_latest(high_level)
        if not hasattr(latest_high_level.root, DATA_SCIENCE_DCR_SUPPORTED_VERSION):
            raise Exception(
                "The retrieved DCR was upgraded to the latest known version,"
                " but it differs from the latest supported version in this SDK"
                f" ({DATA_SCIENCE_DCR_SUPPORTED_VERSION})."
                " This very likely means that your SDK version is out of date and needs to be"
                " upgraded to the latest version."
            )
        else:
            dcr = getattr(
                latest_high_level.root, DATA_SCIENCE_DCR_SUPPORTED_VERSION
            ).root
            if hasattr(dcr, "interactive"):
                return (
                    dcr.interactive.initialConfiguration,
                    dcr.interactive.commits,
                    dcr.interactive.enableAutomergeFeature,
                )
            elif hasattr(dcr, "static"):
                return (dcr.static, [], False)
            else:
                raise Exception("Expected DCR to be either static or interactive")

    def _get_participants(
        self, config: DataScienceDataRoomConfigurationV6
    ) -> List[Participant]:
        participants = [participant for participant in config.participants]
        return participants

    def _get_nodes(
        self,
        config: DataScienceDataRoomConfigurationV6,
        commits: List[DataScienceCommitV6],
    ) -> List[NodeDefinition]:
        nodes = []
        hl_nodes = config.nodes
        # Add any node that might have been added via a commit in the UI
        for commit in commits:
            if hasattr(commit.kind, "addComputation"):
                hl_nodes.append(commit.kind.addComputation.node)

        for node in hl_nodes:
            name = node.name
            root_node = node.kind.root
            node_fields = root_node.model_fields

            if "computation" in node_fields:
                computation_node = (
                    self._construct_computation_node_from_hl_representation(
                        node.id, name, node.kind.root.computation
                    )
                )
                nodes.append(computation_node)
            elif "leaf" in node_fields:
                data_node = self._construct_data_node_from_hl_representation(
                    node.id,
                    name,
                    node.kind.root.leaf,
                )
                nodes.append(data_node)
            else:
                raise Exception("Unknown node type")
        return nodes

    def _construct_computation_node_from_hl_representation(
        self,
        id: str,
        name: str,
        node: ComputationNodeV6,
    ) -> Union[
        PythonComputeNodeDefinition,
        RComputeNodeDefinition,
        SqlComputeNodeDefinition,
        SqliteComputeNodeDefinition,
        S3SinkComputeNodeDefinition,
        MatchingComputeNodeDefinition,
        SyntheticDataComputeNodeDefinition,
        PreviewComputeNodeDefinition,
        AwsImportConnectorDefinition,
    ]:

        root_node = node.kind.root
        node_fields = root_node.model_fields
        compute_node_definition = None
        if "scripting" in node_fields:
            parsed_node = root_node.scripting
            if parsed_node.scriptingLanguage.value == ScriptingLanguage.python.value:
                compute_node_definition = PythonComputeNodeDefinition._from_high_level(
                    id, name, parsed_node
                )
            elif parsed_node.scriptingLanguage.value == ScriptingLanguage.r.value:
                compute_node_definition = RComputeNodeDefinition._from_high_level(
                    id, name, parsed_node
                )
            else:
                raise Exception(
                    f"Unknown scripting language {parsed_node.scriptingLanguage}"
                )
        elif "sql" in node_fields:
            compute_node_definition = SqlComputeNodeDefinition._from_high_level(
                id, name, root_node.sql
            )
        elif "sqlite" in node_fields:
            compute_node_definition = SqliteComputeNodeDefinition._from_high_level(
                id, name, root_node.sqlite
            )
        elif "s3Sink" in node_fields:
            compute_node_definition = S3SinkComputeNodeDefinition._from_high_level(
                id, name, root_node.s3Sink
            )
        elif "match" in node_fields:
            compute_node_definition = MatchingComputeNodeDefinition._from_high_level(
                id, name, root_node.match
            )
        elif "syntheticData" in node_fields:
            compute_node_definition = (
                SyntheticDataComputeNodeDefinition._from_high_level(
                    id, name, root_node.syntheticData
                )
            )
        elif "preview" in node_fields:
            compute_node_definition = PreviewComputeNodeDefinition._from_high_level(
                id, name, root_node.preview
            )
        elif "importConnector" in node_fields:
            import_connector = root_node.importConnector
            credentials_dependency = import_connector.credentialsDependency
            import_connector_kind = import_connector.kind.root.model_fields
            if "aws" in import_connector_kind:
                aws_config = import_connector.kind.root.aws
                compute_node_definition = AwsImportConnectorDefinition._from_high_level(
                    name,
                    aws_config,
                    credentials_dependency,
                )
            else:
                raise Exception(
                    f"Unknown import connector kind {import_connector_kind}"
                )
        elif "exportConnector" in node_fields:
            export_connector = root_node.exportConnector
            credentials_dependency = export_connector.credentialsDependency
            export_connector_kind = export_connector.kind.root.model_fields
            export_connector_node_dependency = export_connector.dependency
            if "aws" in export_connector_kind:
                aws_config = export_connector.kind.root.aws
                compute_node_definition = AwsExportConnectorDefinition._from_high_level(
                    name,
                    aws_config,
                    credentials_dependency,
                    export_connector_node_dependency,
                )
            else:
                raise Exception(
                    f"Unknown export connector kind {export_connector_kind}"
                )
        elif "datasetSink" in node_fields:
            compute_node_definition = DatasetSinkComputeNodeDefinition._from_high_level(
                id=id, name=name, node=root_node.datasetSink
            )

        else:
            raise Exception("Unknown computation node type")
        return compute_node_definition

    def _construct_data_node_from_hl_representation(
        self,
        id: str,
        name: str,
        node: LeafNodeV2,
    ) -> Union[RawDataNodeDefinition, TableDataNodeDefinition]:
        is_required = node.isRequired
        root_node = node.kind.root
        node_fields = root_node.model_fields
        data_node = None
        if "raw" in node_fields:
            data_node = RawDataNodeDefinition._from_high_level(
                id, name, root_node.raw, is_required
            )
        elif "table" in node_fields:
            data_node = TableDataNodeDefinition._from_high_level(
                id,
                name,
                root_node.table,
                is_required,
            )
        else:
            raise Exception("Unknown data node type")
        data_node.dcr_id = self.dcr_id
        data_node.session = self.session
        data_node.client = self.client
        return data_node

    @staticmethod
    def _get_node_permissions_dict(
        participants: List[Participant],
    ) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
        node_data_permissions = {}
        node_compute_permissions = {}
        for participant in participants:
            user = participant.user
            for permission in participant.permissions:
                root_permission = permission.root
                permission_fields = root_permission.model_fields
                if "dataOwner" in permission_fields:
                    data_owner = root_permission.dataOwner
                    node_id = data_owner.nodeId
                    users = node_data_permissions.setdefault(data_owner.nodeId, [])
                    users.append(user)
                    node_data_permissions[node_id] = users
                elif "analyst" in permission_fields:
                    analyst = root_permission.analyst
                    node_id = analyst.nodeId
                    users = node_data_permissions.setdefault(node_id, [])
                    users.append(user)
                    node_compute_permissions[node_id] = users
        return (node_compute_permissions, node_data_permissions)

    @staticmethod
    def _get_owner(
        participants: List[Participant],
    ) -> Optional[str]:
        for participant in participants:
            user = participant.user
            for permission in participant.permissions:
                root_permission = permission.root
                permission_fields = root_permission.model_fields
                if "manager" in permission_fields:
                    return user
