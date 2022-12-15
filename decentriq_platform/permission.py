from .proto import (
    Permission,
    LeafCrudPermission,
    RetrieveAuditLogPermission,
    ExecuteComputePermission,
    RetrieveComputeResultPermission,
    RetrieveDataRoomPermission,
    RetrieveDataRoomStatusPermission,
    UpdateDataRoomStatusPermission,
    RetrievePublishedDatasetsPermission,
    DryRunPermission,
    GenerateMergeSignaturePermission,
    ExecuteDevelopmentComputePermission,
    MergeConfigurationCommitPermission,
)

class Permissions:
    """Helper class for creating data room permissions."""

    def __init__(self):
        """This class is not meant to be instantiated."""

    @staticmethod
    def leaf_crud(leaf_node_id: str) -> Permission:
        """Permission required for publishing a dataset to a data room."""
        return Permission(
            leafCrudPermission=LeafCrudPermission(leafNodeId=leaf_node_id)
        )

    @staticmethod
    def retrieve_data_room() -> Permission:
        """Permission required for retrieving a data room's definition after it has
        been published."""
        return Permission(retrieveDataRoomPermission=RetrieveDataRoomPermission())

    @staticmethod
    def retrieve_audit_log() -> Permission:
        """Permission for retrieving the audit log, a log detailing all past interactions
        with the data room."""
        return Permission(retrieveAuditLogPermission=RetrieveAuditLogPermission())

    @staticmethod
    def execute_compute(compute_node_id: str) -> Permission:
        """Permission for executing the computation with the given id."""
        return Permission(
            executeComputePermission=ExecuteComputePermission(
                computeNodeId=compute_node_id
            )
        )

    @staticmethod
    def retrieve_compute_result(compute_node_id: str) -> Permission:
        """Permission for executing the computation with the given id."""
        return Permission(
            retrieveComputeResultPermission=RetrieveComputeResultPermission(
                computeNodeId=compute_node_id
            )
        )

    @staticmethod
    def retrieve_data_room_status() -> Permission:
        """Permission for retrieving the status of a data room."""
        return Permission(
            retrieveDataRoomStatusPermission=RetrieveDataRoomStatusPermission()
        )

    @staticmethod
    def update_data_room_status() -> Permission:
        """Permission for updating the status of a data room (e.g. irreversibly stopping it)."""
        return Permission(
            updateDataRoomStatusPermission=UpdateDataRoomStatusPermission()
        )

    @staticmethod
    def retrieve_published_datasets() -> Permission:
        """Permission for retrieving the list of datasets that has been published to the data room."""
        return Permission(
            retrievePublishedDatasetsPermission=RetrievePublishedDatasetsPermission()
        )

    @staticmethod
    def dry_run() -> Permission:
        """Permission for triggering a dry run on the data room."""
        return Permission(dryRunPermission=DryRunPermission())

    @staticmethod
    def generate_merge_signature() -> Permission:
        """Permission for generating signatures required for merge approvals."""
        return Permission(
            generateMergeSignaturePermission=GenerateMergeSignaturePermission()
        )

    @staticmethod
    def execute_development_compute() -> Permission:
        """Permission for executing computations in development mode."""
        return Permission(
            executeDevelopmentComputePermission=ExecuteDevelopmentComputePermission()
        )

    @staticmethod
    def merge_configuration_commit() -> Permission:
        """
        Permission for merging configuration commits into the current data
        room configuration.
        """
        return Permission(
            mergeConfigurationCommitPermission=MergeConfigurationCommitPermission()
        )
