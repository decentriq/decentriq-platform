from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Dict, List, Optional

from decentriq_dcr_compiler.schemas import (
    SyntheticDataComputationNode,
)
from typing_extensions import Self

from ..session import Session
from .high_level_node import ContainerComputationNode
from .node_definitions import NodeDefinition
from .sql_helper import read_sql_query_result_as_string
from .table_data_nodes import PrimitiveType

if TYPE_CHECKING:
    from ..client import Client


class MaskType(str, Enum):
    GENERIC_STRING = "genericString"
    GENERIC_NUMBER = "genericNumber"
    NAME = "name"
    ADDRESS = "address"
    POSTCODE = "postcode"
    PHONE_NUMBER = "phoneNumber"
    SOCIAL_SECURITY_NUMBER = "socialSecurityNumber"
    EMAIL = "email"
    DATE = "date"
    TIMESTAMP = "timestamp"
    IBAN = "iban"


@dataclass
class SyntheticNodeColumn:
    data_type: PrimitiveType
    index: int
    mask_type: MaskType
    should_mask_column: bool
    is_nullable: bool = True
    name: Optional[Optional[str]] = None


class SyntheticDataComputeNodeDefinition(NodeDefinition):
    """
    Class representing a Synthetic Data Computation node.
    """

    def __init__(
        self,
        name: str,
        columns: List[SyntheticNodeColumn],
        dependency: str,
        epsilon: float,
        output_original_data_statistics: bool = False,
        enable_logs_on_error: bool = False,
        enable_logs_on_success: bool = False,
        id: Optional[str] = None,
    ) -> None:
        """
        Initialise a `SyntheticDataComputeNodeDefinition`:

        **Parameters**:
        - `name`: Name of the `SyntheticDataComputeNodeDefinition`.
        - `columns`: Columns defined for the `SyntheticDataComputeNodeDefinition`
        - `dependency`: Node that the `SyntheticDataComputeNodeDefinition` depends on.
        - `epsilon`: Amount of noise to add to the data.
        - `output_original_data_statistics`: Include the original statistics in the output.
        - `enable_logs_on_error`: Enable logs in the event of an error.
        - `enable_logs_on_success`: Enable logs when the computation is successful.
        - `id`: Optional ID  of the `SyntheticDataComputeNodeDefinition`.
        """
        super().__init__(name=name, id=id or name)
        self.columns = columns
        self.dependency = dependency
        self.epsilon = epsilon
        self.output_original_data_statistics = output_original_data_statistics
        self.enable_logs_on_error = enable_logs_on_error
        self.enable_logs_on_success = enable_logs_on_success
        self.specification_id = "decentriq.python-synth-data-worker-32-64"
        self.static_content_specification_id = "decentriq.driver"

    @property
    def required_workers(self):
        return [self.static_content_specification_id, self.specification_id]

    def _get_high_level_representation(self) -> Dict[str, str]:
        """
        Retrieve the high level representation of the `SyntheticDataComputeNodeDefinition`.
        """
        columns = []
        for column in self.columns:
            columns.append(
                {
                    "dataFormat": {
                        "dataType": column.data_type.value,
                        "isNullable": column.is_nullable,
                    },
                    "index": column.index,
                    "maskType": column.mask_type.value,
                    "shouldMaskColumn": column.should_mask_column,
                    "name": "" if not column.name else column.name,
                }
            )

        computation_node = {
            "id": self.id,
            "name": self.name,
            "kind": {
                "computation": {
                    "kind": {
                        "syntheticData": {
                            "columns": columns,
                            "dependency": self.dependency,
                            "enableLogsOnError": self.enable_logs_on_error,
                            "enableLogsOnSuccess": self.enable_logs_on_success,
                            "epsilon": self.epsilon,
                            "outputOriginalDataStatistics": self.output_original_data_statistics,
                            "staticContentSpecificationId": self.static_content_specification_id,
                            "synthSpecificationId": self.specification_id,
                        }
                    }
                },
            },
        }
        return computation_node

    @classmethod
    def _from_high_level(
        cls, id: str, name: str, node: SyntheticDataComputationNode
    ) -> Self:
        """
        Instantiate a `SyntheticDataComputeNodeDefinition` from its high level representation.

        **Parameters**:
        - `name`: Name of the `SyntheticDataComputeNodeDefinition`.
        - `node`: Pydantic model of the `SyntheticDataComputeNode`.
        """
        synthetic_data_node = json.loads(node.model_dump_json())
        return cls(
            id=id,
            name=name,
            columns=synthetic_data_node["columns"],
            dependency=synthetic_data_node["dependency"],
            epsilon=synthetic_data_node["epsilon"],
            output_original_data_statistics=synthetic_data_node[
                "outputOriginalDataStatistics"
            ],
            enable_logs_on_error=synthetic_data_node["enableLogsOnError"],
            enable_logs_on_success=synthetic_data_node["enableLogsOnSuccess"],
        )

    def build(
        self,
        dcr_id: str,
        node_definition: NodeDefinition,
        client: Client,
        session: Session,
    ) -> SyntheticDataComputeNode:
        """
        Construct a SyntheticDataComputeNode from the Node Definition.

        **Parameters**:
        - `dcr_id`: ID of the DCR the node is a member of.
        - `node_definition`: Definition of the Synthetic Data Compute Node.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        """
        return SyntheticDataComputeNode(
            name=self.name,
            dcr_id=dcr_id,
            columns=self.columns,
            dependency=self.dependency,
            epsilon=self.epsilon,
            client=client,
            session=session,
            node_definition=node_definition,
            output_original_data_statistics=self.output_original_data_statistics,
            enable_logs_on_error=self.enable_logs_on_error,
            enable_logs_on_success=self.enable_logs_on_success,
            id=self.id,
        )


class SyntheticDataComputeNode(ContainerComputationNode):
    """
    Class representing a Synthetic Data Computation Node.
    """

    def __init__(
        self,
        id: str,
        name: str,
        dcr_id: str,
        columns: List[SyntheticNodeColumn],
        dependency: str,
        epsilon: float,
        client: Client,
        session: Session,
        node_definition: NodeDefinition,
        output_original_data_statistics: bool = False,
        enable_logs_on_error: bool = False,
        enable_logs_on_success: bool = False,
    ) -> None:
        """
        Initialise a `SyntheticDataComputeNode`:

        **Parameters**:
        - `id`: ID of the `SyntheticDataComputeNode`.
        - `name`: Name of the `SyntheticDataComputeNode`.
        - `dcr_id`: ID of the DCR the node is a member of.
        - `columns`: Columns defined for the `SyntheticDataComputeNode`
        - `dependency`: Node that the `SyntheticDataComputeNode` depends on.
        - `epsilon`: Amount of noise to add to the data.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        - `output_original_data_statistics`: Include the original statistics in the output.
        - `enable_logs_on_error`: Enable logs in the event of an error.
        - `enable_logs_on_success`: Enable logs when the computation is successful.
        """
        super().__init__(
            name=name,
            client=client,
            session=session,
            dcr_id=dcr_id,
            id=id,
            definition=node_definition,
        )
        self.columns = columns
        self.dependency = dependency
        self.epsilon = epsilon
        self.output_original_data_statistics = output_original_data_statistics
        self.enable_logs_on_error = enable_logs_on_error
        self.enable_logs_on_success = enable_logs_on_success
        self.specification_id = "decentriq.python-synth-data-worker-32-64"
        self.static_content_specification_id = "decentriq.driver"

    def get_results_as_string(
        self,
        interval: int = 5,
        timeout: Optional[int] = None,
    ) -> Optional[str]:
        """
        Retrieve the results of a computation as a string.

        **Parameters**:
        - `interval`: Time interval (in seconds) to check for results.
        - `timeout`: Time (in seconds) after which results are no longer checked.
        """
        raw_result = self.get_results_as_bytes(interval=interval, timeout=timeout)
        if raw_result:
            return read_sql_query_result_as_string(raw_result)
        else:
            return None

    def run_computation_and_get_results_as_string(
        self,
        interval: int = 5,
        timeout: Optional[int] = None,
    ) -> Optional[str]:
        """
        This is a blocking call to run a computation and get the results as a
        string.

        **Parameters**:
        - `interval`: Time interval (in seconds) to check for results.
        - `timeout`: Time (in seconds) after which results are no longer checked.
        """
        raw_result = self.run_computation_and_get_results_as_bytes(
            interval=interval, timeout=timeout
        )
        if raw_result:
            return read_sql_query_result_as_string(raw_result)
        else:
            return None

    def _get_computation_id(self) -> str:
        """
        Retrieve the ID of the node corresponding to the computation.
        """
        return f"{self.id}_container"
