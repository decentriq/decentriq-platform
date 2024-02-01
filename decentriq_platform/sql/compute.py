from __future__ import annotations
from google.protobuf.json_format import MessageToDict
from typing import List, Optional, Set, Tuple
from .proto import (
    PrimitiveType, PrivacySettings, ComputationConfiguration, TableSchema,
    ValidationConfiguration, Constraint, NamedColumn, ColumnType, SqlWorkerConfiguration,
    TableDependencyMapping
)
from ..proto import serialize_length_delimited, ComputeNodeFormat, parse_length_delimited
from ..node import Node


class SqlCompute(Node):
    """
    Computation node to execute an SQL query.
    """

    def __init__(
            self,
            name: str,
            sql_statement: str,
            dependencies: List[Tuple[str, str]],
            *,
            privacy_settings: Optional[PrivacySettings] = None,
            constraints: Optional[List[Constraint]] = None,
    ) -> None:
        sql_worker_configuration = SqlWorkerConfiguration(
            computation=ComputationConfiguration(
                sqlStatement=sql_statement,
                privacySettings=privacy_settings,
                constraints=constraints,
                tableDependencyMappings=[
                    TableDependencyMapping(table=table, dependency=node_id)
                    for table, node_id in dependencies
                ]
            )
        )
        config = serialize_length_delimited(sql_worker_configuration)

        super().__init__(
            name,
            config=config,
            enclave_type="decentriq.sql-worker",
            dependencies=[node_id for _, node_id in dependencies],
            output_format=ComputeNodeFormat.ZIP
        )


class SqlSchemaVerifier(Node):
    """
    Computation node to validate an input and provide the necessary types.
    """

    def __init__(
        self,
        name: str,
        input_data_node: str,
        columns, # type: List[Tuple[str, PrimitiveType.V, bool]]
    ) -> None:
        named_columns = map(lambda c: NamedColumn(
            name=c[0],
            columnType=ColumnType(
                primitiveType=c[1],
                nullable=c[2]
                )
            ),
            columns
        )
        sql_worker_configuration = SqlWorkerConfiguration(
            validation=ValidationConfiguration(
                tableSchema=TableSchema(namedColumns=named_columns)
            )
        )
        config = serialize_length_delimited(sql_worker_configuration)

        super().__init__(
            name,
            config=config,
            enclave_type="decentriq.sql-worker",
            dependencies=[input_data_node],
            output_format=ComputeNodeFormat.ZIP
        )


class SqlWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = SqlWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)
