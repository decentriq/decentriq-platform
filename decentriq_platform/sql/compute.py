from __future__ import annotations
import sqloxide
from google.protobuf.json_format import MessageToDict
from typing import List, Optional, Set, Tuple
from .proto import (
    PrimitiveType, PrivacySettings, ComputationConfiguration, TableSchema,
    ValidationConfiguration, Constraint, NamedColumn, ColumnType, SqlWorkerConfiguration,
    TableDependencyMapping
)
from ..proto import serialize_length_delimited, ComputeNodeFormat, parse_length_delimited
from ..node import Node


def parse_statement(sql_statement: str):
    statements = sqloxide.parse_sql(sql=sql_statement, dialect='generic')
    if len(statements) != 1:
        raise Exception("Only 1 statment allowed in SQL string")

    statement = statements[0]
    if "Query" not in statement:
        raise Exception("Non-query statement in SQL string")
    return statement["Query"]


def find_referenced_tables_table_factor(table_factor) -> Set[str]:
    if "Table" in table_factor:
        a = {table_factor["Table"]["name"][0]["value"]}
        return a
    elif "Derived" in table_factor:
        return find_referenced_tables(table_factor["Derived"]["subquery"])
    else:
        raise Exception("Unsupported SQL table factor")


def find_referenced_tables_body(sql_body) -> Set[str]:
    if "Select" in sql_body:
        from_select_statements = sql_body["Select"]["from"]
        if len(from_select_statements) != 1:
            raise Exception("Invalid FROM SQL statement")
        from_statement = from_select_statements[0]

        join_referenced_tables: Set[str] = set()
        for join_statement in from_statement["joins"]:
            join_referenced_tables.update(
                find_referenced_tables_table_factor(join_statement["relation"])
            )

        table_factor_referenced_tables = find_referenced_tables_table_factor(from_statement["relation"])
        return join_referenced_tables.union(table_factor_referenced_tables)
    elif "SetOperation" in sql_body:
        set_operation_statement = sql_body["SetOperation"]
        left_statement = set_operation_statement["left"]
        right_statement = set_operation_statement["right"]
        left_referenced_tables = find_referenced_tables_body(left_statement)
        right_referenced_tables = find_referenced_tables_body(right_statement)
        return left_referenced_tables.union(right_referenced_tables)
    else:
        raise Exception("Unsupported SQL expression")


def find_referenced_tables(sql_query) -> Set[str]:
    cte_tables: Set[str] = set()
    cte_referenced_tables: Set[str] = set()
    with_statement = sql_query["with"]
    if with_statement:
        cte_tables_statements = sql_query["with"]["cte_tables"]
        for table in cte_tables_statements:
            cte_tables.add(table["alias"]["name"]["value"])
            cte_referenced_tables.update(find_referenced_tables(table["query"]))

    query_tables = find_referenced_tables_body(sql_query["body"])
    all_tables = query_tables.union(cte_referenced_tables)
    return all_tables.difference(cte_tables)


class SqlCompute(Node):
    """
    Computation node to execute an SQL query.
    """

    def __init__(
            self,
            name: str,
            sql_statement: str,
            dependencies: List[(str, str)],
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
