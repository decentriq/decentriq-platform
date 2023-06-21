from google.protobuf.json_format import MessageToDict
from ..proto import serialize_length_delimited, ComputeNodeFormat, parse_length_delimited
from ..node import Node
from typing import List, Optional, Set, Tuple
from .proto import (
    DataSourceSnowflakeWorkerConfiguration,
    SnowflakeSource,
)
from ..sql.proto import TableSchema, NamedColumn, ColumnType

__docformat__ = "restructuredtext"
__pdoc__ = {
    "proto": False,
}

class DataSourceSnowflake(Node):
    """
    Compute node that fetches a dataset from a Snowflake stage.
    """

    def __init__(
            self,
            name: str,
            warehouseName: str,
            databaseName: str,
            schemaName: str,
            tableName: str,
            stageName: str,
            credentials_dependency: str,
    ) -> None:
        config = DataSourceSnowflakeWorkerConfiguration(
            source=SnowflakeSource(
                warehouseName=warehouseName,
                databaseName=databaseName,
                schemaName=schemaName,
                tableName=tableName,
                stageName=stageName,
            ),
            credentialsDependency=credentials_dependency,
        )
        config_serialized = serialize_length_delimited(config)
        super().__init__(
            name,
            config=config_serialized,
            enclave_type="decentriq.data-source-snowflake-worker",
            dependencies=[credentials_dependency],
            output_format=ComputeNodeFormat.ZIP
        )

class DataSourceSnowflakeWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = DataSourceSnowflakeWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)

__all__ = [
    "DataSourceSnowflake",
]
