from __future__ import annotations

import io
import json
import zipfile
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Dict, List, Optional, cast

from decentriq_dcr_compiler.schemas import TableLeafNodeV2
from typing_extensions import Self

from ..session import Session
from ..storage import Key
from .high_level_node import DataNode
from .node_definitions import NodeDefinition

if TYPE_CHECKING:
    from ..client import Client


class PrimitiveType(str, Enum):
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"


class FormatType(str, Enum):
    STRING = "STRING"
    INTEGER = "INTEGER"
    FLOAT = "FLOAT"
    EMAIL = "EMAIL"
    DATE_ISO8601 = "DATE_ISO8601"
    PHONE_NUMBER_E164 = "PHONE_NUMBER_E164"
    HASH_SHA256_HEX = "HASH_SHA256_HEX"

    @staticmethod
    def from_primitive_type(tpe: str) -> FormatType:
        tpe = tpe.lower()
        if tpe == "integer":
            return FormatType.INTEGER
        elif tpe == "float":
            return FormatType.FLOAT
        elif tpe == "string":
            return FormatType.STRING
        else:
            raise Exception(f"Unable to convert data type {tpe} to a format type")

    @staticmethod
    def to_primitive_type(fmt: FormatType) -> str:
        if fmt == FormatType.INTEGER:
            return "integer"
        elif fmt == FormatType.FLOAT:
            return "float"
        elif fmt in {
            FormatType.STRING,
            FormatType.EMAIL,
            FormatType.DATE_ISO8601,
            FormatType.PHONE_NUMBER_E164,
            FormatType.HASH_SHA256_HEX,
        }:
            return "string"
        else:
            raise Exception(f"Unable to convert format type {fmt} to a primitive type")


class HashingAlgorithm(str, Enum):
    SHA256_HEX = "SHA256_HEX"


class NumericRangeRule:
    greater_than: Optional[float] = None
    greater_than_equals: Optional[float] = None
    less_than: Optional[float] = None
    less_than_equals: Optional[float] = None


@dataclass
class Column:
    format_type: FormatType
    name: str
    is_nullable: bool
    hash_with: Optional[HashingAlgorithm] = None
    in_range: Optional[NumericRangeRule] = None


class TableDataNodeDefinition(NodeDefinition):
    """
    Class representing a Table Data Node Definition.
    """

    def __init__(
        self,
        name: str,
        columns: List[Column],
        is_required: bool,
        id: Optional[str] = None,
        unique_column_combinations: list[list[int]] = [],
    ) -> None:
        """
        Initialise a `TableDataNodeDefinition` instance.

        **Parameters**:
        - `name`: Name of the `TableDataNodeDefinition`
        - `columns`: Definition of the columns that make up the `TableDataNodeDefinition`.
        - `is_required`: Flag determining if the `RawDataNode` must be present for dependent computations.
        - `id`: Optional ID of the `TableDataNodeDefinition`
        - `unique_column_combinations`: Check that the given combination of
          columns are unique across the dataset. This should be a list of lists,
          where the inner lists list the 0-based column indices.
          For example, passing the list `[[0], [0, 1]]` would result in the enclave
          checking that all values in the first column are unique.
          It would further check that all tuples formed by the first and second
          column are unique.
        """
        super().__init__(name, id=id or name)
        self.is_required = is_required
        self.columns = columns
        self.specification_id = "decentriq.python-ml-worker-32-64"
        self.static_content_specification_id = "decentriq.driver"
        self.unique_column_combinations = unique_column_combinations

    def _get_high_level_representation(self) -> Dict[str, str]:
        """
        Retrieve the high level representation of the `TableDataNodeDefinition`.
        """
        column_entries = []
        for column in self.columns:
            validation = {
                "name": column.name,
                "formatType": column.format_type.value,
                "allowNull": column.is_nullable,
            }
            if column.hash_with:
                validation["hashWith"] = column.hash_with.value
            if column.in_range:
                # TODO: fix this
                validation["inRange"] = column.in_range
            column_entries.append(
                {
                    "name": column.name,
                    "dataFormat": {
                        "isNullable": column.is_nullable,
                        "dataType": FormatType.to_primitive_type(column.format_type),
                    },
                    "validation": validation,
                }
            )

        table_validation = {}
        if self.unique_column_combinations:
            table_validation["uniqueness"] = {
                "uniqueKeys": [
                    {
                        "columns": indices
                    }
                ] for indices in self.unique_column_combinations
            }

        table_node = {
            "id": self.id,
            "name": self.name,
            "kind": {
                "leaf": {
                    "isRequired": self.is_required,
                    "kind": {
                        "table": {
                            "columns": column_entries,
                            "validationNode": {
                                "staticContentSpecificationId": self.static_content_specification_id,
                                "pythonSpecificationId": self.specification_id,
                                "validation": table_validation,
                            },
                        }
                    },
                }
            },
        }
        return table_node

    @property
    def required_workers(self):
        return [self.static_content_specification_id, self.specification_id]

    @classmethod
    def _from_high_level(
        cls,
        id: str,
        name: str,
        node: TableLeafNodeV2,
        is_required: bool,
    ) -> Self:
        """
        Instantiate a `TableDataNodeDefinition` from its high level representation.

        **Parameters**:
        - `name`: Name of the `TableDataNodeDefinition`.
        - `node`: Pydantic model of the `TableDataNodeDefinition`.
        """
        node_dict = json.loads(node.model_dump_json())
        columns = [
            Column(
                name=column["name"],
                format_type=(
                    column["validation"]["formatType"]
                    if "formatType" in column.get("validation")
                    else FormatType.from_primitive_type(
                        column["dataFormat"]["dataType"]
                    )
                ),
                is_nullable=column["dataFormat"]["isNullable"],
                hash_with=column["validation"]["hashWith"],
                in_range=column["validation"]["inRange"],
            )
            for column in node_dict["columns"]
        ]
        return cls(
            id=id,
            name=name,
            columns=columns,
            is_required=is_required,
        )

    def build(
        self,
        dcr_id: str,
        node_definition: NodeDefinition,
        client: Client,
        session: Session,
    ) -> TableDataNode:
        """
        Construct a TableDataNode from the Node Definition.

        **Parameters**:
        - `dcr_id`: ID of the DCR the node is a member of.
        - `node_definition`: Definition of the Table Data Node.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        """
        return TableDataNode(
            name=self.name,
            columns=self.columns,
            is_required=self.is_required,
            dcr_id=dcr_id,
            node_definition=cast(TableDataNodeDefinition, node_definition),
            client=client,
            session=session,
            id=self.id,
        )


class TableDataNode(DataNode):
    """
    Class representing a Table Data Node.
    """

    def __init__(
        self,
        id: str,
        name: str,
        columns: List[Column],
        is_required: bool,
        dcr_id: str,
        client: Client,
        session: Session,
        node_definition: TableDataNodeDefinition,
    ) -> None:
        """
        Initialise a `TableDataNode` instance.

        **Parameters**:
        - 'id': ID of the `TableDataNode`.
        - `name`: Name of the `TableDataNode`
        - `columns`: Definition of the columns that make up the `TableDataNode`.
        - `is_required`: Flag determining if the `TableDataNode` must be present for dependent computations.
        - `dcr_id`: ID of the DCR the node is a member of.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        """
        super().__init__(
            name=name,
            is_required=is_required,
            dcr_id=dcr_id,
            client=client,
            session=session,
            id=id,
            definition=node_definition,
        )
        self.columns = columns

    # This data node needs to override the `super` implementation because
    # the leaf ID requires the "_leaf" suffix.
    def publish_dataset(self, manifest_hash: str, key: Key):
        """
        Publish data to the `TableDataNode`.

        **Parameters**:
        - `manifest_hash`: Hash identifying the dataset to be published.
        - `key`: Encryption key used to decrypt the dataset.
        """
        self.session.publish_dataset(
            self.dcr_id, manifest_hash, leaf_id=f"{self.id}_leaf", key=key
        )

    def get_validation_report_as_dict(self) -> Optional[Dict[str, str]]:
        """
        Retrieve the validation report corresponding to this `TableDataNode`.
        """
        validation_node_id = f"{self.id}_validation_report"
        result = self.session.run_computation_and_get_results(
            self.dcr_id, validation_node_id, interval=1
        )
        if result:
            validation_report = {}
            zip = zipfile.ZipFile(io.BytesIO(result), "r")
            if "validation-report.json" in zip.namelist():
                validation_report = json.loads(
                    zip.read("validation-report.json").decode()
                )
            return validation_report
        else:
            return None

    def remove_published_dataset(self) -> None:
        """
        Removes any dataset that is published to this node.
        """
        self.session.remove_published_dataset(self.dcr_id, f"{self.id}_leaf")
