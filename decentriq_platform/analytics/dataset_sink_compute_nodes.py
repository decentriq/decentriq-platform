from __future__ import annotations

from dataclasses import dataclass
import io
import json
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union
import zipfile

from decentriq_dcr_compiler.schemas import (
    DatasetSinkComputationNode,
    DatasetSinkInput,
)
from decentriq_dcr_compiler.schemas.secret_store_entry_state import SecretStoreEntryState
from typing_extensions import Self

from ..storage import Key

from ..session import Session
from ..archv2 import Secret
from .high_level_node import ComputationNode
from .node_definitions import NodeDefinition

if TYPE_CHECKING:
    from ..client import Client


class SinkInput:
    def __init__(self, high_level: Dict[str, Any]) -> None:
        self.high_level_definition = high_level


class SinkInputFormat:
    """
    Factory for creating the desired `SinkInput` type.
    """
    @staticmethod
    def raw() -> SinkInput:
        """
        Store a single raw file to the Decentriq Platform.
        """
        return SinkInput({"raw": ()})

    @staticmethod
    def all() -> SinkInput:
        """
        Store all files in a zip to the Decentriq Platform.
        """
        return SinkInput({"zip": {"all": ()}})

    @staticmethod
    def files(files: List[str]) -> SinkInput:
        """
        Store the specified files in a zip to the Decentriq Platform.
        """
        return SinkInput({"zip": {"files": [files]}})


class DatasetSinkComputeNodeDefinition(NodeDefinition):
    def __init__(
        self,
        name: str,
        dataset_name: str,
        dependency: str,
        encryption_key_dependency: str,
        input_type: SinkInput,
        is_key_hex_encoded: Optional[bool] = False,
        id: Optional[str] = None,
    ) -> None:
        """
        Initialise a `DatasetSinkComputeNodeDefinition`.
        This class is used to construct DatasetSinkComputeNodes.

        **Parameters**:
        - `name`: Name of the `DatasetSinkComputeNodeDefinition`.
        - `dataset_name`: Name of the dataset when it is stored in the Decentriq Platform.
        - `dependency`: Name of the node whose data will be stored.
        - `encryption_key_dependency`: Name of the node storing the encryption key that
                will be used to encrypt the dataset in the Decentriq Platform.
        - `input_type`: The type of input data to be stored (raw, list of files in a zip, entire zip contents).
        - `is_key_hex_encoded`: Flag indicating whether or not the encryption key is hex encoded (`False` indicates raw bytes).
        - `id`: Optional ID of the dataset sink node.
        """
        super().__init__(name, id=id or name)
        self.dataset_name = dataset_name
        self.dependency = dependency
        self.encryption_key_dependency = encryption_key_dependency
        self.is_key_hex_encoded = is_key_hex_encoded
        self.input_type = input_type
        self.specification_id = "decentriq.dataset-sink-worker"

    def _get_high_level_representation(self) -> Dict[str, str]:
        """
        Retrieve the high level representation of the `DatasetSinkComputeNodeDefinition`.
        """
        computation_node = {
            "id": self.id,
            "name": self.name,
            "kind": {
                "computation": {
                    "kind": {
                        "datasetSink": {
                            "datasetImportId": None,
                            "encryptionKeyDependency": {
                                "dependency": self.encryption_key_dependency,
                                "isKeyHexEncoded": self.is_key_hex_encoded,
                            },
                            "input": {
                                "datasetName": self.dataset_name,
                                "dependency": self.dependency,
                                "inputDataType": self.input_type.high_level_definition,
                            },
                            "specificationId": self.specification_id,
                        }
                    }
                },
            },
        }
        return computation_node

    @property
    def required_workers(self):
        return [self.specification_id]

    @classmethod
    def _from_high_level(
        cls,
        id: str,
        name: str,
        node: DatasetSinkComputationNode,
    ) -> Self:
        """
        Instantiate a `DatasetSinkComputeNodeDefinition` from its high level representation.

        **Parameters**:
        - `id`: ID of the `DatasetSinkComputeNodeDefinition`.
        - `name`: Name of the `DatasetSinkComputeNodeDefinition`.
        - `node`: Pydantic model of the `DatasetSinkComputationNode`.
        """
        return cls(
            name=name,
            dataset_name=node.input.datasetName,
            dependency=node.input.dependency,
            encryption_key_dependency=node.encryptionKeyDependency.dependency,
            is_key_hex_encoded=node.encryptionKeyDependency.isKeyHexEncoded,
            input_type=cls._get_input_type_from_high_level(node.input),
            id=id,
        )

    @staticmethod
    def _get_input_type_from_high_level(
        input: DatasetSinkInput,
    ) -> Union[SinkInputFormatRaw | SinkInputZipAll | SinkInputZipFiles]:
        input_data_type = input.inputDataType.root
        fields = input_data_type.model_fields
        if "raw" in fields:
            return SinkInputFormat.raw()
        elif "zip" in fields:
            zip_type = input_data_type.zip.root
            zip_type_fields = zip_type.model_fields
            if "all" in zip_type_fields:
                return SinkInputFormat.all()
            elif "files" in zip_type_fields:
                return SinkInputFormat.files(files=zip_type.files)
            else:
                raise Exception(f"Unknown zip type {zip_type}")
        else:
            raise Exception(f"Unknown input data type {input.inputDataType}")

    def build(
        self,
        dcr_id: str,
        node_definition: NodeDefinition,
        client: Client,
        session: Session,
    ) -> DatasetSinkComputeNode:
        """
        Construct a `DatasetSinkComputeNode` from the definition.

        **Parameters**:
        - `dcr_id`: ID of the DCR the node is a member of.
        - `node_definition`: Definition of the DatasetSink Compute Node.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        """
        return DatasetSinkComputeNode(
            name=self.name,
            dcr_id=dcr_id,
            client=client,
            session=session,
            node_definition=node_definition,
            id=self.id,
        )


class DatasetSinkComputeNode(ComputationNode):
    """
    A DatasetSinkComputeNode is a node that can write datasets to the Decentriq Platform.
    """

    def __init__(
        self,
        id: str,
        name: str,
        dcr_id: str,
        client: Client,
        session: Session,
        node_definition: NodeDefinition,
    ) -> None:
        """
        Initialise a `DatasetSinkComputeNode`.

        **Parameters**:
        - `id`: ID of the `DatasetSinkComputeNode`
        - `name`: Name of the `DatasetSinkComputeNode`.
        - `dcr_id`: ID of the DCR the node is a member of.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        - `node_definition`: The definition of the `DatasetSinkComputeNode`.
        """
        super().__init__(
            name=name,
            client=client,
            session=session,
            dcr_id=dcr_id,
            id=id,
            definition=node_definition,
        )

    def _get_computation_id(self) -> str:
        """
        Retrieve the ID of the node corresponding to the computation.
        """
        return self.id

    def store_dataset_key(self, key: Key) -> Dict[str, Any]:
        """
        Store the dataset to the Decentriq Platform and add an entry to
        the secret store for the encryption key used to encrypt the dataset.
        """
        result = self.run_computation_and_get_results_as_bytes()
        result_zip = zipfile.ZipFile(io.BytesIO(result), "r")
        datasets_json = json.loads(result_zip.read("datasets.json").decode())
        session_v2 = self.client.create_session_v2()
        for dataset in datasets_json["datasets"]:
            manifest_hash = dataset["manifestHash"]
            encryption_key_secret = Secret(secret=key.material, state=SecretStoreEntryState.model_validate(
                {
                    "version": "V0",
                    "acl": {
                        "type": "UsersList",
                        "users": [
                            {
                                "id": self.client.user_email,
                                "role": "Owner",
                            },
                        ],
                    },
                    "type": "DatasetKey",
                    "manifest_hash": manifest_hash,
                }
            ))
            session_v2.create_secret(encryption_key_secret)
        return datasets_json["datasets"]
