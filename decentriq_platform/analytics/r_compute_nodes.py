from __future__ import annotations

import json
from typing import TYPE_CHECKING, Dict, List, Optional

from decentriq_dcr_compiler.schemas.data_science_data_room import (
    ScriptingComputationNode,
)
from typing_extensions import Self

from ..session import Session
from .high_level_node import ContainerComputationNode
from .node_definitions import NodeDefinition
from .script import FileContent, ScriptingLanguage

if TYPE_CHECKING:
    from ..client import Client


class RComputeNodeDefinition(NodeDefinition):
    def __init__(
        self,
        name: str,
        script: str,
        additional_files: Optional[List[FileContent]] = None,
        dependencies: List[str] = [],
        enable_logs_on_error: bool = False,
        enable_logs_on_success: bool = False,
        output: Optional[str] = "/output",
        id: Optional[str] = None,
    ) -> None:
        """
        Initialise a `RComputeNodeDefinition`:

        **Parameters**:
        - `name`: Name of the `RComputeNodeDefinition`.
        - `script`: The R computation as a string.
        - `additional_files`: Other files that can be used by the `RComputeNodeDefinition`.
        - `dependencies`: Nodes that the `RComputeNodeDefinition` depends on.
        - `enable_logs_on_error`: Enable logs in the event of an error.
        - `enable_logs_on_success`: Enable logs when the computation is successful.
        - `output`: Directory where the results should be written.
        """
        super().__init__(name=name, id=id or name)
        self.script = script
        self.dependencies = dependencies
        self.additional_files = additional_files
        self.enable_logs_on_error = enable_logs_on_error
        self.enable_logs_on_success = enable_logs_on_success
        self.output = output
        self.scripting_specification_id = "decentriq.r-ml-worker-32-32"
        self.static_content_specification_id = "decentriq.driver"

    @property
    def required_workers(self):
        return [self.scripting_specification_id, self.static_content_specification_id]

    def _get_high_level_representation(self) -> Dict[str, str]:
        """
        Retrieve the high level representation of the `RComputeNodeDefinition`.
        """
        additional_files = []
        if self.additional_files:
            additional_files = [
                {
                    "name": file.name,
                    "content": file.content,
                }
                for file in self.additional_files
            ]
        computation_node = {
            "id": self.id,
            "name": self.name,
            "kind": {
                "computation": {
                    "kind": {
                        "scripting": {
                            "additionalScripts": additional_files,
                            "dependencies": self.dependencies,
                            "enableLogsOnError": self.enable_logs_on_error,
                            "enableLogsOnSuccess": self.enable_logs_on_success,
                            "mainScript": {
                                "name": "r-script",
                                "content": self.script,
                            },
                            "output": self.output,
                            "scriptingLanguage": ScriptingLanguage.r.value,
                            "scriptingSpecificationId": self.scripting_specification_id,
                            "staticContentSpecificationId": self.static_content_specification_id,
                        }
                    }
                },
            },
        }
        return computation_node

    @classmethod
    def _from_high_level(
        cls,
        id: str,
        name: str,
        node: ScriptingComputationNode,
    ) -> Self:
        """
        Instantiate a `RComputeNodeDefinition` from its high level representation.

        **Parameters**:
        - `name`: Name of the `RComputeNodeDefinition`.
        - `node`: Pydantic model of the `RComputeNode`.
        """
        scripting_node = json.loads(node.model_dump_json())
        return cls(
            id=id,
            name=name,
            script=scripting_node["mainScript"]["content"],
            dependencies=scripting_node["dependencies"],
            additional_files=[
                FileContent(name=script["name"], content=script["content"])
                for script in scripting_node["additionalScripts"]
            ],
            enable_logs_on_error=scripting_node["enableLogsOnError"],
            enable_logs_on_success=scripting_node["enableLogsOnSuccess"],
            output=scripting_node["output"],
        )

    def build(
        self,
        dcr_id: str,
        node_definition: NodeDefinition,
        client: Client,
        session: Session,
    ) -> RComputeNode:
        """
        Construct a RComputeNode from the Node Definition.

        **Parameters**:
        - `dcr_id`: ID of the DCR the node is a member of.
        - `node_definition`: Definition of the R Compute Node.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        """
        return RComputeNode(
            name=self.name,
            dcr_id=dcr_id,
            script=self.script,
            client=client,
            session=session,
            node_definition=node_definition,
            dependencies=self.dependencies,
            additional_files=self.additional_files,
            enable_logs_on_error=self.enable_logs_on_error,
            enable_logs_on_success=self.enable_logs_on_success,
            output=self.output,
            id=self.id,
        )


class RComputeNode(ContainerComputationNode):
    """
    Class representing an R Computation node.

    An RComputeNode is able to run arbitrary R code.
    """

    def __init__(
        self,
        id: str,
        name: str,
        dcr_id: str,
        script: str,
        client: Client,
        session: Session,
        node_definition: NodeDefinition,
        additional_files: Optional[List[FileContent]] = None,
        dependencies: List[str] = [],
        enable_logs_on_error: bool = False,
        enable_logs_on_success: bool = False,
        output: Optional[str] = "/output",
    ) -> None:
        """
        Initialise a `RComputeNode`:

        **Parameters**:
        - `id`: ID of the `RComputeNode`.
        - `name`: Name of the `RComputeNode`.
        - `dcr_id`: ID of the DCR the node is a member of.
        - `script`: The R computation.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        - `node_definition`: Definition of the Matching Node.
        - `additional_files`: Other files that can be used by the `RComputeNode`.
        - `dependencies`: Nodes that the `RComputeNode` depends on.
        - `enable_logs_on_error`: Enable logs in the event of an error.
        - `enable_logs_on_success`: Enable logs when the computation is successful.
        - `output`: Directory where the results should be written.
        """
        super().__init__(
            name=name,
            client=client,
            session=session,
            dcr_id=dcr_id,
            id=id,
            definition=node_definition,
        )
        self.script = script
        self.dependencies = dependencies
        self.additional_files = additional_files
        self.enable_logs_on_error = enable_logs_on_error
        self.enable_logs_on_success = enable_logs_on_success
        self.output = output
        self.scripting_specification_id = "decentriq.r-ml-worker-32-32"
        self.static_content_specification_id = "decentriq.driver"

    def _get_computation_id(self) -> str:
        """
        Retrieve the ID of the node corresponding to the computation.
        """
        return f"{self.id}_container"
