from __future__ import annotations

import io
import json
from typing import TYPE_CHECKING, Any, Dict, List, Optional
import zipfile

from decentriq_dcr_compiler.schemas import (
    EnvironmentComputationNode
)
from typing_extensions import Self

from ..session import Session
from .high_level_node import ContainerComputationNode
from .node_definitions import NodeDefinition

if TYPE_CHECKING:
    from ..client import Client
    
class PythonEnvironmentComputeNodeDefinition(NodeDefinition):
    """
    Class representing a Python Environment Definition.
    """
    
    def __init__(
        self,
        name: str,
        requirements_txt: str,
        id: Optional[str] = None,
    ) -> None:
        """
        Initialise a `PythonEnvironmentDefinition`.

        **Parameters**:
        - `name`: Name of the `PythonEnvironmentDefinition`.
        - `requirements_txt`: Content of the `requirements.txt` file which list the packages for the environment.
        """
        super().__init__(name, id=id or name)
        self.requirements_txt = requirements_txt
        self.scripting_specification_id = "decentriq.python-ml-worker-32-64"
        self.static_content_specification_id = "decentriq.driver"
        
    def _get_high_level_representation(self) -> Dict[str, str]:
        """
        Retrieve the high level representation of the `PythonEnvironmentDefinition`.
        """

        computation_node = {
            "id": self.id,
            "name": self.name,
            "kind": {
                "computation": {
                    "kind": {
                        "environment": {
                            "kind": {
                                "python": {
                                    "staticContentSpecificationId": self.static_content_specification_id,
                                    "scriptingSpecificationId": self.scripting_specification_id,
                                    "requirementsTxtContent": self.requirements_txt,
                                }
                            }
                        }
                    }
                }
            }
        }
        return computation_node

    @property
    def required_workers(self):
        return [self.scripting_specification_id, self.static_content_specification_id]

    @classmethod
    def _from_high_level(
        cls,
        id: str,
        name: str,
        node: EnvironmentComputationNode,
    ) -> Self:
        """
        Instantiate a `PythonEnvironmentComputeNode` from its high level representation.

        **Parameters**:
        - `name`: Name of the `PythonEnvironmentComputeNodeDefinition`.
        - `node`: Pydantic model of the `PythonEnvironmentComputeNode`.
        """
        environment_node = json.loads(node.model_dump_json())
        return cls(
            id=id,
            name=name,
            requirements_txt=environment_node["kind"]["python"]["requirementsTxtContent"],
        )

    def build(
        self,
        dcr_id: str,
        node_definition: NodeDefinition,
        client: Client,
        session: Session,
    ) -> PythonEnvironmentComputeNode:
        """
        Construct a PythonEnvironmentComputeNode from the Node Definition.

        **Parameters**:
        - `dcr_id`: ID of the DCR the node is a member of.
        - `node_definition`: Definition of the Python Environment Compute Node.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - `session`: The session with which to communicate with the enclave.
        """
        return PythonEnvironmentComputeNode(
            id=self.id,
            name=self.name,
            requirements_txt=self.requirements_txt,
            dcr_id=dcr_id,
            session=session,
            client=client,
            node_definition=node_definition,
        )

class PythonEnvironmentComputeNode(ContainerComputationNode):
    """
    Class representing an Environment.
    """

    def __init__(
        self,
        id: str,
        name: str,
        requirements_txt: str,
        dcr_id: str,
        session: Session,
        node_definition: NodeDefinition,
        *,
        client: Client,
    ) -> None:
        """
        Initialise an instance of a `PythonEnvironmentComputationNode`.

        **Parameters**:
        - `id`: ID of the `PythonEnvironmentComputeNode`.
        - `name`: Name of the `PythonEnvironmentComputeNode`.
        - `requirements_txt`: Content of the `requirements.txt` file which list the packages for the environment.
        - `dcr_id`: ID of the DCR the node is a member of.
        - `session`: The session with which to communicate with the enclave.
        - 'node_definition': Definition with which the node was built.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        """
        super().__init__(
            name=name,
            client=client,
            session=session,
            dcr_id=dcr_id,
            id=id,
            definition=node_definition,
        )
        self.requirements_txt = requirements_txt
        
    def _get_computation_id(self) -> str:
        """
        Retrieve the ID of the node corresponding to the computation.
        """
        return f"{self.id}_env_create"

    def get_installation_report_as_dict(self) -> Optional[Dict[str, str]]:
        """
        Retrieve the virtual environment creation report to this `PythonEnvironmentComputeNode`.
        """
        report_node_id = f"{self.id}_env_report"
        result = self.session.run_computation_and_get_results(
            self.dcr_id, report_node_id, interval=1
        )
        if result:
            report = {}
            zip = zipfile.ZipFile(io.BytesIO(result), "r")
            if "report.json" in zip.namelist():
                report = json.loads(
                    zip.read("report.json").decode()
                )
            return report
        else:
            return None
    


