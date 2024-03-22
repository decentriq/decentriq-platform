from __future__ import annotations

import re
from typing import Dict, Union
from abc import ABC, abstractmethod
from .high_level_node import ComputationNode, DataNode


_valid_node_name_pattern = re.compile(r"^([a-zA-Z]|[a-zA-Z][a-zA-Z0-9_ -]*[a-zA-Z0-9])$")


class NodeDefinition(ABC):
    def __init__(self, name: str, id: str) -> None:
        # This check makes sure that node names do not cause issues when they
        # are used as file names within containers.
        if not _valid_node_name_pattern.match(name):
            raise Exception(
                f"Cannot create a node with name '{name}' as it contains invalid characters."
                " Node names should only contain alphanumeric characters,"
                " non-leading and non-trailing underscores/hyphens, as well as whitespace."
                " In addition, names should not start with a number."
            )
        super().__init__()
        self.id = id
        self.name = name

    @abstractmethod
    def _get_high_level_representation(self) -> Dict[str, str]:
        """
        Retrieve the high level representation of the `HighLevelNode`.
        """
        pass

    @abstractmethod
    def build(
        self,
        dcr_id: str,
        node_definition: NodeDefinition,
        client: Client,
        session: Session,
    ) -> Union[ComputationNode, DataNode]:
        pass
