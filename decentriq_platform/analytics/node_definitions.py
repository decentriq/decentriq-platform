from __future__ import annotations

from typing import Dict, Union
from abc import ABC, abstractmethod
from .high_level_node import ComputationNode, DataNode


class NodeDefinition(ABC):
    def __init__(self, name: str, id: str) -> None:
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
