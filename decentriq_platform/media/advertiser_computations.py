from __future__ import annotations

import io
import json
from typing import Dict, Any, Optional, TYPE_CHECKING
import zipfile

from ..session import Session
from .computations import Computation

if TYPE_CHECKING:
    from ..client import Client


class AvailableAudiencesComputation(Computation):
    def __init__(self, dcr_id: str, client: Client, session: Session) -> None:
        super().__init__(dcr_id=dcr_id, client=client, session=session)

    def node_id(self) -> str:
        return "compute_available_audiences"

    def run(self) -> None:
        """
        Run the computation.
        """
        super().run(request_type="computeAvailableAudiences")

    def get_results(
        self, interval: int = 5, timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        results = super().get_results_str_from_zip(
            "available_audiences.json", interval=interval, timeout=timeout
        )
        return json.loads(results)


class GetAudiencesForAdvertiserComputation(Computation):
    def __init__(self, dcr_id: str, client: Client, session: Session) -> None:
        super().__init__(dcr_id=dcr_id, client=client, session=session)

    def node_id(self) -> str:
        return "get_audiences_for_advertiser"

    def run(self) -> None:
        """
        Run the computation.
        """
        super().run(request_type="getAudiencesForAdvertiser")

    def get_results(
        self, interval: int = 5, timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        results = super().get_results_str_from_zip(
            "activated_audiences.json", interval=interval, timeout=timeout
        )
        return json.loads(results)
