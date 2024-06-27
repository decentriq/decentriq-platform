from __future__ import annotations

import io
import json
from typing import Dict, Any, List, Optional, TYPE_CHECKING
import zipfile

from ..session import Session
from .computations import Computation
from ..types import JobId
from decentriq_dcr_compiler.schemas import MediaInsightsRequest
from .audience import Audience

if TYPE_CHECKING:
    from ..client import Client


class OverlapInsightsComputation(Computation):
    def __init__(self, dcr_id: str, client: Client, session: Session) -> None:
        super().__init__(dcr_id=dcr_id, client=client, session=session)

    def node_id(self) -> str:
        return "compute_insights"

    def run(self) -> None:
        """
        Run the computation.
        """
        super().run(request_type="computeInsights")

    def get_results(
        self, interval: int = 5, timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        result = super().get_results_str_from_zip(
            "segments.json", interval=interval, timeout=timeout
        )
        return json.loads(result)


class OverlapStatisticsComputation(Computation):
    def __init__(self, dcr_id: str, client: Client, session: Session) -> None:
        super().__init__(dcr_id=dcr_id, client=client, session=session)

    def node_id(self) -> str:
        return "compute_overlap_statistics"

    def run(self) -> None:
        """
        Run the computation.
        """
        super().run(request_type="computeOverlapStatistics")

    def get_results(
        self, interval: int = 5, timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        result = super().get_results_str_from_zip(
            "overlap.json", interval=interval, timeout=timeout
        )
        return json.loads(result)


class GetAudiencesForPublisherComputation(Computation):
    def __init__(self, dcr_id: str, client: Client, session: Session) -> None:
        super().__init__(dcr_id=dcr_id, client=client, session=session)

    def node_id(self) -> str:
        return "get_audiences_for_publisher"

    def run(self) -> None:
        """
        Run the computation.
        """
        super().run(request_type="getAudiencesForPublisher")

    def get_results(
        self, interval: int = 5, timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        result = super().get_results_str_from_zip(
            "activated_audiences.json", interval=interval, timeout=timeout
        )
        return json.loads(result)


class GetAudienceUserListComputation(Computation):
    def __init__(
        self,
        dcr_id: str,
        audience: Audience,
        client: Client,
        session: Session,
    ) -> None:
        super().__init__(dcr_id=dcr_id, client=client, session=session)
        self.audience = audience

    def node_id(self) -> str:
        return "get_audience_user_list"

    def run(self) -> None:
        """
        Run the computation.
        """
        request = MediaInsightsRequest.model_validate(
            {
                "getAudienceUserList": {
                    "dataRoomIdHex": self.dcr_id,
                    "scopeIdHex": self.client._ensure_dcr_data_scope(self.dcr_id),
                    "requestedAudience": {
                        "activation_type": self.audience.activation_type,
                        "audience_type": self.audience.audience_type,
                        "reach": self.audience.reach,
                    },
                },
            }
        )
        response = self.send_request(request).model_dump()
        self.job_id = JobId(
            job_id=response["getAudienceUserList"]["jobIdHex"],
            compute_node_id=self.node_id(),
        )

    def get_results(
        self, interval: int = 5, timeout: Optional[int] = None
    ) -> List[str]:
        result = super().get_results_str_from_zip(
            "audience_users.csv", interval=interval, timeout=timeout
        )
        return [line for line in result.split("\n") if line]
