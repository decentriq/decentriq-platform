from __future__ import annotations

import json
from typing import Dict, Any, List, Optional, TYPE_CHECKING

from ..session import Session
from .computations import Computation
from decentriq_dcr_compiler.schemas import RequestedAudiencePayload

if TYPE_CHECKING:
    from ..client import Client


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
            "audiences.json", interval=interval, timeout=timeout
        )
        return json.loads(result)


class EstimateAudienceSizeForPublisherComputation(Computation):
    def __init__(
        self,
        dcr_id: str,
        client: Client,
        session: Session,
        generate_audience: RequestedAudiencePayload,
    ) -> None:
        super().__init__(dcr_id=dcr_id, client=client, session=session)
        self.generate_audience = generate_audience

    def node_id(self) -> str:
        return "estimate_audience_size_for_publisher"

    def run(self) -> None:
        """
        Run the computation.
        """
        super().run(
            request_type="estimateAudienceSizeForPublisher",
            generate_audience=self.generate_audience,
        )

    def get_results(
        self, interval: int = 5, timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        results = super().get_results_str_from_zip(
            "audience_size.json", interval=interval, timeout=timeout
        )
        return json.loads(results)


class EstimateAudienceSizeForPublisherLalComputation(Computation):
    def __init__(
        self,
        dcr_id: str,
        client: Client,
        session: Session,
        generate_audience: RequestedAudiencePayload,
        lal_audience: RequestedAudiencePayload,
    ) -> None:
        super().__init__(dcr_id=dcr_id, client=client, session=session)
        self.generate_audience = generate_audience
        self.lal_audience = lal_audience

    def node_id(self) -> str:
        return "estimate_audience_size_for_publisher_lal"

    def run(self) -> None:
        """
        Run the computation.
        """
        super().run(
            request_type="estimateAudienceSizeForPublisherLal",
            generate_audience=self.generate_audience,
            lal_audience=self.lal_audience,
        )

    def get_results(
        self, interval: int = 5, timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        results = super().get_results_str_from_zip(
            "audience_size.json", interval=interval, timeout=timeout
        )
        return json.loads(results)


class GetAudienceUserListForPublisherComputation(Computation):
    def __init__(
        self,
        dcr_id: str,
        client: Client,
        session: Session,
        generate_audience: RequestedAudiencePayload,
    ) -> None:
        super().__init__(dcr_id=dcr_id, client=client, session=session)
        self.generate_audience = generate_audience

    def node_id(self) -> str:
        return "get_audience_user_list_for_publisher"

    def run(self) -> None:
        """
        Run the computation.
        """
        super().run(
            request_type="getAudienceUserListForPublisher",
            generate_audience=self.generate_audience,
        )

    def get_results(
        self, interval: int = 5, timeout: Optional[int] = None
    ) -> List[str]:
        result = super().get_results_str_from_zip(
            "audience_users.csv", interval=interval, timeout=timeout
        )
        return [line for line in result.split("\n") if line]


class GetAudienceUserListForPublisherLalComputation(Computation):
    def __init__(
        self,
        dcr_id: str,
        client: Client,
        session: Session,
        generate_audience: RequestedAudiencePayload,
        lal_audience: RequestedAudiencePayload,
    ) -> None:
        super().__init__(dcr_id=dcr_id, client=client, session=session)
        self.generate_audience = generate_audience
        self.lal_audience = lal_audience

    def node_id(self) -> str:
        return "get_audience_user_list_for_publisher_lal"

    def run(self) -> None:
        """
        Run the computation.
        """
        super().run(
            request_type="getAudienceUserListForPublisherLal",
            generate_audience=self.generate_audience,
            lal_audience=self.lal_audience,
        )

    def get_results(
        self, interval: int = 5, timeout: Optional[int] = None
    ) -> List[str]:
        result = super().get_results_str_from_zip(
            "audience_users.csv", interval=interval, timeout=timeout
        )
        return [line for line in result.split("\n") if line]

class ComputeInsightsComputation(Computation):
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