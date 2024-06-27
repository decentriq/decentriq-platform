from __future__ import annotations

import io
from typing import Dict, Any, Optional, TYPE_CHECKING

from abc import ABC, abstractmethod
import zipfile
from ..session import Session
from ..types import JobId
from decentriq_dcr_compiler.schemas import MediaInsightsRequest, MediaInsightsResponse
from .request import Request

if TYPE_CHECKING:
    from ..client import Client


class Computation(ABC):
    """
    Abstract class representing a computation.
    """

    def __init__(self, dcr_id: str, client: Client, session: Session) -> None:
        super().__init__()
        self.dcr_id = dcr_id
        self.client = client
        self.session = session
        self.job_id = None

    @abstractmethod
    def node_id(self) -> str:
        pass

    def send_request(self, request: MediaInsightsRequest) -> MediaInsightsResponse:
        return Request.send(request, self.session)

    def run(self, request_type: str) -> None:
        """
        Run the computation
        """
        request = MediaInsightsRequest.model_validate(
            {
                request_type: {
                    "dataRoomIdHex": self.dcr_id,
                    "scopeIdHex": self.client._ensure_dcr_data_scope(self.dcr_id),
                },
            }
        )
        response = self.send_request(request).model_dump()
        self.job_id = JobId(
            job_id=response[request_type]["jobIdHex"],
            compute_node_id=self.node_id(),
        )

    def get_results_str_from_zip(
        self, file_name: str, interval: int = 5, timeout: Optional[int] = None
    ) -> str:
        results = self.session.get_computation_result(
            self.job_id,
            interval=interval,
            timeout=timeout,
        )
        zip = zipfile.ZipFile(io.BytesIO(results), "r")
        if file_name in zip.namelist():
            return zip.read(file_name).decode()
        else:
            raise Exception(f"Failed to read {file_name} from zip.")

    def get_results(
        self, interval: int = 5, timeout: Optional[int] = None
    ) -> bytes:
        pass

    def run_and_get_results(
        self, interval: int = 5, timeout: Optional[int] = None
    ) -> bytes:
        self.run()
        return self.get_results(interval=interval, timeout=timeout)
