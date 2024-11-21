from __future__ import annotations

import json
from typing import Dict, Any, List, Optional, TYPE_CHECKING

from .computations import Computation
from ..session import Session
from ..storage import Key
from decentriq_dcr_compiler.schemas import RequestedAudiencePayload
from decentriq_dcr_compiler.schemas import (
    AbMediaRequest,
    RequestedAudiencePayload,
)

if TYPE_CHECKING:
    from ..client import Client


class PublishAudiencesDataset(Computation):
    def __init__(
        self, dcr_id: str, dataset_id: str, key: Key, client: Client, session: Session
    ) -> None:
        super().__init__(dcr_id=dcr_id, client=client, session=session)
        self.dataset_id = dataset_id
        self.key = key

    def node_id(self) -> str:
        pass

    def run(self) -> None:
        """
        Run the computation.
        """
        super().run(request_type="publishAudiencesDataset")


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
            "audiences.json", interval=interval, timeout=timeout
        )
        return json.loads(results)


class RunCreateAudienceUserList(Computation):
    def __init__(self, dcr_id: str, client: Client, session: Session) -> None:
        super().__init__(dcr_id=dcr_id, client=client, session=session)

    def node_id(self) -> str:
        return "run_create_audience_user_list"

    def run(self) -> None:
        """
        Run the computation.
        """
        super().run(request_type="runCreateAudienceUserList")


class EstimateAudienceSizeForAdvertiserComputation(Computation):
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
        return "estimate_audience_size_for_advertiser"

    def run(self) -> None:
        """
        Run the computation.
        """
        super().run(
            request_type="estimateAudienceSizeForAdvertiser",
            generate_audience=self.generate_audience,
        )

    def get_results(
        self, interval: int = 5, timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        results = super().get_results_str_from_zip(
            "audience_size.json", interval=interval, timeout=timeout
        )
        return json.loads(results)


class EstimateAudienceSizeForAdvertiserLalComputation(Computation):
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
        return "estimate_audience_size_for_advertiser_lal"

    def run(self) -> None:
        """
        Run the computation.
        """
        super().run(
            request_type="estimateAudienceSizeForAdvertiserLal",
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


class GetAudienceUserListForAdvertiserComputation(Computation):
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
        return "get_audience_user_list_for_advertiser"

    def run(self) -> None:
        """
        Run the computation.
        """
        super().run(
            request_type="getAudienceUserListForAdvertiser",
            generate_audience=self.generate_audience,
        )

    def get_results(
        self, interval: int = 5, timeout: Optional[int] = None
    ) -> List[str]:
        result = super().get_results_str_from_zip(
            "audience_users.csv", interval=interval, timeout=timeout
        )
        return [line for line in result.split("\n") if line]


class GetAudienceUserListForAdvertiserLalComputation(Computation):
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
        return "get_audience_user_list_for_advertiser_lal"

    def run(self) -> None:
        """
        Run the computation.
        """
        super().run(
            request_type="getAudienceUserListForAdvertiserLal",
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


class PublishAudiencesJson(Computation):
    def __init__(
        self,
        dcr_id: str,
        manifest_hash: str,
        encryption_key_hex: str,
        client: Client,
        session: Session,
    ) -> None:
        super().__init__(dcr_id=dcr_id, client=client, session=session)
        self.manifest_hash = manifest_hash
        self.encryption_key_hex = encryption_key_hex

    def node_id(self) -> str:
        return "audiences.json"

    def run(self) -> None:
        """
        Publish the `audiences.json` dataset.
        """
        request_type = "publishAudiencesJson"
        request = AbMediaRequest.model_validate(
            {
                request_type: {
                    "dataRoomIdHex": self.dcr_id,
                    "datasetHashHex": self.manifest_hash,
                    "encryptionKeyHex": self.encryption_key_hex,
                    "scopeIdHex": self.client._ensure_dcr_data_scope(self.dcr_id),
                },
            }
        )
        response = self.send_request(request).model_dump()


class RetrievePublishedDatasetsComputation(Computation):
    def __init__(
        self,
        dcr_id: str,
        client: Client,
        session: Session,
    ) -> None:
        super().__init__(dcr_id=dcr_id, client=client, session=session)

    def node_id(self) -> str:
        pass

    def run_and_get_results(self) -> Dict[str, Any]:
        """
        Retrieve all datasets published to the DCR.
        """
        request_type = "retrievePublishedDatasets"
        request = AbMediaRequest.model_validate(
            {
                request_type: {
                    "dataRoomIdHex": self.dcr_id,
                },
            }
        )
        response = self.send_request(request).model_dump()
        return response["retrievePublishedDatasets"]


class GetLookalikeAudienceStatisticsComputation(Computation):
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
        return "get_lookalike_audience_statistics_id"

    def run(self) -> None:
        """
        Run the computation.
        """
        super().run(
            request_type="getLookalikeAudienceStatistics",
            generate_audience=self.generate_audience,
        )

    def get_results(
        self, interval: int = 5, timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        results = super().get_results_str_from_zip(
            "lookalike_audience.json", interval=interval, timeout=timeout
        )
        results_json = json.loads(results)

        # Only include the necessary information to the user.
        quality_metrics = {"quality": results_json["quality"]}
        all_roc_curve_keys = quality_metrics["quality"]["roc_curve"].keys()
        keep_roc_curve_keys = ["auc", "fpr", "tpr"]
        drop_keys = list(set(all_roc_curve_keys) - set(keep_roc_curve_keys))
        [quality_metrics["quality"]["roc_curve"].pop(m, None) for m in drop_keys]
        return quality_metrics


class GetDataAttributesComputation(Computation):
    def __init__(self, dcr_id: str, client: Client, session: Session) -> None:
        super().__init__(dcr_id=dcr_id, client=client, session=session)

    def node_id(self) -> str:
        return "get_data_attributes"

    def run(self) -> None:
        """
        Run the computation.
        """
        super().run(request_type="getDataAttributes")

    def get_results(
        self, interval: int = 5, timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        results = super().get_results_str_from_zip(
            "attributes.json", interval=interval, timeout=timeout
        )
        return json.loads(results)
