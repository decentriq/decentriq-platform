from __future__ import annotations
import base64
import json

from typing_extensions import Self
from typing import Dict, List, Optional, TYPE_CHECKING, Tuple
from decentriq_dcr_compiler import compiler, ab_media as ab_media_compiler
from decentriq_dcr_compiler.schemas import CreateAbMediaDcr
from ..attestation import enclave_specifications
from ..types import MATCHING_ID_INTERNAL_LOOKUP, MatchingId, EnclaveSpecification
from ..proto import serialize_length_delimited
from .ab_media import AbMediaDcrDefinition
from .version import AUDIENCE_BUILDER_SUPPORTED_VERSION
from .helper import generate_id

if TYPE_CHECKING:
    from ..client import Client


class AbMediaDcrBuilder:
    """
    A helper class to build an Audience Builder Media DCR.

    Required arguments for building a DCR are passed via the constructor of this
    class. Optional arguments, instead, can be passed through the various
    builder methods.
    """

    def __init__(
        self,
        *,
        client: Client,
        name: str,
        publisher_emails: list[str],
        advertiser_emails: list[str],
        matching_id_format: MatchingId,
        enclave_specs: Optional[dict[str, EnclaveSpecification]] = None,
    ) -> None:
        """
        Initialise an Audience Builder Media DCR builder.

        **Parameters**:
        - `client`: A `Client` object that can be used to retrieve information about the platform.
        - `name`: The name of the DCR.
        - `publisher_emails`: A list with all publisher participants.
        - `advertiser_emails`: A list with all advertiser participants.
        - `matching_id_format`: The format of the matching ids, i.e. the ids that are used
            to match users between the publisher's and advertiser's datasets.
        - `enclave_specs`: Determines the types of enclaves that will supported by this Data Clean Room.
            If not specified, the latest enclave specifications known to this
            SDK version will be used.
        """
        self.client = client
        self.enclave_specs = (
            enclave_specs if enclave_specs else enclave_specifications.latest()
        )
        self.name = name
        self.main_publisher_email = publisher_emails[0]
        self.additional_publisher_emails = publisher_emails[1:]
        self.main_advertiser_email = advertiser_emails[0]
        self.additional_advertiser_emails = advertiser_emails[1:]
        self.agency_emails = []
        self.observer_emails = []
        self.data_partner_emails = []
        self.enable_data_partner = False
        self.matching_id = matching_id_format
        self.enable_insights = False
        self.enable_lookalike = False
        self.enable_remarketing = False
        self.enable_rule_based = False
        self.hide_absolute_values_from_insights = False
        self.enable_advertiser_audience_download = False

    def with_agency_emails(self, emails: List[str]) -> Self:
        """
        Set the agency email addresses.

        **Parameters**:
        - `emails`: List of agency email addresses.
        """
        self.agency_emails = emails
        return self

    def with_observer_emails(self, emails: List[str]) -> Self:
        """
        Set the observer email addresses.

        **Parameters**:
        - `emails`: List of observer email addresses.
        """
        self.observer_emails = emails
        return self

    def with_data_partner_emails(self, emails: List[str]) -> Self:
        """
        Set the data partner email addresses.

        **Parameters**:
        - `emails`: List of data partner email addresses.
        """
        self.data_partner_emails = emails
        self.enable_data_partner = True
        return self

    def with_insights(self) -> Self:
        """
        Enable the "insights" feature set.
        """
        self.enable_insights = True
        return self

    def with_lookalike(self) -> Self:
        """
        Enable the "lookalike" feature set.
        """
        self.enable_lookalike = True
        return self

    def with_remarketing(self) -> Self:
        """
        Enable the "remarketing" feature set.
        """
        self.enable_remarketing = True
        return self

    def with_rule_based(self) -> Self:
        """
        Enable the "rule-based" feature set.
        """
        self.enable_rule_based = True
        return self

    def with_advertiser_audience_download(self) -> Self:
        """
        Allow the advertiser to download the user ids for an audience.
        """
        self.enable_advertiser_audience_download = True
        return self

    def with_hide_absolute_values_from_insights(self) -> Self:
        """
        Ensure absolute values are not included in the output of the insights computation.
        """
        self.hide_absolute_values_from_insights = True
        return self

    def build(self) -> AbMediaDcrDefinition:
        """
        Build the Data Clean Room.

        In order to use the DCR, the output of this method should be passed to
        `client.publish_media_dcr`.
        """
        self._check_advertiser_audience_download_allowed()

        id = f"Audience Builder DCR {generate_id()}"
        root_cert_pem = self.client.decentriq_ca_root_certificate.decode()
        (
            matching_id_format,
            matching_id_hashing_algorithm,
        ) = MATCHING_ID_INTERNAL_LOOKUP[self.matching_id]
        (driver_spec, python_spec) = self._get_ab_dcr_enclave_specs()

        # Dedupe the advertiser and publisher emails.
        # This ensures that the main email address only appears once even if it
        # exists in the addtional email addresses.
        advertiser_emails = list(
            set([self.main_advertiser_email] + self.additional_advertiser_emails)
        )
        publisher_emails = list(
            set([self.main_publisher_email] + self.additional_publisher_emails)
        )
        high_level = {
            AUDIENCE_BUILDER_SUPPORTED_VERSION: {
                "advertiserEmails": advertiser_emails,
                "agencyEmails": self.agency_emails,
                "authenticationRootCertificatePem": root_cert_pem,
                "dataPartnerEmails": self.data_partner_emails,
                "driverEnclaveSpecification": {
                    "attestationProtoBase64": driver_spec.attestationProtoBase64,
                    "id": driver_spec.id,
                    "workerProtocol": driver_spec.workerProtocol,
                },
                "enableAdvertiserAudienceDownload": self.enable_advertiser_audience_download,
                "enableDataPartner": self.enable_data_partner,
                "enableDebugMode": False,
                "enableHideAbsoluteValuesFromInsights": self.hide_absolute_values_from_insights,
                "enableInsights": self.enable_insights,
                "enableLookalikeAudiences": self.enable_lookalike,
                "enableRateLimitingOnPublishDataset": True,
                "enableRemarketing": self.enable_remarketing,
                "enableRuleBasedAudiences": self.enable_rule_based,
                "hashMatchingIdWith": (
                    None
                    if matching_id_hashing_algorithm is None
                    else matching_id_hashing_algorithm.value
                ),
                "id": id,
                "mainAdvertiserEmail": self.main_advertiser_email,
                "mainPublisherEmail": self.main_publisher_email,
                "matchingIdFormat": matching_id_format.value,
                "modelEvaluation": {
                    "postScopeMerge": ["ROC_CURVE"],
                    "preScopeMerge": [],
                },
                "name": self.name,
                "observerEmails": self.observer_emails,
                "publisherEmails": publisher_emails,
                "pythonEnclaveSpecification": {
                    "attestationProtoBase64": python_spec.attestationProtoBase64,
                    "id": python_spec.id,
                    "workerProtocol": python_spec.workerProtocol,
                },
            }
        }
        audience_builder_dcr = ab_media_compiler.create_ab_media_dcr(
            CreateAbMediaDcr.model_validate(high_level)
        )
        dcr_definition = AbMediaDcrDefinition(
            name=self.name,
            high_level=json.loads(audience_builder_dcr.model_dump_json(by_alias=True)),
            enclave_specs=self.enclave_specs,
        )
        return dcr_definition

    def _check_advertiser_audience_download_allowed(self):
        if not self.enable_advertiser_audience_download:
            return

        # Ensure the correct feature sets are enabled before allowing advertiser audience downloads.
        if self.enable_rule_based:
            raise Exception(
                "Advertiser audience downloads are not permitted when rule-based audiences are enabled"
            )
        elif not self.enable_lookalike and not self.enable_remarketing:
            raise Exception(
                "Advertiser audience downloads require the lookalike or remarketing feature to be enabled"
            )

    def _get_ab_dcr_enclave_specs(
        self,
    ) -> Tuple[compiler.EnclaveSpecification, compiler.EnclaveSpecification]:
        driver_spec = None
        python_spec = None
        for spec_id, spec in self.enclave_specs.items():
            spec_payload = {
                "attestationProtoBase64": base64.b64encode(
                    serialize_length_delimited(spec["proto"])
                ).decode(),
                "id": spec_id,
                "workerProtocol": spec["workerProtocols"][0],
            }
            if "decentriq.driver" in spec_id:
                driver_spec = compiler.EnclaveSpecification.model_validate(spec_payload)
            elif "decentriq.python-ml-worker" in spec_id:
                python_spec = compiler.EnclaveSpecification.model_validate(spec_payload)
        if driver_spec is None:
            raise Exception("No driver enclave spec found for the datalab")
        if python_spec is None:
            raise Exception("No python-ml-worker enclave spec found for the datalab")
        return (driver_spec, python_spec)
