import base64
import json
import uuid
from typing import List, Optional, Tuple

from decentriq_dcr_compiler import compiler

from ..client import Client
from ..helpers import (
    create_session_from_driver_spec,
    get_latest_enclave_specs_as_dictionary,
)
from ..keychain import Keychain
from ..proto import serialize_length_delimited
from ..types import MATCHING_ID_INTERNAL_LOOKUP, MatchingId
from .lookalike_media import ExistingLookalikeMediaDcr, LookalikeMediaDcr


def _generate_id():
    return str(uuid.uuid4())


class LookalikeMediaDcrBuilder:
    """
    A helper class to build a Lookalike Media DCR
    """

    def __init__(
        self,
        client: Client,
    ) -> None:
        self.client = client
        self.name = None
        self.main_publisher_email = None
        self.publisher_emails = []
        self.main_advertiser_email = None
        self.advertiser_emails = []
        self.matching_id = None
        self.audit_log_retrieval = True
        self.dev_computations = True
        self.agency_emails = []
        self.observer_emails = []
        self.existing = False

    def with_name(self, name: str):
        """
        Set the name of the Lookalike Media DCR.
        This is required when creating **new** Lookalike Media DCRs only.
        When creating from an existing DCR, the existing name will be used.

        **Parameters**:
        - `name`: Name to be used for the Lookalike Media DCR.
        """
        self.name = name

    def with_publisher_emails(self, main: str, additional: Optional[List[str]] = None):
        """
        Set the publisher email addresses.

        **Parameters**:
        - `main`: The main publisher email address.
        - `additional`: Optional list of additional publisher email addresses.
        """
        self.main_publisher_email = main
        if additional is not None:
            self.publisher_emails = additional

    def with_advertiser_emails(self, main: str, additional: Optional[List[str]] = None):
        """
        Set the advertiser email addresses.

        **Parameters**:
        - `main`: The main advertiser email address.
        - `additional`: Optional list of additional advertiser email addresses.
        """
        self.main_advertiser_email = main
        if additional is not None:
            self.advertiser_emails = additional

    def with_agency_emails(self, emails: List[str]):
        """
        Set the agency email addresses.

        **Parameters**:
        - `emails`: List of agency email addresses.
        """
        self.agency_emails = emails

    def with_observer_emails(self, emails: List[str]):
        """
        Set the observer email addresses.

        **Parameters**:
        - `emails`: List of observer email addresses.
        """
        self.observer_emails = emails

    def with_matching_id_format(self, matching_id: MatchingId):
        """
        Set the matching ID format.
        This is required when creating **new** Lookalike Media DCRs only.
        When creating from an existing DCR, the existing matching ID will be used.

        **Parameters**:
        - `matching_id`: The type of matching ID to use.
        """
        self.matching_id = matching_id

    def from_existing(self, lmdcr_id: str, keychain: Keychain):
        """
        Construct a new Lookalike Media DCR from an existing Lookalike Media DCR with the given ID.

        **Parameters**:
        - `lmdcr_id`: The ID of the existing Lookalike Media DCR.
        - `keychain`: The keychain to use to provision datasets from the old Lookalike Media DCR to the new Lookalike Media DCR.
        """
        self.existing = True
        self.lmdcr_id = lmdcr_id
        self.keychain = keychain

    def build_and_publish(self) -> LookalikeMediaDcr:
        """
        Build and publish the Lookalike Media DCR.
        """
        self._check_required_fields_provided()

        if self.existing:
            # Get existing LMDCR (high level from the enclave).
            driver_attestation_hash = self.client._get_lmdcr_driver_attestation_hash(
                self.lmdcr_id
            )
            driver_enclave_spec = self.client._get_enclave_spec_from_hash(
                driver_attestation_hash
            )
            if driver_enclave_spec == None:
                raise Exception(
                    f"Failed to find driver for data room {driver_enclave_spec}"
                )
            session = create_session_from_driver_spec(self.client, driver_enclave_spec)
            existing_lmdcr = session.retrieve_data_room(self.lmdcr_id)
            high_level_representation = json.loads(
                existing_lmdcr.highLevelRepresentation.decode()
            )
            existing = ExistingLookalikeMediaDcr(self.lmdcr_id, driver_enclave_spec)
            return LookalikeMediaDcr(self.client, high_level_representation, existing)
        else:
            id = f"Lookalike DCR {_generate_id()}"
            root_cert_pem = self.client.decentriq_ca_root_certificate.decode()
            (driver_spec, python_spec) = self._get_lmdcr_enclave_specs(self.client)
            (
                matching_id_format,
                matching_id_hashing_algorithm,
            ) = MATCHING_ID_INTERNAL_LOOKUP[self.matching_id]
            # The publisher and advertiser email lists need to contain all emails including the main one.
            publisher_emails = [self.main_publisher_email] + self.publisher_emails
            advertiser_emails = [self.main_advertiser_email] + self.advertiser_emails
            lmdcr = {
                "v3": {
                    "v3": {
                        "id": id,
                        "name": self.name,
                        "mainPublisherEmail": self.main_publisher_email,
                        "mainAdvertiserEmail": self.main_advertiser_email,
                        "matchingIdFormat": matching_id_format.value,
                        "hashMatchingIdWith": (
                            None
                            if matching_id_hashing_algorithm is None
                            else matching_id_hashing_algorithm.value
                        ),
                        "authenticationRootCertificatePem": root_cert_pem,
                        "driverEnclaveSpecification": {
                            "attestationProtoBase64": driver_spec.attestationProtoBase64,
                            "id": driver_spec.id,
                            "workerProtocol": driver_spec.workerProtocol,
                        },
                        "pythonEnclaveSpecification": {
                            "attestationProtoBase64": python_spec.attestationProtoBase64,
                            "id": python_spec.id,
                            "workerProtocol": python_spec.workerProtocol,
                        },
                        "enableAuditLogRetrieval": self.audit_log_retrieval,
                        "enableDevComputations": self.dev_computations,
                        "enableDebugMode": False,
                        "advertiserEmails": advertiser_emails,
                        "agencyEmails": self.agency_emails,
                        "observerEmails": self.observer_emails,
                        "publisherEmails": publisher_emails,
                    }
                }
            }
            return LookalikeMediaDcr(self.client, lmdcr)

    # Check all necessary options have been provided.
    def _check_required_fields_provided(self):
        # Only perform check when creating new LMDCRs.
        # If creating from existing, these options will be copied across from the existing LMDCR.
        if not self.from_existing:
            if self.name is None:
                raise Exception("A name must be provided")
            elif self.matching_id is None:
                raise Exception("A matching ID must be provided")
            elif self.main_publisher_email is None:
                raise Exception("A publisher email address must be provided")

    @staticmethod
    def _get_lmdcr_enclave_specs(
        client: Client,
    ) -> Tuple[compiler.EnclaveSpecification, compiler.EnclaveSpecification]:
        enclave_specs = get_latest_enclave_specs_as_dictionary(client)
        driver_spec = None
        python_spec = None
        for spec_id, spec in enclave_specs.items():
            spec_payload = {
                "attestationProtoBase64": base64.b64encode(
                    serialize_length_delimited(spec["proto"])
                ).decode(),
                "id": spec_id,
                "workerProtocol": spec["workerProtocols"][0],
            }
            if "decentriq.driver" in spec_id:
                driver_spec = compiler.EnclaveSpecification.parse_obj(spec_payload)
            elif "decentriq.python-ml-worker" in spec_id:
                python_spec = compiler.EnclaveSpecification.parse_obj(spec_payload)
        if driver_spec is None:
            raise Exception("No driver enclave spec found for the datalab")
        if python_spec is None:
            raise Exception("No python-ml-worker enclave spec found for the datalab")
        return (driver_spec, python_spec)
