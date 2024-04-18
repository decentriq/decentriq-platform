from typing import Dict, List

from google.protobuf.json_format import MessageToDict

from .client import Client
from .proto import AttestationSpecification, DataRoomConfiguration
from .session import LATEST_GCG_PROTOCOL_VERSION, Session
from .types import EnclaveSpecification


def decode_compute_node_config(
    config: bytes,
    attestation_spec: AttestationSpecification,
    enclave_specs: List[EnclaveSpecification],
):
    for enclave_spec in enclave_specs:
        if enclave_spec["proto"] == attestation_spec:
            decoder = enclave_spec["decoder"]
            if decoder:
                config_decoded = decoder.decode(config)
                return config_decoded
    return None


def decode_compute_node_configs(
    data_room_configuration: DataRoomConfiguration,
    enclave_specs: List[EnclaveSpecification],
) -> Dict[str, Dict]:
    current_configuration = {}
    for element in data_room_configuration.elements:
        current_configuration[element.id] = element
    decoded_configuration = {}

    for element in data_room_configuration.elements:
        if element.HasField("computeNode"):
            if element.computeNode.HasField("branch"):
                config = element.computeNode.branch.config
                index = element.computeNode.branch.attestationSpecificationId
                attestation_spec = current_configuration[index].attestationSpecification
                config_decoded = decode_compute_node_config(
                    config, attestation_spec, enclave_specs
                )
                if config_decoded:
                    decoded_configuration[element.id] = config_decoded

    return decoded_configuration


def decode_data_room_configuration(
    data_room_configuration: DataRoomConfiguration,
    enclave_specifications: List[EnclaveSpecification],
):
    decoded_configs = decode_compute_node_configs(
        data_room_configuration, enclave_specifications
    )
    decoded_configuration = {}

    for element in data_room_configuration.elements:
        element_json = MessageToDict(element)
        is_branch = (
            "computeNode" in element_json and "branch" in element_json["computeNode"]
        )
        if is_branch and element.id in decoded_configs:
            decoded_config = decoded_configs[element.id]
            if decoded_config:
                element_json["computeNode"]["branch"]["config"] = decoded_config
        decoded_configuration[element.id] = element_json

    return decoded_configuration


def get_latest_enclave_specs_as_dictionary(
    client: Client,
) -> Dict[str, EnclaveSpecification]:
    enclave_specs = client._get_enclave_specifications()
    latest_driver_version = 0
    latest_python_worker_version = 0
    latest_enclaves = {}
    for spec in enclave_specs:
        if spec["name"] == "decentriq.driver":
            version = int(spec["version"])
            if version >= latest_driver_version:
                latest_driver_version = version
                latest_enclaves["decentriq.driver"] = spec
        if spec["name"] == "decentriq.python-ml-worker-32-64":
            version = int(spec["version"])
            if version >= latest_python_worker_version:
                latest_python_worker_version = version
                latest_enclaves["decentriq.python-ml-worker-32-64"] = spec
    latest_enclaves["decentriq.driver"]["clientProtocols"] = [
        LATEST_GCG_PROTOCOL_VERSION
    ]
    return latest_enclaves


def create_session_from_driver_spec(
    client: Client, driver_spec: EnclaveSpecification
) -> Session:
    driver_spec["clientProtocols"] = [LATEST_GCG_PROTOCOL_VERSION]
    enclave_specs = {driver_spec["name"]: driver_spec}
    auth, _ = client.create_auth_using_decentriq_pki(enclave_specs)
    session = client.create_session(auth, enclave_specs)
    return session
