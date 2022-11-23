from .proto import AttestationSpecification, DataRoomConfiguration
from google.protobuf.json_format import MessageToDict
from .types import EnclaveSpecification
from typing import Dict, List


def decode_compute_node_config(
        config : bytes,
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
        enclave_specs: List[EnclaveSpecification]
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
                config_decoded = decode_compute_node_config(config, attestation_spec, enclave_specs)
                if config_decoded:
                    decoded_configuration[element.id] = config_decoded

    return decoded_configuration


def decode_data_room_configuration(
        data_room_configuration: DataRoomConfiguration,
        enclave_specifications: List[EnclaveSpecification],
):
    decoded_configs = decode_compute_node_configs(data_room_configuration, enclave_specifications)
    decoded_configuration = {}

    for element in data_room_configuration.elements:
        element_json = MessageToDict(element)
        is_branch = "computeNode" in element_json and "branch" in element_json["computeNode"]
        if is_branch and element.id in decoded_configs:
            decoded_config = decoded_configs[element.id]
            if decoded_config:
                element_json["computeNode"]["branch"]["config"] =  decoded_config
        decoded_configuration[element.id] = element_json

    return decoded_configuration
