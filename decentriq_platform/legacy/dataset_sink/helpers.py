import json
from typing import Dict

from ...session import Session
from ...storage import Key
from ...types import EnclaveSpecification
from ..builders import DataRoomCommitBuilder
from ..container import read_result_as_zipfile
from ..permission import Permissions
from . import DatasetSink
from .proto import FileSelection, SingleFile, SinkInput, ZipFile


def store_computation_result_as_dataset(
    session: Session,
    enclave_specs: Dict[str, EnclaveSpecification],
    key: Key,
    dataset_name: str,
    data_room_id: str,
    compute_node_id: str,
):
    current_config, history_pin = session.retrieve_current_data_room_configuration(
        data_room_id
    )
    builder = DataRoomCommitBuilder(
        "dataset_sink_node",
        data_room_id,
        current_configuration=current_config,
        history_pin=history_pin,
        enclave_specs=enclave_specs,
    )
    sink_node_id = f"{compute_node_id}_sink"
    key_node_id = f"{sink_node_id}_key"

    inputs = [
        SinkInput(
            name=dataset_name,
            dependency=compute_node_id,
            zip=ZipFile(files=FileSelection(names=[SingleFile(name="hello.txt")])),
        )
    ]

    sink = DatasetSink(
        name=sink_node_id,
        inputs=inputs,
        encryption_key_dependency=f"{compute_node_id}_sink_key",
        is_key_hex_encoded=True,
    )
    builder.add_compute_node(sink, node_id=sink_node_id)
    builder.add_parameter_node(key_node_id, is_required=True, node_id=key_node_id)

    builder.add_user_permission(
        email=session.auth.user_id,
        authentication_method=session.client.decentriq_pki_authentication,
        permissions=[
            Permissions.execute_compute(sink_node_id),
            Permissions.retrieve_compute_result(sink_node_id),
        ],
    )
    commit = builder.build()
    commit_id = session.publish_data_room_configuration_commit(commit)

    job_id = session.run_dev_computation(
        data_room_id,
        commit_id,
        sink_node_id,
        parameters={key_node_id: key.material.hex()},
    )
    results = session.get_computation_result(job_id)
    results_zip = read_result_as_zipfile(results)
    datasets_meta_str = results_zip.read("datasets.json").decode()
    datasets_meta = json.loads(datasets_meta_str)

    return datasets_meta["datasets"][0]["manifestHash"]
