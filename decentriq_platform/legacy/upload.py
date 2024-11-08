import io
from typing import Optional

from .session import Session
from .storage import Key
from ..client import SecretStoreOptions

def provision_tabular_dataset_to_data_science_data_room(
    data: io.BytesIO,
    *,
    session: Session,
    key: Key,
    data_node: str,
    data_room_id: str,
    description: str = "",
    secret_store_options: Optional[SecretStoreOptions] = None,
) -> str:
    """
    Convenience function for uploading data to a tabular data node in a Data Science Data Room.

    **Parameters**:
    - `data`: The input data to be uploaded. Use one of the reader functions provided in this
        package to read CSV-like data.
    - `session`: The session with which to communicate with the enclave.
    - `key`: A key for encrypting the data to-be-uploaded.
    - `data_room_id`: To which data room the dataset should be published. This is the id you
        get when publishing a data room.
    - `description`: An optional description of the dataset.

    **Returns**:
    The manifest hash (dataset id) in case the upload succeeded.
    """
    manifest_hash = session.client.upload_dataset(
        data,
        key,
        data_node,
        description=description,
        secret_store_options=secret_store_options,
    )
    session.publish_dataset(
        data_room_id, manifest_hash, leaf_id=f"{data_node}_leaf", key=key
    )
    return manifest_hash


def provision_raw_dataset_to_data_science_data_room(
    data: io.BytesIO,
    *,
    session: Session,
    key: Key,
    data_node: str,
    data_room_id: str,
    description: str = "",
    secret_store_options: Optional[SecretStoreOptions] = None,
) -> str:
    """
    Convenience function for uploading data to a raw leaf node in a Data Science Data Room.

    **Parameters**:
    - `data`: The input data to be uploaded. Use one of the reader functions provided in this
        package to read CSV-like data.
    - `session`: The session with which to communicate with the enclave.
    - `key`: A key for encrypting the data to-be-uploaded.
    - `data_room_id`: To which data room the dataset should be published. This is the id you
        get when publishing a data room.
    - `description`: An optional description of the dataset.

    **Returns**:
    The manifest hash (dataset id) in case the upload succeeded.
    """
    manifest_hash = session.client.upload_dataset(
        data,
        key,
        data_node,
        description=description,
        secret_store_options=secret_store_options,
    )
    session.publish_dataset(
        data_room_id, manifest_hash, leaf_id=f"{data_node}_leaf", key=key
    )
    return manifest_hash


def provision_matching_dataset_to_lookalike_media_data_room(
    data: io.BytesIO,
    *,
    session: Session,
    key: Key,
    data_node: str,
    data_room_id: str,
    description: str = "",
    secret_store_options: Optional[SecretStoreOptions] = None,
) -> str:
    """
    Convenience function for uploading matching data to a Lookalike Media Data Room.

    **Parameters**:
    - `data`: The input data to be uploaded. Use one of the reader functions provided in this
        package to read CSV-like data.
    - `session`: The session with which to communicate with the enclave.
    - `key`: A key for encrypting the data to-be-uploaded.
    - `data_room_id`: To which data room the dataset should be published. This is the id you
        get when publishing a data room.
    - `description`: An optional description of the dataset.

    **Returns**:
    The manifest hash (dataset id) in case the upload succeeded.
    """
    manifest_hash = session.client.upload_dataset(
        data,
        key,
        data_node,
        description=description,
        secret_store_options=secret_store_options,
    )
    session.publish_dataset(data_room_id, manifest_hash, leaf_id="matching", key=key)
    return manifest_hash
