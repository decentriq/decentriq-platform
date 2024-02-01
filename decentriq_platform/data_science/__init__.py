import io

from typing import Optional

from ..session import Session
from ..storage import Key
from ..keychain import Keychain, KeychainEntry


__docformat__ = "restructuredtext"


__all__ = [
    "provision_tabular_dataset",
    "provision_raw_dataset",
]


def provision_tabular_dataset(
        data: io.BytesIO,
        *,
        name: str,
        session: Session,
        key: Key,
        data_node: str,
        data_room_id: str,
        store_in_keychain: Optional[Keychain] = None,
        description: str = "",
) -> str:
    """
    Convenience function for uploading data to a tabular data node in a Data Science Data Room.

    **Parameters**:
    - `data`: The input data to be uploaded. Use one of the reader functions provided in this
        package to read CSV-like data.
    - `name`: A descriptive name to assign to the dataset. This will help with finding the dataset
        when re-provisioning it to another Data Clean Room.
    - `session`: The session with which to communicate with the enclave.
    - `key`: A key for encrypting the data to-be-uploaded.
    - `data_node`: The name of the data node as seen in the Decentriq UI.
    - `data_room_id`: To which data room the dataset should be published. This is the id you
        get when publishing a data room.
    - `store_in_keychain`: An optional keychain in which to store the dataset key.
    - `description`: An optional description of the dataset.

    **Returns**:
    The manifest hash (dataset id) in case the upload succeeded.
    """
    manifest_hash = session.client.upload_dataset(
        data,
        key,
        name,
        description=description,
        store_in_keychain=store_in_keychain
    )
    session.publish_dataset(
        data_room_id, manifest_hash,
        leaf_id=f"{data_node}_leaf",
        key=key
    )
    return manifest_hash


def provision_raw_dataset(
        data: io.BytesIO,
        *,
        name: str,
        session: Session,
        key: Key,
        data_node: str,
        data_room_id: str,
        store_in_keychain: Optional[Keychain] = None,
        description: str = "",
) -> str:
    """
    Convenience function for uploading data to a raw leaf node in a Data Science Data Room.

    **Parameters**:
    - `data`: The input data to be uploaded. Use one of the reader functions provided in this
        package to read CSV-like data.
    - `name`: A descriptive name to assign to the dataset. This will help with finding the dataset
        when re-provisioning it to another Data Clean Room.
    - `session`: The session with which to communicate with the enclave.
    - `key`: A key for encrypting the data to-be-uploaded.
    - `data_node`: The name of the data node as seen in the Decentriq UI.
    - `data_room_id`: To which data room the dataset should be published. This is the id you
        get when publishing a data room.
    - `store_in_keychain`: An optional keychain in which to store the dataset key.
    - `description`: An optional description of the dataset.

    **Returns**:
    The manifest hash (dataset id) in case the upload succeeded.
    """
    manifest_hash = session.client.upload_dataset(
        data,
        key,
        name,
        description=description,
        store_in_keychain=store_in_keychain
    )
    session.publish_dataset(
        data_room_id, manifest_hash,
        leaf_id=data_node,
        key=key
    )
    return manifest_hash
