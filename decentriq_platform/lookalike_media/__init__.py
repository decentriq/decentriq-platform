import io

from typing import Optional

from ..session import Session
from ..storage import Key
from ..keychain import Keychain


__docformat__ = "restructuredtext"


__all__ = [
    "provision_matching_dataset",
    "provision_audiences_dataset",
    "provision_segments_dataset",
    "provision_embeddings_dataset",
    "provision_demographics_dataset",
]


def _provision_dataset(
        data: io.BytesIO,
        *,
        name: str,
        session: Session,
        key: Key,
        data_room_id: str,
        data_node: str,
        store_in_keychain: Optional[Keychain] = None,
        description: str = "",
) -> str:
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



def provision_matching_dataset(
        data: io.BytesIO,
        *,
        name: str,
        session: Session,
        key: Key,
        data_room_id: str,
        store_in_keychain: Optional[Keychain] = None,
        description: str = "",
) -> str:
    """
    Convenience function for uploading matching data to a Lookalike Media Data Room.

    The data must be a CSV with two columns `user_id` and `matching_id`.
    The file should _not_ contain a header row.

    **Parameters**:
    - `data`: The input data to be uploaded. Use one of the reader functions provided in this
        package to read CSV-like data.
    - `name`: A descriptive name to assign to the dataset. This will help with finding the dataset
        when re-provisioning it to another Data Clean Room.
    - `session`: The session with which to communicate with the enclave.
    - `key`: A key for encrypting the data to-be-uploaded.
    - `data_room_id`: To which data room the dataset should be published. This is the id you
        get when publishing a data room.
    - `store_in_keychain`: An optional keychain in which to store the dataset key.
    - `description`: An optional description of the dataset.

    **Returns**:
    The manifest hash (dataset id) in case the upload succeeded.
    """
    return _provision_dataset(
        data,
        name=name,
        session=session,
        key=key,
        data_room_id=data_room_id,
        store_in_keychain=store_in_keychain,
        description=description,
        data_node="matching",
    )


def provision_embeddings_dataset(
        data: io.BytesIO,
        *,
        name: str,
        session: Session,
        key: Key,
        data_room_id: str,
        store_in_keychain: Optional[Keychain] = None,
        description: str = "",
) -> str:
    """
    Convenience function for uploading embeddings data to a Lookalike Media Data Room.

    The data must be a CSV with the first column being `user_id`. Each additional column is
    interpreted as an "embeddings" column of type float.
    The file should _not_ contain a header row.

    **Parameters**:
    - `data`: The input data to be uploaded. Use one of the reader functions provided in this
        package to read CSV-like data.
    - `name`: A descriptive name to assign to the dataset. This will help with finding the dataset
        when re-provisioning it to another Data Clean Room.
    - `session`: The session with which to communicate with the enclave.
    - `key`: A key for encrypting the data to-be-uploaded.
    - `data_room_id`: To which data room the dataset should be published. This is the id you
        get when publishing a data room.
    - `store_in_keychain`: An optional keychain in which to store the dataset key.
    - `description`: An optional description of the dataset.

    **Returns**:
    The manifest hash (dataset id) in case the upload succeeded.
    """
    return _provision_dataset(
        data,
        name=name,
        session=session,
        key=key,
        data_room_id=data_room_id,
        store_in_keychain=store_in_keychain,
        description=description,
        data_node="embeddings",
    )


def provision_audiences_dataset(
        data: io.BytesIO,
        *,
        name: str,
        session: Session,
        key: Key,
        data_room_id: str,
        store_in_keychain: Optional[Keychain] = None,
        description: str = "",
) -> str:
    """
    Convenience function for uploading audience data to a Lookalike Media Data Room.

    The data must be a CSV with two columns: `matching_id` and `audience_type`.
    The file should _not_ contain a header row.

    **Parameters**:
    - `data`: The input data to be uploaded. Use one of the reader functions provided in this
        package to read CSV-like data.
    - `name`: A descriptive name to assign to the dataset. This will help with finding the dataset
        when re-provisioning it to another Data Clean Room.
    - `session`: The session with which to communicate with the enclave.
    - `key`: A key for encrypting the data to-be-uploaded.
    - `data_room_id`: To which data room the dataset should be published. This is the id you
        get when publishing a data room.
    - `store_in_keychain`: An optional keychain in which to store the dataset key.
    - `description`: An optional description of the dataset.

    **Returns**:
    The manifest hash (dataset id) in case the upload succeeded.
    """
    return _provision_dataset(
        data,
        name=name,
        session=session,
        key=key,
        data_room_id=data_room_id,
        store_in_keychain=store_in_keychain,
        description=description,
        data_node="audiences",
    )


def provision_segments_dataset(
        data: io.BytesIO,
        *,
        name: str,
        session: Session,
        key: Key,
        data_room_id: str,
        store_in_keychain: Optional[Keychain] = None,
        description: str = "",
) -> str:
    """
    Convenience function for uploading segments data to a Lookalike Media Data Room.

    The data must be a CSV with two columns: `user_id` and `segment`.
    A user can appear multiple times in the same file.
    The file should _not_ contain a header row.

    **Parameters**:
    - `data`: The input data to be uploaded. Use one of the reader functions provided in this
        package to read CSV-like data.
    - `name`: A descriptive name to assign to the dataset. This will help with finding the dataset
        when re-provisioning it to another Data Clean Room.
    - `session`: The session with which to communicate with the enclave.
    - `key`: A key for encrypting the data to-be-uploaded.
    - `data_room_id`: To which data room the dataset should be published. This is the id you
        get when publishing a data room.
    - `store_in_keychain`: An optional keychain in which to store the dataset key.
    - `description`: An optional description of the dataset.

    **Returns**:
    The manifest hash (dataset id) in case the upload succeeded.
    """
    return _provision_dataset(
        data,
        name=name,
        session=session,
        key=key,
        data_room_id=data_room_id,
        store_in_keychain=store_in_keychain,
        description=description,
        data_node="segments",
    )


def provision_demographics_dataset(
        data: io.BytesIO,
        name: str,
        *,
        session: Session,
        key: Key,
        data_room_id: str,
        store_in_keychain: Optional[Keychain] = None,
        description: str = "",
) -> str:
    """
    Convenience function for uploading demographics data to a Lookalike Media Data Room.

    The data must be a CSV with three columns: `user_id`, `age`, and `gender`.
    The columns `age` and `gender` can be any string.
    The file should _not_ contain a header row.

    **Parameters**:
    - `data`: The input data to be uploaded. Use one of the reader functions provided in this
        package to read CSV-like data.
    - `name`: A descriptive name to assign to the dataset. This will help with finding the dataset
        when re-provisioning it to another Data Clean Room.
    - `session`: The session with which to communicate with the enclave.
    - `key`: A key for encrypting the data to-be-uploaded.
    - `data_room_id`: To which data room the dataset should be published. This is the id you
        get when publishing a data room.
    - `store_in_keychain`: An optional keychain in which to store the dataset key.
    - `description`: An optional description of the dataset.

    **Returns**:
    The manifest hash (dataset id) in case the upload succeeded.
    """
    return _provision_dataset(
        data,
        name=name,
        session=session,
        key=key,
        data_room_id=data_room_id,
        store_in_keychain=store_in_keychain,
        description=description,
        data_node="demographics",
    )
