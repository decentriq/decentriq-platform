from __future__ import annotations

import io
import zipfile
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, BinaryIO, Optional

from ..keychain import Keychain
from ..session import Session
from ..storage import Key
from .sql_helper import read_sql_query_result_as_string

if TYPE_CHECKING:
    from ..client import Client
    from .node_definitions import NodeDefinition


class HighLevelNode(ABC):
    """
    Abstract class representing a High Level Node.
    """

    def __init__(
        self,
        name: str,
        id: str,
        dcr_id: str,
        client: Client,
        session: Session,
        definition: NodeDefinition,
    ) -> None:
        super().__init__()
        self.id = id
        self.name = name
        self.dcr_id = dcr_id
        self.client = client
        self.session = session
        self.definition = definition


class ComputationNode(HighLevelNode, ABC):
    """
    Class representing a Computation Node.

    Computation Nodes allow a permitted analyst to run a computation and
    retrieve the results of a computation.
    """

    def __init__(
        self,
        id: str,
        name: str,
        dcr_id: str,
        session: Session,
        definition: NodeDefinition,
        *,
        client: Client,
    ) -> None:
        """
        Initialise an instance of a `ComputationNode`.

        **Parameters**:
        - `name`: Name of the `ComputationNode`.
        - `dcr_id`: ID of the DCR the node is a member of.
        - `session`: The session with which to communicate with the enclave.
        - 'definition': Definition with which the node was built.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        - 'id': Node ID.
        """
        super().__init__(
            name=name,
            client=client,
            session=session,
            dcr_id=dcr_id,
            id=id,
            definition=definition,
        )
        self.job_id = None

    def run_computation(self):
        """
        Run the computation associated with this node.
        """
        if not self.session:
            raise Exception(
                f"Unable to run computation. Node {self.id} does not have an associated session"
            )
        self.job_id = self.session.run_computation(
            self.dcr_id, self._get_computation_id()
        )

    def get_results_as_bytes(
        self,
        interval: int = 5,
        timeout: Optional[int] = None,
    ) -> Optional[bytes]:
        """
        Retrieve the results of a computation.

        **Parameters**:
        - `interval`: Time interval (in seconds) to check for results.
        - `timeout`: Time (in seconds) after which results are no longer checked.
        """
        if not self.job_id:
            raise Exception("A computation must be run before results can be retrieved")
        return self.session.get_computation_result(
            self.job_id, interval=interval, timeout=timeout
        )

    def run_computation_and_get_results_as_bytes(
        self,
        interval: int = 5,
        timeout: Optional[int] = None,
    ):
        """
        This is a blocking call to run a computation and get the results.

        **Parameters**:
        - `interval`: Time interval (in seconds) to check for results.
        - `timeout`: Time (in seconds) after which results are no longer checked.
        """
        if not self.session:
            raise Exception(
                f"Unable to run computation. Node {self.id} does not have an associated session"
            )
        return self.session.run_computation_and_get_results(
            self.dcr_id,
            self._get_computation_id(),
            interval=interval,
            timeout=timeout,
        )

    @abstractmethod
    def _get_computation_id(self) -> str:
        """
        Retrieve the ID of the node corresponding to the computation.
        """
        pass


class ContainerComputationNode(ComputationNode):
    def __init__(
        self,
        *args,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)

    def get_results_as_zip(
        self,
        interval: int = 5,
        timeout: Optional[int] = None,
    ) -> Optional[zipfile.ZipFile]:
        """
        Retrieve the results of a computation as a ZIP file.

        **Parameters**:
        - `interval`: Time interval (in seconds) to check for results.
        - `timeout`: Time (in seconds) after which results are no longer checked.
        """
        raw_result = self.get_results_as_bytes(interval=interval, timeout=timeout)
        if raw_result:
            return zipfile.ZipFile(io.BytesIO(raw_result), "r")
        else:
            return None

    def run_computation_and_get_results_as_zip(
        self,
        interval: int = 5,
        timeout: Optional[int] = None,
    ):
        """
        This is a blocking call to run a computation and get the results as a ZIP file.

        **Parameters**:
        - `interval`: Time interval (in seconds) to check for results.
        - `timeout`: Time (in seconds) after which results are no longer checked.
        """
        raw_result = self.run_computation_and_get_results_as_bytes(
            interval=interval, timeout=timeout
        )
        if raw_result:
            return zipfile.ZipFile(io.BytesIO(raw_result), "r")
        else:
            return None


class StructuredOutputNode(ComputationNode):
    def __init__(
        self,
        *args,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)

    def get_results_as_string(
        self,
        interval: int = 5,
        timeout: Optional[int] = None,
    ) -> Optional[str]:
        """
        Retrieve the results of a computation as a string.

        **Parameters**:
        - `interval`: Time interval (in seconds) to check for results.
        - `timeout`: Time (in seconds) after which results are no longer checked.
        """
        raw_result = self.get_results_as_bytes(interval=interval, timeout=timeout)
        if raw_result:
            return read_sql_query_result_as_string(raw_result)
        else:
            return None

    def run_computation_and_get_results_as_string(
        self,
        interval: int = 5,
        timeout: Optional[int] = None,
    ) -> Optional[str]:
        """
        This is a blocking call to run a computation and get the results as a
        string.

        **Parameters**:
        - `interval`: Time interval (in seconds) to check for results.
        - `timeout`: Time (in seconds) after which results are no longer checked.
        """
        raw_result = self.run_computation_and_get_results_as_bytes(
            interval=interval, timeout=timeout
        )
        if raw_result:
            return read_sql_query_result_as_string(raw_result)
        else:
            return None


class DataNode(HighLevelNode, ABC):
    """
    Class representing a Data node.

    Data nodes allow a permitted data owner to upload and publish dataset to the node.
    """

    def __init__(
        self,
        name: str,
        id: str,
        dcr_id: str,
        is_required: bool,
        session: Session,
        definition: NodeDefinition,
        *,
        client: Client,
    ) -> None:
        """
        Initialise an instance of a `DataNode`.

        **Parameters**:
        - `name`: Name of the `DataNode`.
        - `dcr_id`: ID of the DCR the node is a member of.
        - `is_required`: Flag determining if the `DataNode` must be present for dependent computations.
        - `session`: The session with which to communicate with the enclave.
        - `id`: ID of the `DataNode`.
        - 'definition': Definition with which the node was built.
        - `client`: A `Client` object which can be used to perform operations such as uploading data
            and retrieving computation results.
        """
        super().__init__(
            name=name,
            dcr_id=dcr_id,
            client=client,
            session=session,
            id=id,
            definition=definition,
        )
        self.is_required = is_required

    def publish_dataset(self, manifest_hash: str, key: Key):
        """
        Publish data to the `DataNode`.

        **Parameters**:
        - `manifest_hash`: Hash identifying the dataset to be published.
        - `key`: Encryption key used to decrypt the dataset.
        """
        self.session.publish_dataset(
            self.dcr_id, manifest_hash, leaf_id=self.id, key=key
        )

    def upload_and_publish_dataset(
        self,
        data: BinaryIO,
        key: Key,
        name: str,
        store_in_keychain: Optional[Keychain] = None,
        description: str = "",
    ):
        """
        Upload data to the Decentriq Platform and publish it to the `DataNode`.

        **Parameters**:
        - `data`: Binary representation of the data to be uploaded.
        - `key`: Key to be used for encrypting the data.
        - `name`: Name of the file.
        - `store_in_keychain`: An optional keychain in which to store the dataset key.
        - `description`: An optional description of the dataset.
        """
        if not self.dcr_id:
            raise Exception("Data node is not part of a data room")

        manifest_hash = self.client.upload_dataset(
            data,
            key,
            name,
            store_in_keychain=store_in_keychain,
            description=description,
        )
        self.publish_dataset(manifest_hash, key)

    def remove_published_dataset(self) -> None:
        """
        Removes any dataset that is published to this node.
        """
        self.session.remove_published_dataset(self.dcr_id, self.id)
