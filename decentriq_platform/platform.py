from typing import List, Optional, Tuple
import datetime
import base64
import json
import uuid
from .authentication import generate_csr, generate_key, Auth
from .types import (
    DataRoomDescription,
    DatasetDescription,
    UserCsrResponse,
    UserCsrRequest,
)
from .api import API, Endpoints
from .proto import (
    AuthenticationMethod, TrustedPki, DataRoom, DataRoomStatus, ConfigurationModification
)
from .config import (
    DECENTRIQ_CLIENT_ID,
    DECENTRIQ_API_PLATFORM_HOST, DECENTRIQ_API_PLATFORM_PORT, DECENTRIQ_API_PLATFORM_USE_TLS
)

__all__ = [
    "ClientPlatformFeatures", "SessionPlatformFeatures"
]


def platform_hash_from_str(s: str) -> bytes:
    """
    The reverse operation of `platform_hash_to_str`.
    """
    list_u8 = [int(x) for x in base64.b64decode(s).decode('ascii').split(',')]
    return bytes(list_u8)


def platform_hash_to_str(bs: bytes) -> str:
    """
    Transform a bytestring received from the
    The platform stores hashes (both files and data rooms) in the following form:
    Given a series of bytes with values 1 2 3, it will store the ascii codes of the
    string '1,2,3' (including the commas), so we get the byte array 49 44 50 44 51.
    This is then base64 encoded and sent to the backend where it is base64 decoded.
    """
    return base64.b64encode(','.join([str(b) for b in bs]).encode('ascii')).decode('ascii')


_GET_DATASET_LINKS_QUERY = """
query getDatasetLinks($filter: DatasetLinkFilter!) {
    datasetLinks(filter: $filter) {
        nodes {
            datasetLinkUuid: datasetLinkId
            computeNode {
                computeNodeUuid: computeNodeId
                nodeName
                dataRoom {
                    dataRoomUuid: dataRoomId
                    dataRoomId: dataRoomHashEncoded
                }
            }
            dataset {
                name
                datasetId: datasetHashEncoded
            }
        }
    }
}
"""


class PlatformApi:
    """
    Class to interact with the GraphQL endpoint of the Decentriq platform.

    This class enables the integration of the Python SDK with the browser-based
    Decentriq platform UI by providing the necessary CRUD functions.
    """

    user_email: str
    _http_api: API

    def __init__(self, user_email: str, http_api: API):
        self.user_email = user_email
        self._http_api = http_api

    def get_data_room_descriptions(self) -> List[DataRoomDescription]:
        data = self._post_graphql(
            """
            query getDataRooms($filter: DataRoomFilter) {
                dataRooms(filter: $filter, orderBy: NAME_ASC) {
                    nodes {
                        dataRoomId: dataRoomHashEncoded
                        name
                        description
                        mrenclave
                        ownerEmail
                        creationDate: createdAt
                        state {
                            status
                        }
                    }
                }
            }
            """
        )
        return self._parse_get_data_rooms_response(data)

    def update_data_room_status(
            self,
            data_room_hash: str,
            status # type: DataRoomStatus.V
    ):
        data_room = self.get_data_room_by_hash(data_room_hash)
        if not data_room:
            raise Exception(f"Unable to find data room with hash '{data_room_hash}'")
        data_room_uuid = data_room["dataRoomUuid"]
        current_datetime_str = datetime.datetime.now().isoformat()
        self._post_graphql(
            """
            mutation upsertState($input: UpsertStateInput!) {
                upsertState(input: $input) {
                    state {
                        id
                        status
                        statusUpdatedAt
                        updatedAt
                        updatedByEmail
                    }
                }
            }
            """,
            {
                "input": {
                    "clientMutationId": str(uuid.uuid4()),
                    "state": {
                        "dataRoomId": data_room_uuid,
                        "status": DataRoomStatus.Name(status).upper(),
                        "statusUpdatedAt": current_datetime_str,
                    }
                }
            }
        )

    def get_dataset_link(
            self,
            data_room_id: str,
            leaf_id: str,
    ) -> Optional[dict]:
        data_room = self.get_data_room_by_hash(data_room_id)
        if not data_room:
            raise Exception(f"Unable to get data room for hash '{data_room_id}'")
        data_room_uuid = data_room["dataRoomUuid"]
        compute_node = self._get_compute_node(data_room_uuid, leaf_id)
        if compute_node:
            compute_node_uuid = compute_node["computeNodeUuid"]
            return self._get_dataset_link(compute_node_uuid)
        else:
            raise Exception(
                f"Unable to find leaf with name '{leaf_id}' for data room '{data_room_id}'"
            )

    def get_dataset_links_for_manifest_hash(
            self,
            manifest_hash: str,
    ) -> Optional[List[str]]:
        links = self._get_dataset_links_for_manifest_hash(manifest_hash)
        return [link["datasetLinkUuid"] for link in links]

    def _get_dataset_links_for_manifest_hash(
            self,
            manifest_hash: str,
    ) -> List[dict]:
        data = self._post_graphql(
            _GET_DATASET_LINKS_QUERY,
            {
                "filter": {
                    "datasetHashEncoded": {"equalTo": manifest_hash},
                }
            }
        )
        return data["datasetLinks"]["nodes"]

    def _get_dataset_link(self, compute_node_uuid: str) -> Optional[dict]:
        data = self._post_graphql(
            _GET_DATASET_LINKS_QUERY,
            {
                "filter": {
                    "computeNode": {
                        "computeNodeId": {"equalTo": compute_node_uuid}
                    }
                }
            }
        )

        nodes = data["datasetLinks"]["nodes"]
        if nodes:
            return nodes[0]
        else:
            return None

    def get_data_rooms_with_published_dataset(self, manifest_hash) -> List[str]:
        links = self._get_dataset_links_for_manifest_hash(manifest_hash)
        data_room_ids = []
        for link in links:
            if "computeNode" in link and "dataRoom" in link["computeNode"]:
                data_room_id = link["computeNode"]["dataRoom"].get("dataRoomId")
                if data_room_id:
                    data_room_ids.append(data_room_id)
        return data_room_ids

    def delete_dataset_link(
            self,
            data_room_id: str,
            leaf_id: str,
    ) -> Optional[dict]:
        dataset_link = self.get_dataset_link(data_room_id, leaf_id)
        if not dataset_link:
            raise Exception(
                f"Unable to find a dataset link for data room '{data_room_id}'" +
                f" and data node '{leaf_id}'"
            )
        else:
            self._post_graphql(
                """
                mutation deleteDatasetLink($input: DeleteDatasetLinkInput!) {
                    deleteDatasetLink(input: $input) {
                        clientMutationId
                    }
                }
                """,
                {
                    "input": {
                        "clientMutationId": str(uuid.uuid4()),
                        "datasetLinkId": dataset_link["datasetLinkUuid"]
                    }
                }
            )

    def delete_dataset_links_for_manifest_hash(
            self,
            manifest_hash: str,
    ) -> Optional[dict]:
        uuids = self.get_dataset_links_for_manifest_hash(manifest_hash)
        if uuids:
            for link_id in uuids:
                self._post_graphql(
                    """
                    mutation deleteDatasetLink($input: DeleteDatasetLinkInput!) {
                        deleteDatasetLink(input: $input) {
                            clientMutationId
                        }
                    }
                    """,
                    {
                        "input": {
                            "clientMutationId": str(uuid.uuid4()),
                            "datasetLinkId": link_id
                        }
                    }
                )

    def _delete_data_room(self, data_room_uuid: str) -> str:
        data = self._post_graphql(
            """
            mutation deleteDataRoom($input: DeleteDataRoomByIdInput!) {
                deleteDataRoomById(input: $input) {
                    clientMutationId
                    dataRoom {
                        id
                    }

                }
            }
            """,
            {
                "input": {
                    "clientMutationId": str(uuid.uuid4()),
                    "id": data_room_uuid,
                }
            }
        )
        deleted_id = data.get("deleteDataRoomById", {}).get("dataRoom", {}).get("id")
        if deleted_id is None:
            raise Exception(
                "Received malformed response when trying to delete DCR in backend"
            )
        else:
            return data_room_uuid

    def publish_data_room(
            self,
            data_room_definition: Tuple[DataRoom, List[ConfigurationModification]],
            data_room_hash: str,
            attestation_specification_hash: str,
            additional_fields: dict = {},
    ):
        data_room, conf_modifications = data_room_definition
        owner_email = data_room.ownerEmail

        participant_emails = [
            op.add.element.userPermission.email
            for op in conf_modifications
            if op.HasField("add") and op.add.element.HasField("userPermission")
        ]

        if owner_email in participant_emails:
            participant_emails.remove(owner_email)

        user_permissions_input = []
        for participant_email in participant_emails:
            user_permissions_input.append({
                "email": participant_email,
            })

        data = self._post_graphql(
            """
            mutation createDataRoom($input: CreateDataRoomInput!) {
                createDataRoom(input: $input) {
                    dataRoom {
                        dataRoomUuid: dataRoomId
                        dataRoomHashEncoded
                        lock {
                            isLocked
                        }
                    }
                }
            }
            """,
            {
                "input": {
                    "clientMutationId": str(uuid.uuid4()),
                    "dataRoom": {
                        "dataRoomHash": platform_hash_to_str(bytes.fromhex(data_room_hash)),
                        "dataRoomHashEncoded": data_room_hash,
                        "name": data_room.name,
                        "description": data_room.description,
                        "mrenclave": attestation_specification_hash,
                        "source": "PYTHON",
                        "ownerEmail": data_room.ownerEmail,
                        "userPermissions": {
                            "create": user_permissions_input
                        },
                        **additional_fields,
                        "lock": {
                            "create": {
                                "isLocked": True
                            }
                        }
                    }
                }
            }
        )

        data_room_uuid = data.get("createDataRoom", {}).get("dataRoom", {}).get("dataRoomUuid")
        if data_room_uuid is None:
            raise Exception(
                "Received malformed response when trying to create DCR in backend"
            )

    def _parse_get_data_rooms_response(self, data) -> List[DataRoomDescription]:
        remove_keys = set(["state"])
        def payload_to_dcr_description(d):
            # A DCR without a state should be displayed as a DCR with "Active" status
            # Uppercase status such as "STOPPED" should be displayed as "Stopped" to match
            # the proto version.
            if d.get("state") and d["state"].get("status"):
                status = d["state"]["status"].capitalize()
            else:
                status = "Active"
            d_cleaned = {k: v for k, v in d.items() if k not in remove_keys}
            return DataRoomDescription(status=status, **d_cleaned)

        dcr_dicts = data.get("dataRooms", {}).get("nodes", [])
        dcr_descriptions = [payload_to_dcr_description(d) for d in dcr_dicts]

        # Remove non-published DCRs from list
        return [desc for desc in dcr_descriptions if desc["dataRoomId"]]

    def get_data_room_by_hash(self, data_room_hash: str) -> Optional[dict]:
        data = self._post_graphql(
            """
            query getDataRoomByHash($dataRoomHashEncoded: String!) {
                dataRooms(condition: {dataRoomHashEncoded: $dataRoomHashEncoded}) {
                    nodes {
                        dataRoomUuid: dataRoomId
                        source
                    }
                }
            }
            """,
            { "dataRoomHashEncoded": data_room_hash }
        )
        entries = data.get("dataRooms", {}).get("nodes", [])

        if len(entries) > 1:
            raise Exception("Cannot have multiple DCRs with the same hashcode")
        elif len(entries) == 0:
            return None
        else:
            return entries[0]

    def get_datasets_of_user(self) -> List[DatasetDescription]:
        data = self._post_graphql(
            """
            query getDatasets {
                datasets {
                    nodes {
                        datasetId: datasetHashEncoded
                        name
                        description
                        ownerEmail
                        creationDate: createdAt
                        datasetMeta {
                            description
                        }
                    }
                }
            }
            """
        )
        nodes = data.get("datasets", {}).get("nodes", [])
        datasets = []
        for node in nodes:
            meta_info = node.get("datasetMeta")
            if meta_info:
                description = meta_info.get("description")
            else:
                description = None
            datasets.append(
                DatasetDescription(
                    datasetId=node["datasetId"],
                    name=node["name"],
                    description=description,
                    ownerEmail=node["ownerEmail"],
                    creationDate=node["creationDate"]
                )
            )
        return datasets

    def save_dataset_metadata(
            self,
            manifest_hash: str,
            file_name: str,
            description: str,
            owner_email: str
    ):
        self._post_graphql(
            """
            mutation createDatasetMeta($input: CreateDatasetMetaInput!) {
                createDatasetMeta(input: $input) {
                    datasetMeta {
                        datasetHashEncoded
                        name
                        description
                    }
                }
            }
            """,
            {
                "input": {
                    "clientMutationId": str(uuid.uuid4()),
                    "datasetMeta": {
                        "datasetHash": platform_hash_to_str(bytes.fromhex(manifest_hash)),
                        "name": file_name,
                        "description": description,
                        "ownerEmail": owner_email,
                    }
                }
            }
        )

    def delete_dataset_metadata(self, manifest_hash: str):
        self._post_graphql(
            """
            mutation deleteDatasetMeta($datasetHashEncoded: String!) {
                deleteDatasetMetaByDatasetHashEncoded(input: {datasetHashEncoded: $datasetHashEncoded}) {
                    datasetMeta {
                        id
                    }
                }
            }
            """,
            {
                "datasetHashEncoded":  manifest_hash
            }
        )

    def create_dataset_link(
            self,
            data_room_id: str,
            manifest_hash: str,
            leaf_id: str
    ):
        data_room = self.get_data_room_by_hash(data_room_id)
        if not data_room:
            raise Exception(f"Unable to get data room id for hash {data_room_id}")
        else:
            if data_room["source"] == "WEB":
                data_room_uuid = data_room["dataRoomUuid"]
                compute_node = self._get_compute_node(data_room_uuid, leaf_id)
                if compute_node:
                    compute_node_uuid = compute_node["computeNodeUuid"]
                    # Can link to both compute nodes (type BRANCH) and leaf nodes (type LEAF).
                    # For SQL nodes we need to link to the verifier compute node.
                    if compute_node_uuid:
                        existing_link = self._get_dataset_link(compute_node_uuid)
                        if existing_link:
                            dataset_hash = existing_link["dataset"]["datasetId"]
                            raise Exception(
                                "The following dataset has already been published for this node." +
                                " Please unpublish this dataset first." +
                                f" Dataset: '{dataset_hash}'"
                            )
                        self._post_graphql(
                            """
                            mutation createDatasetLink($input: CreateDatasetLinkInput!) {
                                createDatasetLink(input: $input) {
                                    clientMutationId
                                    datasetLink {
                                        datasetHashEncoded
                                    }
                                }
                            }
                            """,
                            {
                                "input": {
                                    "clientMutationId": str(uuid.uuid4()),
                                    "datasetLink": {
                                        "datasetHash": platform_hash_to_str(
                                            bytes.fromhex(manifest_hash)
                                        ),
                                        "computeNodeId": compute_node_uuid,
                                    }
                                }
                            }
                        )
                else:
                    raise Exception(
                        f"Unable to find leaf with name '{leaf_id}' for data room '{data_room_id}'"
                    )
            else:
                pass

    def get_datasets_by_ids(
            self,
            manifest_hashes: List[str]
    ) -> List[DatasetDescription]:
        """
        Returns the a list of datasets with the given ids.
        """
        data = self._post_graphql(
            """
            query getDatasets($filter: DatasetMetaFilter!) {
                datasetMetas(filter: $filter) {
                    nodes {
                        datasetId: datasetHashEncoded
                        name
                        description
                        ownerEmail
                        creationDate: createdAt
                    }
                }
            }
            """,
            {
                "filter": {
                    "datasetHashEncoded": {
                        "in": manifest_hashes
                    }
                }
            }
        )
        nodes = data.get("datasetMetas", {}).get("nodes", [])
        return [DatasetDescription(**node) for node in nodes]

    def _get_compute_node(self, data_room_uuid: str, leaf_id: str) -> Optional[dict]:
        data = self._post_graphql(
            """
            query getComputeNodes($filter: ComputeNodeFilter!) {
                computeNodes(filter: $filter) {
                    nodes {
                        computeNodeUuid: computeNodeId
                        nodeName
                        computeNodeType
                    }
                }
            }
            """,
            {
                "filter": {
                    "dataRoomId": { "equalTo": data_room_uuid },
                    "nodeName": { "equalTo": leaf_id },
                }
            }
        )
        nodes = data["computeNodes"]["nodes"]
        if nodes and len(nodes) == 1:
            return nodes[0]
        else:
            return None

    def _post_graphql(self, query: str, variables={}) -> dict:
        request_payload = { "query": query }
        if variables:
            request_payload["variables"] = variables
        response = self._http_api.post(
            "",
            json.dumps(request_payload),
            {"Content-type": "application/json"}
        )
        payload = response.json()
        if "errors" in payload:
            error_messages = []
            for message in payload["errors"]:
                decoded_message =\
                    base64.b64decode(message["message"]).decode('utf-8')
                error_messages.append(decoded_message)
            raise Exception(",".join(error_messages))
        elif "data" in payload:
            return payload["data"]
        else:
            raise Exception("Malformed GraphQL response: no 'data' or 'errors' key")


def create_platform_api(
    api_token: str,
    user_email: str,
    client_id: str = DECENTRIQ_CLIENT_ID,
    api_host: str = DECENTRIQ_API_PLATFORM_HOST,
    api_port: int = DECENTRIQ_API_PLATFORM_PORT,
    api_use_tls: bool = DECENTRIQ_API_PLATFORM_USE_TLS
):
    http_api = API(
        api_token,
        client_id,
        api_host,
        api_port,
        api_prefix="/api/decentriq-platform/graphql",
        use_tls=api_use_tls,
        additional_auth_headers={
            "Authorization-User-Email": user_email,
        }
    )
    return PlatformApi(user_email, http_api)


class ClientPlatformFeatures:
    """
    Provider of a list of methods and properties mirroring what is offered by the Decentriq
    web platform.
    """
    _http_api: API
    _platform_api: PlatformApi

    def __init__(
        self,
        api_token: str,
        user_email: str,
        http_api: API,
        client_id: str = DECENTRIQ_CLIENT_ID,
        api_host: str = DECENTRIQ_API_PLATFORM_HOST,
        api_port: int = DECENTRIQ_API_PLATFORM_PORT,
        api_use_tls: bool = DECENTRIQ_API_PLATFORM_USE_TLS,
    ):
        """
        Creating objects of this class directly is not necessary as an object of this class is
        provided as part of each `Client` object.
        """
        self._http_api = http_api
        self._platform_api = create_platform_api(api_token, user_email, client_id, api_host, api_port, api_use_tls)
        self.user_email = user_email

    @property
    def decentriq_ca_root_certificate(self) -> bytes:
        """
        Returns the root certificate used by the Decentriq identity provider.
        Note that when using this certificate in any authentication scheme, you trust Decentriq as an identity provider!
        """
        url = Endpoints.SYSTEM_CERTIFICATE_AUTHORITY
        response = self._http_api.get(url).json()
        return response["rootCertificate"].encode("utf-8")

    @property
    def decentriq_pki_authentication(self) -> AuthenticationMethod:
        """
        The authentication method that uses the Decentriq root certificate to authenticate
        users.

        This method should be specified when building a data room in case you want to interact
        with the that data room either via the web interface or with sessions created using
        `create_auth_using_decentriq_pki`.
        Note that when using this authentication method you trust Decentriq as an identity provider!

        You can also create an `AuthenticationMethod` object directly and supply your own root certificate,
        with which to authenticate users connecting to your data room.
        In this case you will also need to issue corresponding user certificates and create your
        own custom `decentriq_platform.authentication.Auth` objects.
        """
        root_pki = self.decentriq_ca_root_certificate
        return AuthenticationMethod(
            trustedPki=TrustedPki(rootCertificatePem=root_pki)
        )

    def create_auth_using_decentriq_pki(self, email: str = None) -> Auth:
        """
        Creates a `decentriq_platform.authentication.Auth` object which can be
        attached to a `decentriq_platform.session.Session`.
        Sessions created using such an `Auth` object will commonly be used with
        data rooms that have been configured to use the `decentriq_pki_authentication`
        authentication method.
        """
        email = email if email is not None else self.user_email
        keypair = generate_key()
        csr = generate_csr(email, keypair)
        url = Endpoints.USER_CERTIFICATE.replace(":userId", email)
        csr_req = UserCsrRequest(csrPem=csr.decode("utf-8"))
        resp: UserCsrResponse = self._http_api.post(url, req_body=json.dumps(csr_req)).json()
        cert_chain_pem = resp["certChainPem"].encode("utf-8")
        auth = Auth(cert_chain_pem, keypair, email)
        return auth

    def get_data_room_descriptions(self) -> List[DataRoomDescription]:
        """
        Returns the a list of descriptions of all the data rooms a user created
        or participates in.
        """
        return self._platform_api.get_data_room_descriptions()

    def get_available_datasets(self) -> List[DatasetDescription]:
        """
        Returns the a list of datasets that the current user uploaded, regardless
        of whether they have already been connected to a data room or not.
        """
        return self._platform_api.get_datasets_of_user()


class SessionPlatformFeatures:
    """
    A provider for methods that mirror functionality known from the Decentriq
    web platform.

    This class is similar to `ClientPlatformFeatures` but methods provided on
    this class require communication with an enclave.
    """

    _platform_api: PlatformApi

    def __init__(self, session, api: PlatformApi):
        """
        Instances of this class should not be created directly but rather be
        accessed via the `Session.platform` field.
        """
        self._session = session
        self._platform_api = api

    def get_published_datasets(
            self,
            data_room_id: str
    ) -> List[DatasetDescription]:
        """
        Get a list of all the datasets that were published for a given data room.
        """
        response = self._session.retrieve_published_datasets(data_room_id)
        manifest_hashes =\
            [dataset.datasetHash.hex() for dataset in response.publishedDatasets]
        return self._platform_api.get_datasets_by_ids(manifest_hashes)
