from __future__ import annotations
from typing import List, Any, Optional, Callable, Dict, Tuple

from .proto import (
    AuthenticationMethod, UserPermission, ComputeNode,
    ComputeNodeLeaf, ComputeNodeBranch, Permission, DataRoom,
    AttestationSpecification,
    StaticDataRoomPolicy, AffectedDataOwnersApprovePolicy,
    ConfigurationModification, AddModification, ChangeModification, ConfigurationElement,
    ConfigurationCommit,
    DataRoomConfiguration, ComputeNodeProtocol
)
from .proto import GovernanceProtocol as GovernanceProtocolProto
from .node import Node
from .permission import Permissions
from .types import EnclaveSpecification
from .session import Session
import uuid


__all__ = [
    "DataRoomBuilder",
    "DataRoomCommitBuilder",
    "DataRoomModificationsBuilder",
    "GovernanceProtocol",
]


def _extract_configuration_elements(
        config: Optional[DataRoomConfiguration]
) -> Tuple[
        List[Tuple[str, AttestationSpecification]],
        List[Tuple[str, AuthenticationMethod]],
        List[Tuple[str, UserPermission]]
    ]:
    attestation_specs = {}
    authentication_methods = {}
    user_permissions = {}

    items = config.elements if config else []

    for element in items:
        if element.HasField("attestationSpecification"):
            attestation_specs[element.id] = element.attestationSpecification
        elif element.HasField("authenticationMethod"):
            authentication_methods[element.id] = element.authenticationMethod
        elif element.HasField("userPermission"):
            user_permissions[element.id] = element.userPermission

    return (
        list(attestation_specs.items()),
        list(authentication_methods.items()),
        list(user_permissions.items())
    )


def _find_matching_proto_object(
        proto_object: Any,
        other_proto_objects: List[Tuple[str, Any]]
) -> Optional[str]:
    existing_node_id = next(
        (node_id
            for node_id, other_proto_object in other_proto_objects
            if proto_object == other_proto_object),
        None
    )
    return existing_node_id


class GovernanceProtocol:
    """
    The protocol that defines whether and how a data room can be changed
    after it has been published.
    """

    @staticmethod
    def static():
        """
        The data room cannot be changed after it has been published.
        Participants are still allowed to execute development computations
        as long as the required permissions have been granted.
        """
        return GovernanceProtocolProto(
            staticDataRoomPolicy=StaticDataRoomPolicy()
        )

    @staticmethod
    def affected_data_owners_approve():
        """
        The addition of compute nodes must be approved by all data owners
        on whose data the new compute node will depend.
        """
        return GovernanceProtocolProto(
            affectedDataOwnersApprovePolicy=AffectedDataOwnersApprovePolicy()
        )


def _deduplicate_proto_objects(protos):
    """
    Helper function for deduplicating a list of proto messages while
    keeping their original order.
    """
    # Python dicts for Python >= 3.7 keep insertion order
    protos_map = { proto.SerializeToString(): proto for proto in protos }
    return [proto for proto in protos_map.values()]


def _extend_repeated_field(repeated_field, new_protos) -> bool:
    """
    Helper function for extending a repeated field, making sure
    not to insert any duplicates while keeping insertion order.
    """
    repeated_field_map = { proto.SerializeToString(): proto for proto in repeated_field }
    did_append_something = False
    for proto in new_protos:
        proto_key = proto.SerializeToString()
        if proto_key not in repeated_field_map:
            repeated_field_map[proto_key] = proto
            repeated_field.append(proto)
            did_append_something = True
    return did_append_something


class DataRoomBuilder():
    """
    A helper class to ease the building process of a data clean room.
    """
    name: str
    governance_protocol: GovernanceProtocolProto
    description: Optional[str]
    dcr_secret_id: Optional[bytes]
    modifications_builder: DataRoomModificationsBuilder

    def __init__(
            self,
            name: str,
            enclave_specs: Dict[str, EnclaveSpecification],
            governance_protocol: GovernanceProtocolProto = GovernanceProtocol.static(),
            *,
            add_basic_user_permissions: bool = True,
            description: str = None,
            dcr_secret_id: bytes = None,
        ) -> None:
        """
        Create a data room builder object.

        **Parameters**:
        - `name`: The name of the data room to be created.
        - `enclave_specs`: The enclave specification set in which to look-up
            enclave specs for enclaves responsible for executing compute nodes.
            These specs are provided by the `decentriq_platform.enclave_specifications`
            catalogue.
        - `governance_protocol`: The protocol that defines whether and how a
            data room can be changed after it has been published.
        - `add_basic_user_permissions`: Whether to add basic user permissions
            for each participant. These are:
            1. Permission to retrieve the data room definition
            2. Permission to retrieve the status of the data room
            3. Permission to retrieve the audit log
            4. Permission to retrieve the list of datasets that have been published to the data room
            5. Permission to run development computations
        - `description`: Description of the data room.
        """
        assert name, "The DCR must have a non-empty name"

        self.modifications_builder = DataRoomModificationsBuilder(
            enclave_specs,
            add_basic_user_permissions=add_basic_user_permissions
        )
        self.name = name
        self.description = description
        self.governance_protocol = governance_protocol
        self.enclave_specs = enclave_specs
        self.dcr_secret_id = dcr_secret_id

        if description:
            self.add_description(description)

    def add_data_node(
            self,
            name: str,
            is_required: bool = False,
            node_id: Optional[str] = None
    ) -> str:
        """
        Add a new data node. If the node is marked as required, any computation
        which includes it as a dependency will not start in case no data has
        been provided yet.

        **Parameters**:
        - `name`: Name of the data node.
        - `is_required`: If true, any computation which depends on this data node
            can only be run if data has been provided for this node.
        - `node_id`: A custom identifier for this node.
            If not specified, the identifier is generated automatically.

        **Returns**:
        The id that was assigned to the added data node.
        This id will be needed when connecting a dataset or when permissions condering
        this node are defined.
        """
        return self.modifications_builder.add_data_node(
            name,
            is_required=is_required,
            node_id=node_id
        )

    def add_compute_node(
            self,
            node: Node,
            node_id: Optional[str] = None,
            attestation_id: Optional[str] = None
    ) -> str:
        """
        Add a new compute node. Specific compute node classes are provided either
        by the main package or by the respective compute submodules.

        **Parameters**:
        - `node`: The node object to add.
        - `node_id`: A customer identifier for this node. If not specified,
            the identifier is generated automatically.
        - `attestation_id`: An identifier for a concrete attestation specification
            to use for this compute node. If not specified, the specification is
            chosen automatically based on the type of compute node.

        **Returns**:
        The id that was assigned to the added compute node.
        This id is needed when running computations or when adding permissions
        concerning this node.
        """
        return self.modifications_builder.add_compute_node(
            node,
            node_id=node_id,
            attestation_id=attestation_id
        )

    def add_user_permission(
            self,
            email: str,
            authentication_method: AuthenticationMethod,
            permissions: List[Permission],
    ):
        """
        Add permissions for a user.
        The authentication is performed on the enclave side based on the method supplied.
        """
        return self.modifications_builder.add_user_permission(
            email,
            authentication_method,
            permissions
        )

    def add_description(self, description: str):
        """Add a description to the data room being built."""
        self.description = description

    def build(self) -> DataRoom:
        """
        Finalize data room contruction.

        Built data rooms still need to be published by a
        `decentriq_platform.Session` before they can be interacted with.

        **Returns**:
        A tuple containing the following elements:
        (1) A data room object that stores the core properties of the DCR, such
        as its name, its owner, and the government protocol that defines what changes
        can be made to the data room's configuration.
        (2) A list of the recorded modifications that will be applied to the initially
        empty data room configuration within the enclave.
        """
        data_room = DataRoom()
        data_room.name = self.name
        if self.description:
            data_room.description = self.description
        data_room.id = DataRoomBuilder._generate_id()
        data_room.governanceProtocol.CopyFrom(self.governance_protocol)
        data_room.initialConfiguration.CopyFrom(self.modifications_builder.build_flat())

        return data_room

    @staticmethod
    def _generate_id():
        return str(uuid.uuid4())


class DataRoomModificationsBuilder():
    """
    Builder class for constructing lists of modifications that can be
    applied to existing data room configurations.
    """
    data_room_id: Optional[str]
    history_pin: Optional[str]

    new_attestation_specs: List[Tuple[str, AttestationSpecification]]
    new_authentication_methods: List[Tuple[str, AuthenticationMethod]]
    new_user_permissions: List[Tuple[str, UserPermission]]
    new_compute_nodes: List[Tuple[str, ComputeNode]]

    existing_attestation_specs: List[Tuple[str, AttestationSpecification]]
    existing_authentication_methods: List[Tuple[str, AuthenticationMethod]]
    existing_user_permissions: List[Tuple[str, UserPermission]]

    change_user_permissions: List[Tuple[str, UserPermission]]
    change_attestation_specs: List[Tuple[str, AttestationSpecification]]

    enclave_specs: Dict[str, EnclaveSpecification]
    add_basic_user_permissions: bool

    def __init__(
            self,
            enclave_specs: Dict[str, EnclaveSpecification],
            *,
            data_room_id: Optional[str] = None,
            data_room_configuration: Optional[DataRoomConfiguration] = None,
            history_pin: Optional[str] = None,
            add_basic_user_permissions: bool = True,
        ) -> None:
        """
        Construct a builder object for constructing lists of modifications that
        can be applied to existing data room configurations.

        **Parameters**:
        - `enclave_specs`: The enclave specification set in which to lookup
            enclave specs for enclaves responsible for executing compute nodes.
            These specs are provided by the `decentriq_platform.enclave_specifications`
            catalogue.
        - `data_room_id`: The data room to which the modifications should be
            applied.
        - `data_room_configuration`: The current configuration of the data room
            to be altered.
        - `history_pin`: The current history pin that identifies a specific
            point in time within a line of configuration changes.
        - `add_basic_user_permissions`: Whether to add basic user permissions
            for each participant. These are:
            1. Permission to retrieve the data room definition
            2. Permission to retrieve the status of the data room
            3. Permission to retrieve the audit log
            4. Permission to retrieve the list of datasets that have been published to the data room
            5. Permission to run development computations
        """
        self.data_room_id = data_room_id
        self.history_pin = history_pin
        self.enclave_specs = enclave_specs
        self.add_basic_user_permissions = add_basic_user_permissions

        self.new_attestation_specs = []
        self.new_authentication_methods = []
        self.new_user_permissions = []
        self.new_compute_nodes = []

        self.change_user_permissions = []
        self.change_attestation_specs = []

        extracted_conf_elements =\
            _extract_configuration_elements(data_room_configuration)
        self.existing_attestation_specs, \
            self.existing_authentication_methods, \
            self.existing_user_permissions = extracted_conf_elements

    def add_data_node(
            self,
            name: str,
            is_required: bool = False,
            node_id: Optional[str] = None
    ) -> str:
        """
        Add a new data node. If the node is marked as required, any computation
        which includes it as a dependency will not start in case no data has
        been provided yet.

        **Parameters**:
        - `name`: Name of the data node.
        - `is_required`: If true, any computation which depends on this data node
            can only be run if data has been provided for this node.
        - `node_id`: A custom identifier for this node.
            If not specified, the identifier is generated automatically.

        **Returns**:
        The id that was assigned to the added data node.
        This id will be needed when connecting a dataset or when permissions condering
        this node are defined.
        """
        node_id = DataRoomModificationsBuilder._generate_id() if not node_id else node_id
        node = ComputeNode(
            nodeName=name,
            leaf=ComputeNodeLeaf(isRequired=is_required)
        )
        self.new_compute_nodes.append((node_id, node))
        return node_id

    def _add_attestation_specification(
            self,
            attestation_specification: AttestationSpecification
    ) -> str:
        existing_id = _find_matching_proto_object(
            attestation_specification,
            self.existing_attestation_specs + self.new_attestation_specs
        )
        if not existing_id:
            new_id = DataRoomModificationsBuilder._generate_id()
            self.new_attestation_specs.append(
                (new_id, attestation_specification)
            )
            return new_id
        else:
            return existing_id

    def change_attestation_specification(
            self,
            attestation_id: str,
            attestation_specification: AttestationSpecification
    ) -> None:
        """
        Change a particular attestation specification within an existing data room
        configuration to a different one.
        This can be useful if a certain computation is run by a particular worker enclave
        that needs to be upgraded to a newer version.

        **Parameters**:
        - `attestation_id`: The id of the attestation to be replaced.
        - `attestation_specification`: The attestation specification protobuf object.
        """
        existing_spec_ix = None
        for ix, (a_id, attestation) in enumerate(self.new_attestation_specs):
            if a_id == attestation_id:
                existing_spec_ix = ix
                break

        if existing_spec_ix:
            old_spec_id, old_spec = self.new_attestation_specs[existing_spec_ix]
            self.new_attestation_specs[existing_spec_ix] = old_spec_id, attestation_specification
        elif attestation_id in dict(self.existing_attestation_specs):
            self.change_attestation_specs.append(
                (attestation_id, attestation_specification)
            )
        else:
            raise Exception(
                f"There is no attestation specification with id {attestation_id}"
            )

    def add_compute_node(
            self,
            node: Node,
            node_id: Optional[str] = None,
            attestation_id: Optional[str] = None
    ) -> str:
        """
        Add a new compute node. Specific compute node classes are provided either
        by the main package or by the respective compute submodules.

        **Parameters**:
        - `node`: The node object to add.
        - `node_id`: A customer identifier for this node. If not specified,
            the identifier is generated automatically.
        - `attestation_id`: An identifier for a concrete attestation specification
            to use for this compute node. If not specified, the specification is
            chosen automatically based on the type of compute node.

        **Returns**:
        The id that was assigned to the added compute node.
        This id is needed when running computations or when adding permissions
        concerning this node.
        """
        if self.enclave_specs:
            if node.enclave_type in self.enclave_specs:
                attestation_proto = self.enclave_specs[node.enclave_type]["proto"]
                worker_protocol_version = max(
                    self.enclave_specs[node.enclave_type]["workerProtocols"]
                )
                node_protocol = ComputeNodeProtocol(version=worker_protocol_version)
            else:
                raise Exception(
                    f"This compute node requires an enclave of type '{node.enclave_type}' but no"
                    " corresponding enclave spec was provided to this builder."
                )
        else:
            raise Exception(
                "You need to provide a dictionary of enclave specifications to the"
                " builder before calling this method."
            )

        if attestation_id:
            final_attestation_id = attestation_id
        else:
            final_attestation_id =\
                self._add_attestation_specification(attestation_proto)

        node_id = DataRoomModificationsBuilder._generate_id() if not node_id else node_id
        proto_node = ComputeNode(
            nodeName=node.name,
            branch=ComputeNodeBranch(
                config=node.config,
                attestationSpecificationId=final_attestation_id,
                dependencies=node.dependencies,
                outputFormat=node.output_format,
                protocol=node_protocol,
            )
        )
        self.new_compute_nodes.append((node_id, proto_node))
        return node_id

    def _add_authentication_method(
        self,
        authentication_method: AuthenticationMethod
    ) -> str:
        existing_id = _find_matching_proto_object(
            authentication_method,
            self.existing_authentication_methods + self.new_authentication_methods
        )
        if existing_id:
            return existing_id
        else:
            new_id = DataRoomModificationsBuilder._generate_id()
            self.new_authentication_methods.append(
                (new_id, authentication_method)
            )
            return new_id

    def add_user_permission(
            self,
            email: str,
            authentication_method: AuthenticationMethod,
            permissions: List[Permission],
    ):
        """
        Add permissions for a user.
        The authentication is performed on the enclave side based on the method supplied.
        """
        authentication_method_id =\
            self._add_authentication_method(authentication_method)

        if self.add_basic_user_permissions:
            permissions.extend([
                Permissions.retrieve_data_room_status(),
                Permissions.retrieve_audit_log(),
                Permissions.retrieve_data_room(),
                Permissions.retrieve_published_datasets(),
                Permissions.execute_development_compute()
            ])

        # Check whether a set of permissions has already been added in a previous
        # call, and extend the permissions in case the authentication method matches.
        # This is required because helper functions might add permissions
        # to the builder before this method is called.
        existing_permission_old = [
            permission for permission in self.existing_user_permissions
                if email == permission[1].email and
                    authentication_method_id == permission[1].authenticationMethodId
        ]
        existing_permission_new = [
            permission for permission in self.new_user_permissions
                if email == permission[1].email and
                    authentication_method_id == permission[1].authenticationMethodId
        ]

        if existing_permission_old:
            existing_id, existing_permission = existing_permission_old[0]
            did_append_something =\
                _extend_repeated_field(existing_permission.permissions, permissions)
            # Do not add a change modification if none is necessary
            if did_append_something:
                self.change_user_permissions.append((existing_id, existing_permission))
        elif existing_permission_new:
            _, existing_permission = existing_permission_new[0]
            _extend_repeated_field(existing_permission.permissions, permissions)
        else:
            permission = UserPermission(
                email=email,
                authenticationMethodId=authentication_method_id,
                permissions=_deduplicate_proto_objects(permissions)
            )
            self.new_user_permissions.append(
                (DataRoomModificationsBuilder._generate_id(), permission)
            )

    def build_flat(self) -> DataRoomConfiguration:
        configuration_elements = []

        for spec_id, attestation_spec in self.new_attestation_specs:
            configuration_elements.append(
                ConfigurationElement(
                    id=spec_id,
                    attestationSpecification=attestation_spec
                )
            )

        for node_id, compute_node in self.new_compute_nodes:
            configuration_elements.append(
                ConfigurationElement(
                    id=node_id,
                    computeNode=compute_node
                )
            )

        for auth_id, auth_method in self.new_authentication_methods:
            configuration_elements.append(
                ConfigurationElement(
                    id=auth_id,
                    authenticationMethod=auth_method
                )
            )

        for perm_id, permission in self.new_user_permissions:
            configuration_elements.append(
                ConfigurationElement(
                    id=perm_id,
                    userPermission=permission
                )
            )

        configuration = DataRoomConfiguration(elements=configuration_elements)
        return configuration

    def build(self) -> List[ConfigurationModification]:
        """
        Build the list of configuration modifications.
        """
        modifications = []

        for spec_id, attestation_spec in self.new_attestation_specs:
            modifications.append(
                ConfigurationModification(
                    add=AddModification(
                        element=ConfigurationElement(
                            id=spec_id,
                            attestationSpecification=attestation_spec
                        )
                    )
                )
            )

        for node_id, compute_node in self.new_compute_nodes:
            modifications.append(
                ConfigurationModification(
                    add=AddModification(
                        element=ConfigurationElement(
                            id=node_id,
                            computeNode=compute_node
                        )
                    )
                )
            )

        for auth_id, auth_method in self.new_authentication_methods:
            modifications.append(
                ConfigurationModification(
                    add=AddModification(
                        element=ConfigurationElement(
                            id=auth_id,
                            authenticationMethod=auth_method
                        )
                    )
                ),
            )

        for perm_id, permission in self.new_user_permissions:
            modifications.append(
                ConfigurationModification(
                    add=AddModification(
                        element=ConfigurationElement(
                            id=perm_id,
                            userPermission=permission
                        )
                    )
                )
            )

        for perm_id, permission in self.change_user_permissions:
            modifications.append(
                ConfigurationModification(
                    change=ChangeModification(
                        element=ConfigurationElement(
                            id=perm_id,
                            userPermission=permission
                        )
                    )
                )
            )

        for attestation_id, attestation_spec in self.change_attestation_specs:
            modifications.append(
                ConfigurationModification(
                    change=ChangeModification(
                        element=ConfigurationElement(
                            id=attestation_id,
                            attestationSpecification=attestation_spec
                        )
                    )
                )
            )

        return modifications

    @staticmethod
    def _generate_id():
        return str(uuid.uuid4())


class DataRoomCommitBuilder:
    """
    A helper class to build a data room configuration commit,
    i.e. a list of modifications that are to be applied to the configuration
    of an existing data room.
    """
    name: str
    data_room_id: str
    history_pin: str
    modifications_builder: DataRoomModificationsBuilder

    def __init__(
            self,
            name: str,
            data_room_id: str,
            current_configuration: DataRoomConfiguration,
            history_pin: str,
            enclave_specs: Dict[str, EnclaveSpecification],
            *,
            add_basic_user_permissions: bool = False,
    ):
        """
        Construct a builder object for constructing new data room
        configuration commits.
        A configuraton commit contains a list of modifications that
        can be applied to existing data room configuration.

        **Parameters**:
        - `data_room_id`: The data room to which the modifications should be
            applied.
        - `data_room_configuration`: The current configuration of the data room
            to be altered.
        - `history_pin`: The current history pin that identifies a specific
            point in time within a line of configuration changes.
        - `enclave_specs`: The enclave specification set in which to look-up
            enclave specs for enclaves responsible for executing compute nodes.
            These specs are provided by the `decentriq_platform.enclave_specifications`
            catalogue.
        - `add_basic_user_permissions`: Whether to add basic user permissions
            for each participant. These are:
            1. Permission to retrieve the data room definition
            2. Permission to retrieve the status of the data room
            3. Permission to retrieve the audit log
            4. Permission to retrieve the list of datasets that have been published to the data room
            5. Permission to run development computations
        """
        self.name = name
        self.data_room_id = data_room_id
        self.history_pin = history_pin
        self.modifications_builder = DataRoomModificationsBuilder(
            enclave_specs,
            data_room_id=data_room_id,
            history_pin=history_pin,
            data_room_configuration=current_configuration,
            add_basic_user_permissions=add_basic_user_permissions,
        )

    def add_data_node(
            self,
            name: str,
            is_required: bool = False,
            node_id: Optional[str] = None
    ) -> str:
        """
        Add a new data node. If the node is marked as required, any computation
        which includes it as a dependency will not start in case no data has
        been provided yet.

        **Parameters**:
        - `name`: Name of the data node.
        - `is_required`: If true, any computation which depends on this data node
            can only be run if data has been provided for this node.
        - `node_id`: A custom identifier for this node.
            If not specified, the identifier is generated automatically.

        **Returns**:
        The id that was assigned to the added data node.
        This id will be needed when connecting a dataset or when permissions condering
        this node are defined.
        """
        return self.modifications_builder.add_data_node(
            name,
            is_required=is_required,
            node_id=node_id
        )

    def change_attestation_specification(
            self,
            attestation_id: str,
            attestation_specification: AttestationSpecification
    ) -> None:
        self.modifications_builder.change_attestation_specification(
            attestation_id, attestation_specification
        )

    def add_compute_node(
            self,
            node: Node,
            node_id: Optional[str] = None,
            attestation_id: Optional[str] = None
    ) -> str:
        """
        Add a new compute node. Specific compute node classes are provided either
        by the main package or by the respective compute submodules.

        **Parameters**:
        - `node`: The node object to add.
        - `node_id`: A customer identifier for this node. If not specified,
            the identifier is generated automatically.
        - `attestation_id`: An identifier for a concrete attestation specification
            to use for this compute node. If not specified, the specification is
            chosen automatically based on the type of compute node.

        **Returns**:
        The id that was assigned to the added compute node.
        This id is needed when running computations or when adding permissions
        concerning this node.
        """
        return self.modifications_builder.add_compute_node(
            node,
            node_id=node_id,
            attestation_id=attestation_id
        )

    def add_user_permission(
            self,
            email: str,
            authentication_method: AuthenticationMethod,
            permissions: List[Permission],
    ):
        """
        Add permissions for a user.
        The authentication is performed on the enclave side based on the method supplied.
        """
        return self.modifications_builder.add_user_permission(
            email,
            authentication_method,
            permissions
        )

    @staticmethod
    def _generate_id():
        return str(uuid.uuid4())

    def build(self):
        """
        Build the data room configuration commit.

        The built commit still needs to be published and merged in order for
        it to be made part of the data room configuration.
        """
        return ConfigurationCommit(
            id=DataRoomCommitBuilder._generate_id(),
            name=self.name,
            dataRoomId=bytes.fromhex(self.data_room_id),
            dataRoomHistoryPin=bytes.fromhex(self.history_pin),
            modifications=self.modifications_builder.build()
        )
