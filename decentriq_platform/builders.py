from __future__ import annotations
from typing import List, Any, Optional, Callable, Dict
from .proto import (
    AuthenticationMethod, UserPermission, ComputeNode,
    ComputeNodeLeaf, ComputeNodeBranch, Permission, DataRoom,
    AttestationSpecification
)
from .node import Node
from .permission import Permissions
from .types import EnclaveSpecification
import random


class DataRoomBuilder():
    """
    A helper class to ease the building process of a data clean room.
    """
    attestation_specifications: List[AttestationSpecification]
    authentication_methods: List[AuthenticationMethod]
    user_permissions: List[UserPermission]
    compute_nodes: List[ComputeNode]
    id: Optional[str]
    name: str
    description: Optional[str]
    owner_email: Optional[str]
    enclave_specs: Optional[Dict[str, EnclaveSpecification]]

    def __init__(
            self,
            name: str,
            enclave_specs: Optional[Dict[str, EnclaveSpecification]] = None,
            *,
            add_basic_user_permissions: bool = True,
            description: str = None,
            owner_email: str = None,
        ) -> None:
        """
        Create a data room builder object.

        **Parameters**:
        - `name`: The name of the data room to be created.
        - `enclave_specs`: The enclave specification set in which to lookup
            enclave specs for enclaves responsible for executing compute nodes.
            These specs are provided by the `decentriq_platform.enclave_specifications`
            catalogue.
        - `add_basic_user_permissions`: Whether to add basic user permissions
            for each participant. These are:
            1. Permission to retrieve the data room definition
            2. Permission to retrieve the status of the data room
            3. Permission to retrieve the audit log
            4. Permission to retrieve the list of datasets that have been published to the data room
        - `description`: Description of the data room.
        - `owner_email`: A custom owner of the data room. By default this will
            be set to the owner of the session publishing the data room.
        """
        assert name, "The DCR must have a non-empty name"

        self.name = name
        self.attestation_specifications = list()
        self.authentication_methods = list()
        self.user_permissions = list()
        self.compute_nodes = list()
        self.owner_email = owner_email
        self.description = description
        self.id = None
        self.enclave_specs = enclave_specs
        self.add_basic_user_permissions = add_basic_user_permissions

        if description:
            self.add_description(description)

    def using_enclave_specs(self, enclave_specs: Dict[str, EnclaveSpecification]):
        """
        Configure the builder to use the given set of enclave specs. Whenever a new compute
        node is added, the builder will inspect the set of enclave specs to find the correct
        spec that matches the enclave type required by the compute node.
        This method should be called before any compute nodes are added.
        """
        self.enclave_specs = enclave_specs

    def add_description(self, description: str):
        """Add a description to the data room being built."""
        self.description = description

    def add_owner_email(self, email: str):
        """
        Specify a specific owner of the data room.
        By default, the current user will be used.
        """
        self.owner_email = email

    def add_data_node(self, name: str, is_required=False):
        """
        Add a new data node. If the node is marked as required, any computation
        which includes it as a dependency will not start in case no data has
        been provided yet.
        """
        node = ComputeNode(
            nodeName=name,
            leaf=ComputeNodeLeaf(isRequired=is_required)
        )
        self.compute_nodes.append(node)

    def add_compute_node(self, node: Node):
        """
        Add a new compute node. Specific compute node classes are provided either
        by the main package or by the respective compute submodules.
        """
        if self.enclave_specs:
            if node.enclave_type in self.enclave_specs:
                attestation_proto = self.enclave_specs[node.enclave_type]["proto"]
                node_protocol = self.enclave_specs[node.enclave_type]["protocol"]
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
        try:
            attestation_index = self.attestation_specifications.index(attestation_proto)
        except ValueError:
            self.attestation_specifications.append(attestation_proto)
            attestation_index = len(self.attestation_specifications) - 1
        proto_node = ComputeNode(
            nodeName=node.name,
            branch=ComputeNodeBranch(
                config=node.config,
                attestationSpecificationIndex=attestation_index,
                dependencies=node.dependencies,
                outputFormat=node.output_format,
                protocol=node_protocol,
            )
        )
        self.compute_nodes.append(proto_node)

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
        try:
            authentication_method_index = self.authentication_methods.index(authentication_method)
        except ValueError:
            self.authentication_methods.append(authentication_method)
            authentication_method_index = len(self.authentication_methods) - 1

        if self.add_basic_user_permissions:
            permissions.extend([
                Permissions.retrieve_data_room_status(),
                Permissions.retrieve_audit_log(),
                Permissions.retrieve_data_room(),
                Permissions.retrieve_published_datasets(),
            ])

        # Check whether a set of permissions has already been added in a previous
        # call, and extend the permissions in case the authentication method matches.
        # This is required because helper functions might add permissions
        # to the builder before this method is called.
        existing_permission = [
            permission for permission in self.user_permissions
                if email == permission.email and
                    authentication_method_index == permission.authenticationMethodIndex
        ]

        if existing_permission:
            existing_permission[0].permissions.extend(permissions)
        else:
            permission = UserPermission(
                email=email,
                authenticationMethodIndex=authentication_method_index,
                permissions=permissions
            )
            self.user_permissions.append(permission)

    def set_id(self, id: str):
        """
        Set the **internal** identifier for the data room.

        **This is not used for addressing the data room**.
        When publishing the data room, you will recieve the data room hash that can be used
        to interact with the data room.
        By default, this internal id will be automatically randomly generated and therefore calling
        this method is very likely not necessary.

        The main purpose of this field is to give additional entropy to the dataroom definition so that
        otherwise equivalent dataroom definitions may be differentiated.
        It may also be used for retries to ensure exactly-once creation of the data room.
        """
        self.id = id

    def build(self) -> DataRoom:
        """
        Finalize data room contruction.

        Built data rooms still need to be published by a `decentriq_platform.Session` before they can
        be interacted with.
        """
        data_room = DataRoom()
        data_room.name = self.name
        data_room.computeNodes.extend(self.compute_nodes)
        data_room.attestationSpecifications.extend(self.attestation_specifications)
        data_room.userPermissions.extend(self.user_permissions)
        data_room.authenticationMethods.extend(self.authentication_methods)

        if self.owner_email:
            data_room.ownerEmail = self.owner_email

        if self.id:
            data_room.id = self.id
        else:
            data_room.id = random.getrandbits(64).to_bytes(8, byteorder='little').hex()

        if self.description:
            data_room.description = self.description

        return data_room
