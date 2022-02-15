from __future__ import annotations
from typing import List, Any, Optional, Callable, Dict
from .proto import (
    AuthenticationMethod, ComputeNodeFormat, UserPermission, ComputeNode,
    ComputeNodeLeaf, ComputeNodeBranch, Permission, DataRoom,
    AttestationSpecification
)
from .types import EnclaveSpecification
import random


class DataRoomBuilder():
    """
    An helper class to ease the building process of a data clean room
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
            description: str = None,
            owner_email: str = None,
        ) -> None:
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
        """Specify the owner of the data room."""
        self.owner_email = email

    def add_data_node(self, name: str, is_required=False):
        """
        Add a new data node. If the node is marked as required, any computation
        which includes it as a dependency will not progress.
        """
        node = ComputeNode(
            nodeName=name,
            leaf=ComputeNodeLeaf(isRequired=is_required)
        )
        self.compute_nodes.append(node)

    def add_using_function(self, do_with_builder: Callable[[DataRoomBuilder], None]):
        """Apply the given function to the builder, transforming it in useful ways."""
        do_with_builder(self)

    def add_compute_node(
            self,
            name: str,
            node: Any,
            dependencies: List[str] = []
    ):
        """
        Add a new compute node. The configuration for a compute node should be
        created using one of the compute-specific libraries.
        """

        required_attributes = set(["enclave_type", "config", "output_format"])
        if not all([hasattr(node, attr) for attr in required_attributes]):
            raise Exception(
                "The given node object is missing a required attribute"
                f" (required: {', '.join(required_attributes)}). "
                "Are you sure that this is a proper node object?"
                " Refer to the documentation of the class you're trying to pass in "
                " to see how it should be used."
            )

        if self.enclave_specs:
            if node.enclave_type in self.enclave_specs:
                attestation_proto = self.enclave_specs[node.enclave_type]["proto"]
            else:
                raise Exception(
                    f"This compute node requires an enclave of type '{node.enclave_type}' but no"
                    " corresponding attestation spec was provided to this builder."
                )
        else:
            raise Exception(
                "You need to provide an attestation spec set to the builder"
                " before calling this method."
            )
        try:
            attestation_index = self.attestation_specifications.index(attestation_proto)
        except ValueError:
            self.attestation_specifications.append(attestation_proto)
            attestation_index = len(self.attestation_specifications) - 1
        proto_node = ComputeNode(
            nodeName=name,
            branch=ComputeNodeBranch(
                config=node.config,
                attestationSpecificationIndex=attestation_index,
                dependencies=dependencies,
                outputFormat=node.output_format,
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
        Add permissions for a user. The authentication is performed on the enclave side
        based on the method supplied.
        """
        try:
            authentication_method_index = self.authentication_methods.index(authentication_method)
        except ValueError:
            self.authentication_methods.append(authentication_method)
            authentication_method_index = len(self.authentication_methods) - 1

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
        By default this internal id will be automatically randomly generated and therefore calling
        this method is very likely not necessary.

        This values main purpose is to give additional entropy to the dataroom definition so that
        otherwise equivalent dataroom definitions may be differentiated.
        It may also be used for retries to ensure exactly-once creation of the dataroom.
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

        if not self.owner_email:
            raise Exception("The data room requires an owner email address to bet set!")
        else:
            data_room.ownerEmail = self.owner_email

        if self.id:
            data_room.id = self.id
        else:
            data_room.id = random.getrandbits(64).to_bytes(8, byteorder='little').hex()

        if self.description:
            data_room.description = self.description

        return data_room
