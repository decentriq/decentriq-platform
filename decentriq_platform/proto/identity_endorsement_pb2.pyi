"""
@generated by mypy-protobuf.  Do not edit manually!
isort:skip_file
"""
import builtins
import google.protobuf.descriptor
import google.protobuf.message
import typing
import typing_extensions

DESCRIPTOR: google.protobuf.descriptor.FileDescriptor

class EndorsementRequest(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    PKIENDORSEMENTREQUEST_FIELD_NUMBER: builtins.int
    DCRSECRETENDORSEMENTREQUEST_FIELD_NUMBER: builtins.int
    @property
    def pkiEndorsementRequest(self) -> global___PkiEndorsementRequest: ...
    @property
    def dcrSecretEndorsementRequest(self) -> global___DcrSecretEndorsementRequest: ...
    def __init__(self,
        *,
        pkiEndorsementRequest: typing.Optional[global___PkiEndorsementRequest] = ...,
        dcrSecretEndorsementRequest: typing.Optional[global___DcrSecretEndorsementRequest] = ...,
        ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["dcrSecretEndorsementRequest",b"dcrSecretEndorsementRequest","endorsementRequest",b"endorsementRequest","pkiEndorsementRequest",b"pkiEndorsementRequest"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["dcrSecretEndorsementRequest",b"dcrSecretEndorsementRequest","endorsementRequest",b"endorsementRequest","pkiEndorsementRequest",b"pkiEndorsementRequest"]) -> None: ...
    def WhichOneof(self, oneof_group: typing_extensions.Literal["endorsementRequest",b"endorsementRequest"]) -> typing.Optional[typing_extensions.Literal["pkiEndorsementRequest","dcrSecretEndorsementRequest"]]: ...
global___EndorsementRequest = EndorsementRequest

class EndorsementResponse(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    PKIENDORSEMENTRESPONSE_FIELD_NUMBER: builtins.int
    DCRSECRETENDORSEMENTRESPONSE_FIELD_NUMBER: builtins.int
    @property
    def pkiEndorsementResponse(self) -> global___PkiEndorsementResponse: ...
    @property
    def dcrSecretEndorsementResponse(self) -> global___DcrSecretEndorsementResponse: ...
    def __init__(self,
        *,
        pkiEndorsementResponse: typing.Optional[global___PkiEndorsementResponse] = ...,
        dcrSecretEndorsementResponse: typing.Optional[global___DcrSecretEndorsementResponse] = ...,
        ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["dcrSecretEndorsementResponse",b"dcrSecretEndorsementResponse","endorsementResponse",b"endorsementResponse","pkiEndorsementResponse",b"pkiEndorsementResponse"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["dcrSecretEndorsementResponse",b"dcrSecretEndorsementResponse","endorsementResponse",b"endorsementResponse","pkiEndorsementResponse",b"pkiEndorsementResponse"]) -> None: ...
    def WhichOneof(self, oneof_group: typing_extensions.Literal["endorsementResponse",b"endorsementResponse"]) -> typing.Optional[typing_extensions.Literal["pkiEndorsementResponse","dcrSecretEndorsementResponse"]]: ...
global___EndorsementResponse = EndorsementResponse

class PkiEndorsementRequest(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    CERTIFICATECHAINPEM_FIELD_NUMBER: builtins.int
    certificateChainPem: builtins.bytes
    def __init__(self,
        *,
        certificateChainPem: builtins.bytes = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["certificateChainPem",b"certificateChainPem"]) -> None: ...
global___PkiEndorsementRequest = PkiEndorsementRequest

class PkiEndorsementResponse(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    PKIENDORSEMENT_FIELD_NUMBER: builtins.int
    @property
    def pkiEndorsement(self) -> global___EnclaveEndorsement: ...
    def __init__(self,
        *,
        pkiEndorsement: typing.Optional[global___EnclaveEndorsement] = ...,
        ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["pkiEndorsement",b"pkiEndorsement"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["pkiEndorsement",b"pkiEndorsement"]) -> None: ...
global___PkiEndorsementResponse = PkiEndorsementResponse

class DcrSecretEndorsementRequest(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    DCRSECRET_FIELD_NUMBER: builtins.int
    dcrSecret: typing.Text
    def __init__(self,
        *,
        dcrSecret: typing.Text = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["dcrSecret",b"dcrSecret"]) -> None: ...
global___DcrSecretEndorsementRequest = DcrSecretEndorsementRequest

class DcrSecretEndorsementResponse(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    DCRSECRETENDORSEMENT_FIELD_NUMBER: builtins.int
    DCRSECRETID_FIELD_NUMBER: builtins.int
    @property
    def dcrSecretEndorsement(self) -> global___EnclaveEndorsement: ...
    dcrSecretId: builtins.bytes
    def __init__(self,
        *,
        dcrSecretEndorsement: typing.Optional[global___EnclaveEndorsement] = ...,
        dcrSecretId: builtins.bytes = ...,
        ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["dcrSecretEndorsement",b"dcrSecretEndorsement"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["dcrSecretEndorsement",b"dcrSecretEndorsement","dcrSecretId",b"dcrSecretId"]) -> None: ...
global___DcrSecretEndorsementResponse = DcrSecretEndorsementResponse

class EnclaveEndorsements(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    PERSONALPKI_FIELD_NUMBER: builtins.int
    DQPKI_FIELD_NUMBER: builtins.int
    DCRSECRET_FIELD_NUMBER: builtins.int
    @property
    def personalPki(self) -> global___EnclaveEndorsement: ...
    @property
    def dqPki(self) -> global___EnclaveEndorsement: ...
    @property
    def dcrSecret(self) -> global___EnclaveEndorsement: ...
    def __init__(self,
        *,
        personalPki: typing.Optional[global___EnclaveEndorsement] = ...,
        dqPki: typing.Optional[global___EnclaveEndorsement] = ...,
        dcrSecret: typing.Optional[global___EnclaveEndorsement] = ...,
        ) -> None: ...
    def HasField(self, field_name: typing_extensions.Literal["dcrSecret",b"dcrSecret","dqPki",b"dqPki","personalPki",b"personalPki"]) -> builtins.bool: ...
    def ClearField(self, field_name: typing_extensions.Literal["dcrSecret",b"dcrSecret","dqPki",b"dqPki","personalPki",b"personalPki"]) -> None: ...
global___EnclaveEndorsements = EnclaveEndorsements

class EnclaveEndorsement(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    ENDORSEMENTCERTIFICATEDER_FIELD_NUMBER: builtins.int
    endorsementCertificateDer: builtins.bytes
    def __init__(self,
        *,
        endorsementCertificateDer: builtins.bytes = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["endorsementCertificateDer",b"endorsementCertificateDer"]) -> None: ...
global___EnclaveEndorsement = EnclaveEndorsement

class PkiClaim(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    ROOTCERTIFICATEDER_FIELD_NUMBER: builtins.int
    rootCertificateDer: builtins.bytes
    def __init__(self,
        *,
        rootCertificateDer: builtins.bytes = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["rootCertificateDer",b"rootCertificateDer"]) -> None: ...
global___PkiClaim = PkiClaim

class DcrSecretClaim(google.protobuf.message.Message):
    DESCRIPTOR: google.protobuf.descriptor.Descriptor
    DCRSECRETID_FIELD_NUMBER: builtins.int
    dcrSecretId: builtins.bytes
    def __init__(self,
        *,
        dcrSecretId: builtins.bytes = ...,
        ) -> None: ...
    def ClearField(self, field_name: typing_extensions.Literal["dcrSecretId",b"dcrSecretId"]) -> None: ...
global___DcrSecretClaim = DcrSecretClaim
