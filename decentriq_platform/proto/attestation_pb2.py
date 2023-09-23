# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: attestation.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='attestation.proto',
  package='attestation',
  syntax='proto3',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\x11\x61ttestation.proto\x12\x0b\x61ttestation\"\xc2\x01\n\x08\x46\x61tquote\x12)\n\x04\x65pid\x18\x01 \x01(\x0b\x32\x19.attestation.FatquoteEpidH\x00\x12)\n\x04\x64\x63\x61p\x18\x02 \x01(\x0b\x32\x19.attestation.FatquoteDcapH\x00\x12+\n\x05nitro\x18\x03 \x01(\x0b\x32\x1a.attestation.FatquoteNitroH\x00\x12\'\n\x03snp\x18\x04 \x01(\x0b\x32\x18.attestation.FatquoteSnpH\x00\x42\n\n\x08\x66\x61tquote\"k\n\x0c\x46\x61tquoteEpid\x12\x17\n\x0fiasResponseBody\x18\x01 \x01(\x0c\x12\x16\n\x0eiasCertificate\x18\x02 \x01(\x0c\x12\x14\n\x0ciasSignature\x18\x03 \x01(\x0c\x12\x14\n\x0ciasRootCaDer\x18\x04 \x01(\x0c\"\x86\x01\n\x0c\x46\x61tquoteDcap\x12\x11\n\tdcapQuote\x18\x01 \x01(\x0c\x12\x0f\n\x07tcbInfo\x18\x02 \x01(\x0c\x12\x12\n\nqeIdentity\x18\x03 \x01(\x0c\x12\x13\n\x0btcbSignCert\x18\x04 \x01(\x0c\x12\x12\n\nqeSignCert\x18\x05 \x01(\x0c\x12\x15\n\rdcapRootCaDer\x18\x06 \x01(\x0c\"5\n\rFatquoteNitro\x12\x0c\n\x04\x63ose\x18\x01 \x01(\x0c\x12\x16\n\x0enitroRootCaDer\x18\x02 \x01(\x0c\"\xdf\x01\n\x0b\x46\x61tquoteSnp\x12\x11\n\treportBin\x18\x01 \x01(\x0c\x12\x11\n\tamdArkDer\x18\x02 \x01(\x0c\x12\x11\n\tamdSevDer\x18\x03 \x01(\x0c\x12\x12\n\nvcekCrtDer\x18\x04 \x01(\x0c\x12\x12\n\nreportData\x18\x05 \x01(\x0c\x12\x17\n\x0froughtimePubKey\x18\x06 \x01(\x0c\x12\x16\n\x0eroughtimeNonce\x18\x07 \x01(\x0c\x12\x17\n\x0fsignedTimestamp\x18\x08 \x01(\x0c\x12\x14\n\x0c\x64\x65\x63\x65ntriqDer\x18\t \x01(\x0c\x12\x0f\n\x07\x63hipDer\x18\n \x01(\x0c\"\xc3\x02\n\x18\x41ttestationSpecification\x12\x43\n\tintelEpid\x18\x01 \x01(\x0b\x32..attestation.AttestationSpecificationIntelEpidH\x00\x12\x43\n\tintelDcap\x18\x02 \x01(\x0b\x32..attestation.AttestationSpecificationIntelDcapH\x00\x12\x41\n\x08\x61wsNitro\x18\x03 \x01(\x0b\x32-.attestation.AttestationSpecificationAwsNitroH\x00\x12=\n\x06\x61mdSnp\x18\x04 \x01(\x0b\x32+.attestation.AttestationSpecificationAmdSnpH\x00\x42\x1b\n\x19\x61ttestation_specification\"\xa9\x01\n!AttestationSpecificationIntelEpid\x12\x11\n\tmrenclave\x18\x01 \x01(\x0c\x12\x14\n\x0ciasRootCaDer\x18\x02 \x01(\x0c\x12\x14\n\x0c\x61\x63\x63\x65pt_debug\x18\x03 \x01(\x08\x12 \n\x18\x61\x63\x63\x65pt_group_out_of_date\x18\x04 \x01(\x08\x12#\n\x1b\x61\x63\x63\x65pt_configuration_needed\x18\x05 \x01(\x08\"\xbc\x01\n!AttestationSpecificationIntelDcap\x12\x11\n\tmrenclave\x18\x01 \x01(\x0c\x12\x15\n\rdcapRootCaDer\x18\x02 \x01(\x0c\x12\x14\n\x0c\x61\x63\x63\x65pt_debug\x18\x03 \x01(\x08\x12\x1a\n\x12\x61\x63\x63\x65pt_out_of_date\x18\x04 \x01(\x08\x12#\n\x1b\x61\x63\x63\x65pt_configuration_needed\x18\x05 \x01(\x08\x12\x16\n\x0e\x61\x63\x63\x65pt_revoked\x18\x06 \x01(\x08\"r\n AttestationSpecificationAwsNitro\x12\x16\n\x0enitroRootCaDer\x18\x01 \x01(\x0c\x12\x0c\n\x04pcr0\x18\x02 \x01(\x0c\x12\x0c\n\x04pcr1\x18\x03 \x01(\x0c\x12\x0c\n\x04pcr2\x18\x04 \x01(\x0c\x12\x0c\n\x04pcr8\x18\x05 \x01(\x0c\"\x92\x01\n\x1e\x41ttestationSpecificationAmdSnp\x12\x11\n\tamdArkDer\x18\x01 \x01(\x0c\x12\x13\n\x0bmeasurement\x18\x02 \x01(\x0c\x12\x17\n\x0froughtimePubKey\x18\x03 \x01(\x0c\x12\x19\n\x11\x61uthorizedChipIds\x18\x04 \x03(\x0c\x12\x14\n\x0c\x64\x65\x63\x65ntriqDer\x18\x05 \x01(\x0c\x62\x06proto3'
)




_FATQUOTE = _descriptor.Descriptor(
  name='Fatquote',
  full_name='attestation.Fatquote',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='epid', full_name='attestation.Fatquote.epid', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='dcap', full_name='attestation.Fatquote.dcap', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='nitro', full_name='attestation.Fatquote.nitro', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='snp', full_name='attestation.Fatquote.snp', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='fatquote', full_name='attestation.Fatquote.fatquote',
      index=0, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
  ],
  serialized_start=35,
  serialized_end=229,
)


_FATQUOTEEPID = _descriptor.Descriptor(
  name='FatquoteEpid',
  full_name='attestation.FatquoteEpid',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='iasResponseBody', full_name='attestation.FatquoteEpid.iasResponseBody', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='iasCertificate', full_name='attestation.FatquoteEpid.iasCertificate', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='iasSignature', full_name='attestation.FatquoteEpid.iasSignature', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='iasRootCaDer', full_name='attestation.FatquoteEpid.iasRootCaDer', index=3,
      number=4, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=231,
  serialized_end=338,
)


_FATQUOTEDCAP = _descriptor.Descriptor(
  name='FatquoteDcap',
  full_name='attestation.FatquoteDcap',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='dcapQuote', full_name='attestation.FatquoteDcap.dcapQuote', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='tcbInfo', full_name='attestation.FatquoteDcap.tcbInfo', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='qeIdentity', full_name='attestation.FatquoteDcap.qeIdentity', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='tcbSignCert', full_name='attestation.FatquoteDcap.tcbSignCert', index=3,
      number=4, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='qeSignCert', full_name='attestation.FatquoteDcap.qeSignCert', index=4,
      number=5, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='dcapRootCaDer', full_name='attestation.FatquoteDcap.dcapRootCaDer', index=5,
      number=6, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=341,
  serialized_end=475,
)


_FATQUOTENITRO = _descriptor.Descriptor(
  name='FatquoteNitro',
  full_name='attestation.FatquoteNitro',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='cose', full_name='attestation.FatquoteNitro.cose', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='nitroRootCaDer', full_name='attestation.FatquoteNitro.nitroRootCaDer', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=477,
  serialized_end=530,
)


_FATQUOTESNP = _descriptor.Descriptor(
  name='FatquoteSnp',
  full_name='attestation.FatquoteSnp',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='reportBin', full_name='attestation.FatquoteSnp.reportBin', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='amdArkDer', full_name='attestation.FatquoteSnp.amdArkDer', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='amdSevDer', full_name='attestation.FatquoteSnp.amdSevDer', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='vcekCrtDer', full_name='attestation.FatquoteSnp.vcekCrtDer', index=3,
      number=4, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='reportData', full_name='attestation.FatquoteSnp.reportData', index=4,
      number=5, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='roughtimePubKey', full_name='attestation.FatquoteSnp.roughtimePubKey', index=5,
      number=6, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='roughtimeNonce', full_name='attestation.FatquoteSnp.roughtimeNonce', index=6,
      number=7, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='signedTimestamp', full_name='attestation.FatquoteSnp.signedTimestamp', index=7,
      number=8, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='decentriqDer', full_name='attestation.FatquoteSnp.decentriqDer', index=8,
      number=9, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='chipDer', full_name='attestation.FatquoteSnp.chipDer', index=9,
      number=10, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=533,
  serialized_end=756,
)


_ATTESTATIONSPECIFICATION = _descriptor.Descriptor(
  name='AttestationSpecification',
  full_name='attestation.AttestationSpecification',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='intelEpid', full_name='attestation.AttestationSpecification.intelEpid', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='intelDcap', full_name='attestation.AttestationSpecification.intelDcap', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='awsNitro', full_name='attestation.AttestationSpecification.awsNitro', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='amdSnp', full_name='attestation.AttestationSpecification.amdSnp', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='attestation_specification', full_name='attestation.AttestationSpecification.attestation_specification',
      index=0, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
  ],
  serialized_start=759,
  serialized_end=1082,
)


_ATTESTATIONSPECIFICATIONINTELEPID = _descriptor.Descriptor(
  name='AttestationSpecificationIntelEpid',
  full_name='attestation.AttestationSpecificationIntelEpid',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='mrenclave', full_name='attestation.AttestationSpecificationIntelEpid.mrenclave', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='iasRootCaDer', full_name='attestation.AttestationSpecificationIntelEpid.iasRootCaDer', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='accept_debug', full_name='attestation.AttestationSpecificationIntelEpid.accept_debug', index=2,
      number=3, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='accept_group_out_of_date', full_name='attestation.AttestationSpecificationIntelEpid.accept_group_out_of_date', index=3,
      number=4, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='accept_configuration_needed', full_name='attestation.AttestationSpecificationIntelEpid.accept_configuration_needed', index=4,
      number=5, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1085,
  serialized_end=1254,
)


_ATTESTATIONSPECIFICATIONINTELDCAP = _descriptor.Descriptor(
  name='AttestationSpecificationIntelDcap',
  full_name='attestation.AttestationSpecificationIntelDcap',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='mrenclave', full_name='attestation.AttestationSpecificationIntelDcap.mrenclave', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='dcapRootCaDer', full_name='attestation.AttestationSpecificationIntelDcap.dcapRootCaDer', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='accept_debug', full_name='attestation.AttestationSpecificationIntelDcap.accept_debug', index=2,
      number=3, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='accept_out_of_date', full_name='attestation.AttestationSpecificationIntelDcap.accept_out_of_date', index=3,
      number=4, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='accept_configuration_needed', full_name='attestation.AttestationSpecificationIntelDcap.accept_configuration_needed', index=4,
      number=5, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='accept_revoked', full_name='attestation.AttestationSpecificationIntelDcap.accept_revoked', index=5,
      number=6, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1257,
  serialized_end=1445,
)


_ATTESTATIONSPECIFICATIONAWSNITRO = _descriptor.Descriptor(
  name='AttestationSpecificationAwsNitro',
  full_name='attestation.AttestationSpecificationAwsNitro',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='nitroRootCaDer', full_name='attestation.AttestationSpecificationAwsNitro.nitroRootCaDer', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='pcr0', full_name='attestation.AttestationSpecificationAwsNitro.pcr0', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='pcr1', full_name='attestation.AttestationSpecificationAwsNitro.pcr1', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='pcr2', full_name='attestation.AttestationSpecificationAwsNitro.pcr2', index=3,
      number=4, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='pcr8', full_name='attestation.AttestationSpecificationAwsNitro.pcr8', index=4,
      number=5, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1447,
  serialized_end=1561,
)


_ATTESTATIONSPECIFICATIONAMDSNP = _descriptor.Descriptor(
  name='AttestationSpecificationAmdSnp',
  full_name='attestation.AttestationSpecificationAmdSnp',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='amdArkDer', full_name='attestation.AttestationSpecificationAmdSnp.amdArkDer', index=0,
      number=1, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='measurement', full_name='attestation.AttestationSpecificationAmdSnp.measurement', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='roughtimePubKey', full_name='attestation.AttestationSpecificationAmdSnp.roughtimePubKey', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='authorizedChipIds', full_name='attestation.AttestationSpecificationAmdSnp.authorizedChipIds', index=3,
      number=4, type=12, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='decentriqDer', full_name='attestation.AttestationSpecificationAmdSnp.decentriqDer', index=4,
      number=5, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=b"",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1564,
  serialized_end=1710,
)

_FATQUOTE.fields_by_name['epid'].message_type = _FATQUOTEEPID
_FATQUOTE.fields_by_name['dcap'].message_type = _FATQUOTEDCAP
_FATQUOTE.fields_by_name['nitro'].message_type = _FATQUOTENITRO
_FATQUOTE.fields_by_name['snp'].message_type = _FATQUOTESNP
_FATQUOTE.oneofs_by_name['fatquote'].fields.append(
  _FATQUOTE.fields_by_name['epid'])
_FATQUOTE.fields_by_name['epid'].containing_oneof = _FATQUOTE.oneofs_by_name['fatquote']
_FATQUOTE.oneofs_by_name['fatquote'].fields.append(
  _FATQUOTE.fields_by_name['dcap'])
_FATQUOTE.fields_by_name['dcap'].containing_oneof = _FATQUOTE.oneofs_by_name['fatquote']
_FATQUOTE.oneofs_by_name['fatquote'].fields.append(
  _FATQUOTE.fields_by_name['nitro'])
_FATQUOTE.fields_by_name['nitro'].containing_oneof = _FATQUOTE.oneofs_by_name['fatquote']
_FATQUOTE.oneofs_by_name['fatquote'].fields.append(
  _FATQUOTE.fields_by_name['snp'])
_FATQUOTE.fields_by_name['snp'].containing_oneof = _FATQUOTE.oneofs_by_name['fatquote']
_ATTESTATIONSPECIFICATION.fields_by_name['intelEpid'].message_type = _ATTESTATIONSPECIFICATIONINTELEPID
_ATTESTATIONSPECIFICATION.fields_by_name['intelDcap'].message_type = _ATTESTATIONSPECIFICATIONINTELDCAP
_ATTESTATIONSPECIFICATION.fields_by_name['awsNitro'].message_type = _ATTESTATIONSPECIFICATIONAWSNITRO
_ATTESTATIONSPECIFICATION.fields_by_name['amdSnp'].message_type = _ATTESTATIONSPECIFICATIONAMDSNP
_ATTESTATIONSPECIFICATION.oneofs_by_name['attestation_specification'].fields.append(
  _ATTESTATIONSPECIFICATION.fields_by_name['intelEpid'])
_ATTESTATIONSPECIFICATION.fields_by_name['intelEpid'].containing_oneof = _ATTESTATIONSPECIFICATION.oneofs_by_name['attestation_specification']
_ATTESTATIONSPECIFICATION.oneofs_by_name['attestation_specification'].fields.append(
  _ATTESTATIONSPECIFICATION.fields_by_name['intelDcap'])
_ATTESTATIONSPECIFICATION.fields_by_name['intelDcap'].containing_oneof = _ATTESTATIONSPECIFICATION.oneofs_by_name['attestation_specification']
_ATTESTATIONSPECIFICATION.oneofs_by_name['attestation_specification'].fields.append(
  _ATTESTATIONSPECIFICATION.fields_by_name['awsNitro'])
_ATTESTATIONSPECIFICATION.fields_by_name['awsNitro'].containing_oneof = _ATTESTATIONSPECIFICATION.oneofs_by_name['attestation_specification']
_ATTESTATIONSPECIFICATION.oneofs_by_name['attestation_specification'].fields.append(
  _ATTESTATIONSPECIFICATION.fields_by_name['amdSnp'])
_ATTESTATIONSPECIFICATION.fields_by_name['amdSnp'].containing_oneof = _ATTESTATIONSPECIFICATION.oneofs_by_name['attestation_specification']
DESCRIPTOR.message_types_by_name['Fatquote'] = _FATQUOTE
DESCRIPTOR.message_types_by_name['FatquoteEpid'] = _FATQUOTEEPID
DESCRIPTOR.message_types_by_name['FatquoteDcap'] = _FATQUOTEDCAP
DESCRIPTOR.message_types_by_name['FatquoteNitro'] = _FATQUOTENITRO
DESCRIPTOR.message_types_by_name['FatquoteSnp'] = _FATQUOTESNP
DESCRIPTOR.message_types_by_name['AttestationSpecification'] = _ATTESTATIONSPECIFICATION
DESCRIPTOR.message_types_by_name['AttestationSpecificationIntelEpid'] = _ATTESTATIONSPECIFICATIONINTELEPID
DESCRIPTOR.message_types_by_name['AttestationSpecificationIntelDcap'] = _ATTESTATIONSPECIFICATIONINTELDCAP
DESCRIPTOR.message_types_by_name['AttestationSpecificationAwsNitro'] = _ATTESTATIONSPECIFICATIONAWSNITRO
DESCRIPTOR.message_types_by_name['AttestationSpecificationAmdSnp'] = _ATTESTATIONSPECIFICATIONAMDSNP
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Fatquote = _reflection.GeneratedProtocolMessageType('Fatquote', (_message.Message,), {
  'DESCRIPTOR' : _FATQUOTE,
  '__module__' : 'attestation_pb2'
  # @@protoc_insertion_point(class_scope:attestation.Fatquote)
  })
_sym_db.RegisterMessage(Fatquote)

FatquoteEpid = _reflection.GeneratedProtocolMessageType('FatquoteEpid', (_message.Message,), {
  'DESCRIPTOR' : _FATQUOTEEPID,
  '__module__' : 'attestation_pb2'
  # @@protoc_insertion_point(class_scope:attestation.FatquoteEpid)
  })
_sym_db.RegisterMessage(FatquoteEpid)

FatquoteDcap = _reflection.GeneratedProtocolMessageType('FatquoteDcap', (_message.Message,), {
  'DESCRIPTOR' : _FATQUOTEDCAP,
  '__module__' : 'attestation_pb2'
  # @@protoc_insertion_point(class_scope:attestation.FatquoteDcap)
  })
_sym_db.RegisterMessage(FatquoteDcap)

FatquoteNitro = _reflection.GeneratedProtocolMessageType('FatquoteNitro', (_message.Message,), {
  'DESCRIPTOR' : _FATQUOTENITRO,
  '__module__' : 'attestation_pb2'
  # @@protoc_insertion_point(class_scope:attestation.FatquoteNitro)
  })
_sym_db.RegisterMessage(FatquoteNitro)

FatquoteSnp = _reflection.GeneratedProtocolMessageType('FatquoteSnp', (_message.Message,), {
  'DESCRIPTOR' : _FATQUOTESNP,
  '__module__' : 'attestation_pb2'
  # @@protoc_insertion_point(class_scope:attestation.FatquoteSnp)
  })
_sym_db.RegisterMessage(FatquoteSnp)

AttestationSpecification = _reflection.GeneratedProtocolMessageType('AttestationSpecification', (_message.Message,), {
  'DESCRIPTOR' : _ATTESTATIONSPECIFICATION,
  '__module__' : 'attestation_pb2'
  # @@protoc_insertion_point(class_scope:attestation.AttestationSpecification)
  })
_sym_db.RegisterMessage(AttestationSpecification)

AttestationSpecificationIntelEpid = _reflection.GeneratedProtocolMessageType('AttestationSpecificationIntelEpid', (_message.Message,), {
  'DESCRIPTOR' : _ATTESTATIONSPECIFICATIONINTELEPID,
  '__module__' : 'attestation_pb2'
  # @@protoc_insertion_point(class_scope:attestation.AttestationSpecificationIntelEpid)
  })
_sym_db.RegisterMessage(AttestationSpecificationIntelEpid)

AttestationSpecificationIntelDcap = _reflection.GeneratedProtocolMessageType('AttestationSpecificationIntelDcap', (_message.Message,), {
  'DESCRIPTOR' : _ATTESTATIONSPECIFICATIONINTELDCAP,
  '__module__' : 'attestation_pb2'
  # @@protoc_insertion_point(class_scope:attestation.AttestationSpecificationIntelDcap)
  })
_sym_db.RegisterMessage(AttestationSpecificationIntelDcap)

AttestationSpecificationAwsNitro = _reflection.GeneratedProtocolMessageType('AttestationSpecificationAwsNitro', (_message.Message,), {
  'DESCRIPTOR' : _ATTESTATIONSPECIFICATIONAWSNITRO,
  '__module__' : 'attestation_pb2'
  # @@protoc_insertion_point(class_scope:attestation.AttestationSpecificationAwsNitro)
  })
_sym_db.RegisterMessage(AttestationSpecificationAwsNitro)

AttestationSpecificationAmdSnp = _reflection.GeneratedProtocolMessageType('AttestationSpecificationAmdSnp', (_message.Message,), {
  'DESCRIPTOR' : _ATTESTATIONSPECIFICATIONAMDSNP,
  '__module__' : 'attestation_pb2'
  # @@protoc_insertion_point(class_scope:attestation.AttestationSpecificationAmdSnp)
  })
_sym_db.RegisterMessage(AttestationSpecificationAmdSnp)


# @@protoc_insertion_point(module_scope)
