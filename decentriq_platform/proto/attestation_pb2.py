# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: attestation.proto
"""Generated protocol buffer code."""
from google.protobuf.internal import builder as _builder
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x11\x61ttestation.proto\x12\x0b\x61ttestation\"\xc2\x01\n\x08\x46\x61tquote\x12)\n\x04\x65pid\x18\x01 \x01(\x0b\x32\x19.attestation.FatquoteEpidH\x00\x12)\n\x04\x64\x63\x61p\x18\x02 \x01(\x0b\x32\x19.attestation.FatquoteDcapH\x00\x12+\n\x05nitro\x18\x03 \x01(\x0b\x32\x1a.attestation.FatquoteNitroH\x00\x12\'\n\x03snp\x18\x04 \x01(\x0b\x32\x18.attestation.FatquoteSnpH\x00\x42\n\n\x08\x66\x61tquote\"k\n\x0c\x46\x61tquoteEpid\x12\x17\n\x0fiasResponseBody\x18\x01 \x01(\x0c\x12\x16\n\x0eiasCertificate\x18\x02 \x01(\x0c\x12\x14\n\x0ciasSignature\x18\x03 \x01(\x0c\x12\x14\n\x0ciasRootCaDer\x18\x04 \x01(\x0c\"\x86\x01\n\x0c\x46\x61tquoteDcap\x12\x11\n\tdcapQuote\x18\x01 \x01(\x0c\x12\x0f\n\x07tcbInfo\x18\x02 \x01(\x0c\x12\x12\n\nqeIdentity\x18\x03 \x01(\x0c\x12\x13\n\x0btcbSignCert\x18\x04 \x01(\x0c\x12\x12\n\nqeSignCert\x18\x05 \x01(\x0c\x12\x15\n\rdcapRootCaDer\x18\x06 \x01(\x0c\"5\n\rFatquoteNitro\x12\x0c\n\x04\x63ose\x18\x01 \x01(\x0c\x12\x16\n\x0enitroRootCaDer\x18\x02 \x01(\x0c\"\xbb\x01\n\x0b\x46\x61tquoteSnp\x12\x11\n\treportBin\x18\x01 \x01(\x0c\x12\x11\n\tamdArkDer\x18\x02 \x01(\x0c\x12\x11\n\tamdSevDer\x18\x03 \x01(\x0c\x12\x12\n\nvcekCrtDer\x18\x04 \x01(\x0c\x12\x12\n\nreportData\x18\x05 \x01(\x0c\x12\x19\n\x11roughtime_pub_key\x18\x06 \x01(\x0c\x12\x17\n\x0froughtime_nonce\x18\x07 \x01(\x0c\x12\x17\n\x0fsignedTimestamp\x18\x08 \x01(\x0c\"\xc3\x02\n\x18\x41ttestationSpecification\x12\x43\n\tintelEpid\x18\x01 \x01(\x0b\x32..attestation.AttestationSpecificationIntelEpidH\x00\x12\x43\n\tintelDcap\x18\x02 \x01(\x0b\x32..attestation.AttestationSpecificationIntelDcapH\x00\x12\x41\n\x08\x61wsNitro\x18\x03 \x01(\x0b\x32-.attestation.AttestationSpecificationAwsNitroH\x00\x12=\n\x06\x61mdSnp\x18\x04 \x01(\x0b\x32+.attestation.AttestationSpecificationAmdSnpH\x00\x42\x1b\n\x19\x61ttestation_specification\"\xa9\x01\n!AttestationSpecificationIntelEpid\x12\x11\n\tmrenclave\x18\x01 \x01(\x0c\x12\x14\n\x0ciasRootCaDer\x18\x02 \x01(\x0c\x12\x14\n\x0c\x61\x63\x63\x65pt_debug\x18\x03 \x01(\x08\x12 \n\x18\x61\x63\x63\x65pt_group_out_of_date\x18\x04 \x01(\x08\x12#\n\x1b\x61\x63\x63\x65pt_configuration_needed\x18\x05 \x01(\x08\"\xbc\x01\n!AttestationSpecificationIntelDcap\x12\x11\n\tmrenclave\x18\x01 \x01(\x0c\x12\x15\n\rdcapRootCaDer\x18\x02 \x01(\x0c\x12\x14\n\x0c\x61\x63\x63\x65pt_debug\x18\x03 \x01(\x08\x12\x1a\n\x12\x61\x63\x63\x65pt_out_of_date\x18\x04 \x01(\x08\x12#\n\x1b\x61\x63\x63\x65pt_configuration_needed\x18\x05 \x01(\x08\x12\x16\n\x0e\x61\x63\x63\x65pt_revoked\x18\x06 \x01(\x08\"r\n AttestationSpecificationAwsNitro\x12\x16\n\x0enitroRootCaDer\x18\x01 \x01(\x0c\x12\x0c\n\x04pcr0\x18\x02 \x01(\x0c\x12\x0c\n\x04pcr1\x18\x03 \x01(\x0c\x12\x0c\n\x04pcr2\x18\x04 \x01(\x0c\x12\x0c\n\x04pcr8\x18\x05 \x01(\x0c\"|\n\x1e\x41ttestationSpecificationAmdSnp\x12\x11\n\tamdArkDer\x18\x01 \x01(\x0c\x12\x13\n\x0bmeasurement\x18\x02 \x01(\x0c\x12\x17\n\x0froughtimePubKey\x18\x03 \x01(\x0c\x12\x19\n\x11\x61uthorizedChipIds\x18\x04 \x03(\x0c\x62\x06proto3')

_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, globals())
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'attestation_pb2', globals())
if _descriptor._USE_C_DESCRIPTORS == False:

  DESCRIPTOR._options = None
  _FATQUOTE._serialized_start=35
  _FATQUOTE._serialized_end=229
  _FATQUOTEEPID._serialized_start=231
  _FATQUOTEEPID._serialized_end=338
  _FATQUOTEDCAP._serialized_start=341
  _FATQUOTEDCAP._serialized_end=475
  _FATQUOTENITRO._serialized_start=477
  _FATQUOTENITRO._serialized_end=530
  _FATQUOTESNP._serialized_start=533
  _FATQUOTESNP._serialized_end=720
  _ATTESTATIONSPECIFICATION._serialized_start=723
  _ATTESTATIONSPECIFICATION._serialized_end=1046
  _ATTESTATIONSPECIFICATIONINTELEPID._serialized_start=1049
  _ATTESTATIONSPECIFICATIONINTELEPID._serialized_end=1218
  _ATTESTATIONSPECIFICATIONINTELDCAP._serialized_start=1221
  _ATTESTATIONSPECIFICATIONINTELDCAP._serialized_end=1409
  _ATTESTATIONSPECIFICATIONAWSNITRO._serialized_start=1411
  _ATTESTATIONSPECIFICATIONAWSNITRO._serialized_end=1525
  _ATTESTATIONSPECIFICATIONAMDSNP._serialized_start=1527
  _ATTESTATIONSPECIFICATIONAMDSNP._serialized_end=1651
# @@protoc_insertion_point(module_scope)
