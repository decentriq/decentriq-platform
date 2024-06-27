import base64
from typing import Any, Dict, List, Tuple, cast

import asn1crypto.pem

from .certs import (
    amd_snp_ark_pem,
    aws_nitro_root_ca_pem,
    intel_sgx_dcap_root_ca,
    intel_sgx_ias_root_ca,
)
from .decoder import *
from .proto import (
    AttestationSpecification,
    AttestationSpecificationAmdSnp,
    AttestationSpecificationIntelDcap,
)
from .types import EnclaveSpecification

intel_sgx_dcap_root_ca_der = cast(
    Tuple[Any, Any, bytes], asn1crypto.pem.unarmor(intel_sgx_dcap_root_ca)
)[2]
intel_sgx_ias_root_ca_der = cast(
    Tuple[Any, Any, bytes], asn1crypto.pem.unarmor(intel_sgx_ias_root_ca)
)[2]
aws_nitro_root_ca_der = cast(
    Tuple[Any, Any, bytes], asn1crypto.pem.unarmor(aws_nitro_root_ca_pem)
)[2]
amd_snp_ark_der = cast(Tuple[Any, Any, bytes], asn1crypto.pem.unarmor(amd_snp_ark_pem))[
    2
]


# From https://developers.cloudflare.com/time-services/roughtime/recipes/
# See announcement about new server https://groups.google.com/a/chromium.org/g/proto-roughtime/c/vbmjoudG184/m/aXMLEAktBAAJ
# old roughtime public key, valid until July 1st, 2024
roughtime_public_key = base64.b64decode("gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo=")
# new roughtime public key
new_roughtime_public_key = base64.b64decode(
    "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg="
)
decentriq_root_ca_der = base64.b64decode(
    "MIIBPjCB46ADAgECAgEBMAwGCCqGSM49BAMCBQAwEjEQMA4GA1UEAwwHUm9vdCBDQTAgFw0yMzAxMDEwMDAwMDBaGA8yMDcwMDEwMTAwMDAwMFowEjEQMA4GA1UEAwwHUm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOnqVIfFUOqBS5tt8g5srIRfFJkYl61kbOKaAH3gi1QICmItg69K5hdtye3loMCUNiQGSnqS/TeGJuXjTqGpsSWjJjAkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMAwGCCqGSM49BAMCBQADSAAwRQIgX9UM7iEie/2Q5YJiXYn8qHT/FlAOy593VKACQZcqMgsCIQDyxkeooGwU85ilwj0oJOXg4YF7ohVZOuKagomsThIFKg=="
)

SPECIFICATIONS = {
    "decentriq.driver:v10": EnclaveSpecification(
        name="decentriq.driver",
        version="10",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "799044e44e189338553b18706e32284725300926569bbec19af576557abfba19"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GcgDriverDecoder(),
        clientProtocols=[3],
    ),
    "decentriq.driver:v11": EnclaveSpecification(
        name="decentriq.driver",
        version="11",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "661cb988c03197f60a619fc4b6e28980790fefb6ab710f9d8994d42e9d00d8ed"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GcgDriverDecoder(),
        clientProtocols=[4],
    ),
    "decentriq.driver:v12": EnclaveSpecification(
        name="decentriq.driver",
        version="12",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "b24067659124bebeb3e83d15733a50ad72669a162484c3bb5488dba8e743a1d7"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GcgDriverDecoder(),
        clientProtocols=[4],
    ),
    "decentriq.driver:v13": EnclaveSpecification(
        name="decentriq.driver",
        version="13",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "0858710d10692cfd2f00c3f93cda35d125413beb5076b5ca2a7741d8260ed540"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GcgDriverDecoder(),
        clientProtocols=[5],
    ),
    "decentriq.driver:v14": EnclaveSpecification(
        name="decentriq.driver",
        version="14",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "6be4c9677818e70e2b75229617cb3b25c0b53642a7ad50867f9babb1d904d38e"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GcgDriverDecoder(),
        clientProtocols=[5],
    ),
    "decentriq.driver:v16": EnclaveSpecification(
        name="decentriq.driver",
        version="16",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "2e4fec5faa3fab558c8b6a248b97cba2824838329bd0a53e6014c14ed9026140"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GcgDriverDecoder(),
        clientProtocols=[5],
    ),
    "decentriq.driver:v17": EnclaveSpecification(
        name="decentriq.driver",
        version="17",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "c112b5aaa940100d7d70a590963b0cac71d889ff3f14587a590ffb8f42a576e1"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GcgDriverDecoder(),
        clientProtocols=[5],
    ),
    "decentriq.driver:v18": EnclaveSpecification(
        name="decentriq.driver",
        version="18",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "7690de11d11efb95b6977cdd75f99035513006790227e8fd7faf153e02d3cc50"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GcgDriverDecoder(),
        clientProtocols=[5],
    ),
    "decentriq.driver:v19": EnclaveSpecification(
        name="decentriq.driver",
        version="19",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "e3584803d8996bac8a090ae6f4f30c5fb6ebc91ad82080fedb1c82160eda529c"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GcgDriverDecoder(),
        clientProtocols=[5],
    ),
    "decentriq.driver:v20": EnclaveSpecification(
        name="decentriq.driver",
        version="20",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "ae201c5380a6a7c122f2a0e2762f13add664618c4e868e039e23174e66156892"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GcgDriverDecoder(),
        clientProtocols=[6],
    ),
    "decentriq.driver:v21": EnclaveSpecification(
        name="decentriq.driver",
        version="21",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "ae290dfdee2759066341697af5441993ff6df00359be52439c551c37416f77e1"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GcgDriverDecoder(),
        clientProtocols=[6],
    ),
    "decentriq.sql-worker:v10": EnclaveSpecification(
        name="decentriq.sql-worker",
        version="10",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "dcc9847948837a5cdb85d4fb13d6b77ff6ff5dab63bef35c95901adfa7f1a102"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=SqlWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.sql-worker:v11": EnclaveSpecification(
        name="decentriq.sql-worker",
        version="11",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "6812cea56521a8c495d12e4940b7cf66c54d8dbc03859f587db2ea22f68051c8"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=SqlWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.sql-worker:v12": EnclaveSpecification(
        name="decentriq.sql-worker",
        version="12",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "72ca63e791b03ab1a9136c67da8f4fec2cb505fcea8a611afe6e5f6751cc4dd9"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=SqlWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.post-worker:v5": EnclaveSpecification(
        name="decentriq.post-worker",
        version="5",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "52e363142aaefdfbb27e4cb248c3a96743bd917dcc97b05eb42ac1aa6b019860"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=PostWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.post-worker:v6": EnclaveSpecification(
        name="decentriq.post-worker",
        version="6",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "95ff137db91d6ed5f187c9c69eed4e936c4200291ef65fd68bdf2dbe775958e3"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=PostWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.post-worker:v8": EnclaveSpecification(
        name="decentriq.post-worker",
        version="8",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "517096c140d10deb5a081c5b7492953e6ee06b3796c8f191cc48e2785758e596"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=PostWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.post-worker:v9": EnclaveSpecification(
        name="decentriq.post-worker",
        version="9",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "3829df22f1298b15626c7809e43b23bb298eed1fe85030ab4cd06d4a250475a2"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=PostWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-ml-worker-32-64:v10": EnclaveSpecification(
        name="decentriq.python-ml-worker-32-64",
        version="10",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "9a6a0fd3d0652eae039011346c80cedf572c8e725cbb294a2067ce0a66e7c128c7baf370a77b1005eba3f98f467c9cde"
                ),
                roughtimePubKey=roughtime_public_key,
                authorizedChipIds=[
                    bytes.fromhex(
                        "372499d1b652b98aa1cde6d146136ad2b3e8f93b8223c367087577a73b76813928ad25545327032f7dc44a288965eb8e7f16179dbdb3a71fddc36cc19478ce47"
                    ),
                    bytes.fromhex(
                        "ce8a61aea3f76bbdd05706bcbfb4ade4c65b33ad41f49d0e89dec177951117d247781a3195de2e85399b7117d9eee2f6f2c2e5d21064a4d7e2815380212f0937"
                    ),
                    bytes.fromhex(
                        "86185338a275af6b5e26e06a21b4e0c65db0fc9033e4a24e27cb528321726dc152f28b08c05493c48e8fba3047aba6f0a0dd01d3eebb055b3318c1029c0a74ee"
                    ),
                    bytes.fromhex(
                        "7d2e30af8f43cc6de4e6c3ee59a7ab0d9ddfbff4caba3de0e54430215bd640c571d0e4b49d0cd1502fa74ae8a59475fe06dd9e7635500d584478e13f1191dc27"
                    ),
                    bytes.fromhex(
                        "02926acb4dab55b176946d75e5955154b11269dd8bfe7ff7bcd162b26ea47d8b9557bebd927e90667e34e6dbf9f1bb3bff4bdd36f41d2b755cccabf50270e324"
                    ),
                ],
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-ml-worker-32-64:v11": EnclaveSpecification(
        name="decentriq.python-ml-worker-32-64",
        version="11",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "683b9ad485cfd3eb25c5d49739d1392552f044e736a1c15a3039407edfb0c3bbd9e397dd27ab866c0417e6acdc0794ca"
                ),
                roughtimePubKey=roughtime_public_key,
                authorizedChipIds=[
                    bytes.fromhex(
                        "372499d1b652b98aa1cde6d146136ad2b3e8f93b8223c367087577a73b76813928ad25545327032f7dc44a288965eb8e7f16179dbdb3a71fddc36cc19478ce47"
                    ),
                    bytes.fromhex(
                        "ce8a61aea3f76bbdd05706bcbfb4ade4c65b33ad41f49d0e89dec177951117d247781a3195de2e85399b7117d9eee2f6f2c2e5d21064a4d7e2815380212f0937"
                    ),
                    bytes.fromhex(
                        "86185338a275af6b5e26e06a21b4e0c65db0fc9033e4a24e27cb528321726dc152f28b08c05493c48e8fba3047aba6f0a0dd01d3eebb055b3318c1029c0a74ee"
                    ),
                    bytes.fromhex(
                        "7d2e30af8f43cc6de4e6c3ee59a7ab0d9ddfbff4caba3de0e54430215bd640c571d0e4b49d0cd1502fa74ae8a59475fe06dd9e7635500d584478e13f1191dc27"
                    ),
                    bytes.fromhex(
                        "02926acb4dab55b176946d75e5955154b11269dd8bfe7ff7bcd162b26ea47d8b9557bebd927e90667e34e6dbf9f1bb3bff4bdd36f41d2b755cccabf50270e324"
                    ),
                ],
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-ml-worker-32-64:v12": EnclaveSpecification(
        name="decentriq.python-ml-worker-32-64",
        version="12",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "8c17b219d1c0e7ce224b9fd8716bca389f7e1c15df3d791ab7d8ef0dbb85554ae7fa3e7328d5d30cf277bedfd266ee5a"
                ),
                roughtimePubKey=roughtime_public_key,
                authorizedChipIds=[
                    bytes.fromhex(
                        "372499d1b652b98aa1cde6d146136ad2b3e8f93b8223c367087577a73b76813928ad25545327032f7dc44a288965eb8e7f16179dbdb3a71fddc36cc19478ce47"
                    ),
                    bytes.fromhex(
                        "ce8a61aea3f76bbdd05706bcbfb4ade4c65b33ad41f49d0e89dec177951117d247781a3195de2e85399b7117d9eee2f6f2c2e5d21064a4d7e2815380212f0937"
                    ),
                    bytes.fromhex(
                        "86185338a275af6b5e26e06a21b4e0c65db0fc9033e4a24e27cb528321726dc152f28b08c05493c48e8fba3047aba6f0a0dd01d3eebb055b3318c1029c0a74ee"
                    ),
                    bytes.fromhex(
                        "7d2e30af8f43cc6de4e6c3ee59a7ab0d9ddfbff4caba3de0e54430215bd640c571d0e4b49d0cd1502fa74ae8a59475fe06dd9e7635500d584478e13f1191dc27"
                    ),
                    bytes.fromhex(
                        "02926acb4dab55b176946d75e5955154b11269dd8bfe7ff7bcd162b26ea47d8b9557bebd927e90667e34e6dbf9f1bb3bff4bdd36f41d2b755cccabf50270e324"
                    ),
                ],
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-ml-worker-32-64:v13": EnclaveSpecification(
        name="decentriq.python-ml-worker-32-64",
        version="13",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "46b53ba8ff69e0c739cc8a10811bc90aba3d802fdec6bb14f89ca0dc37ff546a70302285f0153c7e41a3eb0872eb92e0"
                ),
                roughtimePubKey=roughtime_public_key,
                authorizedChipIds=[
                    bytes.fromhex(
                        "372499d1b652b98aa1cde6d146136ad2b3e8f93b8223c367087577a73b76813928ad25545327032f7dc44a288965eb8e7f16179dbdb3a71fddc36cc19478ce47"
                    ),
                    bytes.fromhex(
                        "ce8a61aea3f76bbdd05706bcbfb4ade4c65b33ad41f49d0e89dec177951117d247781a3195de2e85399b7117d9eee2f6f2c2e5d21064a4d7e2815380212f0937"
                    ),
                    bytes.fromhex(
                        "86185338a275af6b5e26e06a21b4e0c65db0fc9033e4a24e27cb528321726dc152f28b08c05493c48e8fba3047aba6f0a0dd01d3eebb055b3318c1029c0a74ee"
                    ),
                    bytes.fromhex(
                        "7d2e30af8f43cc6de4e6c3ee59a7ab0d9ddfbff4caba3de0e54430215bd640c571d0e4b49d0cd1502fa74ae8a59475fe06dd9e7635500d584478e13f1191dc27"
                    ),
                    bytes.fromhex(
                        "02926acb4dab55b176946d75e5955154b11269dd8bfe7ff7bcd162b26ea47d8b9557bebd927e90667e34e6dbf9f1bb3bff4bdd36f41d2b755cccabf50270e324"
                    ),
                    bytes.fromhex(
                        "7102b9671cb139729cf41529cffbd45504c2a644947d56c53ec187e6cdde1d4b136a58958049c6d081362d5c4eac518ba6cbce73fba66d56a288b4b26b36c6f3"
                    ),
                ],
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-ml-worker-32-64:v14": EnclaveSpecification(
        name="decentriq.python-ml-worker-32-64",
        version="14",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "7e51b8520f9c509401a0a663558f5bfdd83727e382fe98bd5be81314793608402bb9d0c055663dda6c76152efd15ce0c"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-ml-worker-32-64:v16": EnclaveSpecification(
        name="decentriq.python-ml-worker-32-64",
        version="16",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "8a820d9e1ac5e37267efcc3a703fad82eb0c9fb33bd5ffe43fa548cbe885c142890e306858c491b795602ee977f4d5a7"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-ml-worker-32-64:v17": EnclaveSpecification(
        name="decentriq.python-ml-worker-32-64",
        version="17",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "1003ebcf8740bcb2ed7eea7f07dd9b6e08d025341768e54bc6a27824cb2d799d1109436928d23fc1f8bb9173c063ffb7"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-ml-worker-32-64:v18": EnclaveSpecification(
        name="decentriq.python-ml-worker-32-64",
        version="18",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "7d6676ba14c429880836af7f6230a14a05d0130f1a4a66ca28393c1fbfca569e0ce151284e0ca86325efae1fd271f51a"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-ml-worker-32-64:v19": EnclaveSpecification(
        name="decentriq.python-ml-worker-32-64",
        version="19",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "4ce88a690b4ea1c8d2361c8a84578f27b3b97b4bdc1a21e4117b1effba5e94ad7db95eeee7510fd3d340e7b5c2494319"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-ml-worker-32-64:v20": EnclaveSpecification(
        name="decentriq.python-ml-worker-32-64",
        version="20",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "c766a31beb97525887cc9c096ef871fb5b50fcf4949e5c345750f0dbb5da647f90a50dd7184aa13e9496e994ac5b33b7"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-ml-worker-32-64:v21": EnclaveSpecification(
        name="decentriq.python-ml-worker-32-64",
        version="21",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "2edf7b49f55cb0c654c06c922134bf21b532d6892667e8af2f4ecb98021fcc1e5391f1f87ab7b9237d706fc209435a1a"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-ml-worker-32-64:v22": EnclaveSpecification(
        name="decentriq.python-ml-worker-32-64",
        version="22",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "490c7043fd83a4cedf2ca9d6cf128d302b406b5f1a8172ed48afc3e231f15621ece52d97babb89322592018907eed6d3"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-ml-worker-32-64:v23": EnclaveSpecification(
        name="decentriq.python-ml-worker-32-64",
        version="23",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "9d13a27344d211698052b8cb911c7a7624b614a9b416ce617894d3c7238925d0cd0f152400e234d39103390d7d3aec68"
                ),
                roughtimePubKey=new_roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-synth-data-worker-32-64:v10": EnclaveSpecification(
        name="decentriq.python-synth-data-worker-32-64",
        version="10",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "8b9f780b6524418f4fc8d4bc8b2450c82e09aefb17b36aebfcf0630b6dea8b1451f12c35203d6ddc9c94b74351db9a22"
                ),
                roughtimePubKey=roughtime_public_key,
                authorizedChipIds=[
                    bytes.fromhex(
                        "372499d1b652b98aa1cde6d146136ad2b3e8f93b8223c367087577a73b76813928ad25545327032f7dc44a288965eb8e7f16179dbdb3a71fddc36cc19478ce47"
                    ),
                    bytes.fromhex(
                        "ce8a61aea3f76bbdd05706bcbfb4ade4c65b33ad41f49d0e89dec177951117d247781a3195de2e85399b7117d9eee2f6f2c2e5d21064a4d7e2815380212f0937"
                    ),
                    bytes.fromhex(
                        "86185338a275af6b5e26e06a21b4e0c65db0fc9033e4a24e27cb528321726dc152f28b08c05493c48e8fba3047aba6f0a0dd01d3eebb055b3318c1029c0a74ee"
                    ),
                    bytes.fromhex(
                        "7d2e30af8f43cc6de4e6c3ee59a7ab0d9ddfbff4caba3de0e54430215bd640c571d0e4b49d0cd1502fa74ae8a59475fe06dd9e7635500d584478e13f1191dc27"
                    ),
                    bytes.fromhex(
                        "02926acb4dab55b176946d75e5955154b11269dd8bfe7ff7bcd162b26ea47d8b9557bebd927e90667e34e6dbf9f1bb3bff4bdd36f41d2b755cccabf50270e324"
                    ),
                ],
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-synth-data-worker-32-64:v11": EnclaveSpecification(
        name="decentriq.python-synth-data-worker-32-64",
        version="11",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "4b5c2949eddbe215607a81df61ba75084e705922c76af792d39e437c4ef1f33cc64e04d4bbd40e395bcc3d4bf8daef70"
                ),
                roughtimePubKey=roughtime_public_key,
                authorizedChipIds=[
                    bytes.fromhex(
                        "372499d1b652b98aa1cde6d146136ad2b3e8f93b8223c367087577a73b76813928ad25545327032f7dc44a288965eb8e7f16179dbdb3a71fddc36cc19478ce47"
                    ),
                    bytes.fromhex(
                        "ce8a61aea3f76bbdd05706bcbfb4ade4c65b33ad41f49d0e89dec177951117d247781a3195de2e85399b7117d9eee2f6f2c2e5d21064a4d7e2815380212f0937"
                    ),
                    bytes.fromhex(
                        "86185338a275af6b5e26e06a21b4e0c65db0fc9033e4a24e27cb528321726dc152f28b08c05493c48e8fba3047aba6f0a0dd01d3eebb055b3318c1029c0a74ee"
                    ),
                    bytes.fromhex(
                        "7d2e30af8f43cc6de4e6c3ee59a7ab0d9ddfbff4caba3de0e54430215bd640c571d0e4b49d0cd1502fa74ae8a59475fe06dd9e7635500d584478e13f1191dc27"
                    ),
                    bytes.fromhex(
                        "02926acb4dab55b176946d75e5955154b11269dd8bfe7ff7bcd162b26ea47d8b9557bebd927e90667e34e6dbf9f1bb3bff4bdd36f41d2b755cccabf50270e324"
                    ),
                ],
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-synth-data-worker-32-64:v12": EnclaveSpecification(
        name="decentriq.python-synth-data-worker-32-64",
        version="12",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "c817b0eefc1549b5a077b2a6ddb955bc233824d84301d782643598b48900cde52821b968fb9ab27ae831d4926ac641b7"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-synth-data-worker-32-64:v14": EnclaveSpecification(
        name="decentriq.python-synth-data-worker-32-64",
        version="14",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "9b40ac320e2f142b707f65f055b9a4ef9f7fbe9e1cf2ba5d41cc782f3a614eefa324509b45a6df857dd383c8bb1297b5"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-synth-data-worker-32-64:v15": EnclaveSpecification(
        name="decentriq.python-synth-data-worker-32-64",
        version="15",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "46696d754525bdeb7b5738eb3ab4b41c966938396b6dd7b4a7180f4d6b26b8044d46fc49d0800d88467c539060392e96"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-synth-data-worker-32-64:v16": EnclaveSpecification(
        name="decentriq.python-synth-data-worker-32-64",
        version="16",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "a6c41eba6549d247e9323fa2762dd62985a05ed5d89527c6b2ec5d8b0521d98615e422cb04c3656ac8c50f88f3c8a67e"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-synth-data-worker-32-64:v17": EnclaveSpecification(
        name="decentriq.python-synth-data-worker-32-64",
        version="17",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "26a9c458b2326c4dc63ec619429590da0d9a38a25ba51a759cb3e04cd744e045bf9ca091dc484c0c1b304fc23b689fba"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-synth-data-worker-32-64:v18": EnclaveSpecification(
        name="decentriq.python-synth-data-worker-32-64",
        version="18",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "7c15aafecef3fa78b0e9b1b195b96bb1c00d445e8914ba0243ff66619de346d06e40a95e06b1934c5e3d4ed37686e053"
                ),
                roughtimePubKey=new_roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.r-latex-worker-32-32:v10": EnclaveSpecification(
        name="decentriq.r-latex-worker-32-32",
        version="10",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "5f0a74f6c0633d9d4781d8c112617ce386507b86869b341a89b2183c8e41f01032c3ec9821567530f023f26c0f8a846d"
                ),
                roughtimePubKey=roughtime_public_key,
                authorizedChipIds=[
                    bytes.fromhex(
                        "372499d1b652b98aa1cde6d146136ad2b3e8f93b8223c367087577a73b76813928ad25545327032f7dc44a288965eb8e7f16179dbdb3a71fddc36cc19478ce47"
                    ),
                    bytes.fromhex(
                        "ce8a61aea3f76bbdd05706bcbfb4ade4c65b33ad41f49d0e89dec177951117d247781a3195de2e85399b7117d9eee2f6f2c2e5d21064a4d7e2815380212f0937"
                    ),
                    bytes.fromhex(
                        "86185338a275af6b5e26e06a21b4e0c65db0fc9033e4a24e27cb528321726dc152f28b08c05493c48e8fba3047aba6f0a0dd01d3eebb055b3318c1029c0a74ee"
                    ),
                    bytes.fromhex(
                        "7d2e30af8f43cc6de4e6c3ee59a7ab0d9ddfbff4caba3de0e54430215bd640c571d0e4b49d0cd1502fa74ae8a59475fe06dd9e7635500d584478e13f1191dc27"
                    ),
                    bytes.fromhex(
                        "02926acb4dab55b176946d75e5955154b11269dd8bfe7ff7bcd162b26ea47d8b9557bebd927e90667e34e6dbf9f1bb3bff4bdd36f41d2b755cccabf50270e324"
                    ),
                ],
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.r-latex-worker-32-32:v11": EnclaveSpecification(
        name="decentriq.r-latex-worker-32-32",
        version="11",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "de88718b50772045dd4427f0a7b83e80aa5c6a4e33664b88bc37e9663677d724bb3708ede4fca930506f344662141997"
                ),
                roughtimePubKey=roughtime_public_key,
                authorizedChipIds=[
                    bytes.fromhex(
                        "372499d1b652b98aa1cde6d146136ad2b3e8f93b8223c367087577a73b76813928ad25545327032f7dc44a288965eb8e7f16179dbdb3a71fddc36cc19478ce47"
                    ),
                    bytes.fromhex(
                        "ce8a61aea3f76bbdd05706bcbfb4ade4c65b33ad41f49d0e89dec177951117d247781a3195de2e85399b7117d9eee2f6f2c2e5d21064a4d7e2815380212f0937"
                    ),
                    bytes.fromhex(
                        "86185338a275af6b5e26e06a21b4e0c65db0fc9033e4a24e27cb528321726dc152f28b08c05493c48e8fba3047aba6f0a0dd01d3eebb055b3318c1029c0a74ee"
                    ),
                    bytes.fromhex(
                        "7d2e30af8f43cc6de4e6c3ee59a7ab0d9ddfbff4caba3de0e54430215bd640c571d0e4b49d0cd1502fa74ae8a59475fe06dd9e7635500d584478e13f1191dc27"
                    ),
                    bytes.fromhex(
                        "02926acb4dab55b176946d75e5955154b11269dd8bfe7ff7bcd162b26ea47d8b9557bebd927e90667e34e6dbf9f1bb3bff4bdd36f41d2b755cccabf50270e324"
                    ),
                ],
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.r-latex-worker-32-32:v12": EnclaveSpecification(
        name="decentriq.r-latex-worker-32-32",
        version="12",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "9f06e56b2ad9fb74988a4a84b891735adfa6cc5189c83f4daf0eade78db682f7c89c8a2285a40b1fceeffcfdfdbbd663"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.r-latex-worker-32-32:v14": EnclaveSpecification(
        name="decentriq.r-latex-worker-32-32",
        version="14",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "a0276c0d0e3ca7462e59e9c6243a3110e24f773cf23b4dae94ecc7bf2c6fb758b1f22443330430106f20a8b78e3c5ffe"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.r-latex-worker-32-32:v15": EnclaveSpecification(
        name="decentriq.r-latex-worker-32-32",
        version="15",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "a15bb713f5985a690333092e25afbb072b8d6d1858af760127f49cb81fbe1a33d15984f8f37e40a2e01c170cb4a05cc1"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.r-latex-worker-32-32:v16": EnclaveSpecification(
        name="decentriq.r-latex-worker-32-32",
        version="16",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "dfecd4a6642efca9fdf5720711b490b996b1526bd2a24e42f12d67d772641653119745f8c679a5a27c10bf0b06331a8b"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.r-latex-worker-32-32:v17": EnclaveSpecification(
        name="decentriq.r-latex-worker-32-32",
        version="17",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "7f212fb3d7d60c74438d12edfa2e17212a05a6906b881ab7153e2c85bb9235d0ef167c858dcddd89050838bc4e57df49"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.r-ml-worker-32-32:v1": EnclaveSpecification(
        name="decentriq.r-ml-worker-32-32",
        version="1",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "8ad29c4692d73649da5509b25675ba92d500b8d09f149f3bc7dfac6e8eb8abd8f14cd298264449aaa8bf41134ca91aad"
                ),
                roughtimePubKey=new_roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.s3-sink-worker:v2": EnclaveSpecification(
        name="decentriq.s3-sink-worker",
        version="2",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "963ca160598716c0c94722a8b376b5b647302cc369c0344b2f3bae3dfb1e8eb3"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=S3SinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.s3-sink-worker:v3": EnclaveSpecification(
        name="decentriq.s3-sink-worker",
        version="3",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "09c34e9750a6e18ec7b18d633a5ffb5533c9d5be2bf896eb280717e3da4f2024"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=S3SinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.s3-sink-worker:v5": EnclaveSpecification(
        name="decentriq.s3-sink-worker",
        version="5",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "293b598b660a982bbf6dcc9db44f8c30fcb8a13d0150960434a5669a60d4cb43"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=S3SinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.s3-sink-worker:v6": EnclaveSpecification(
        name="decentriq.s3-sink-worker",
        version="6",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "eabe3e4efe8e8472d6945ca1b1a238b6702fad50fe4864cd80dc089f7712d740"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=S3SinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.s3-sink-worker:v7": EnclaveSpecification(
        name="decentriq.s3-sink-worker",
        version="7",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "1a7e771493f850e6addd7cbada59ec17023c4fa55b922a02c5db9677ade03c70"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=S3SinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.salesforce-worker:v1": EnclaveSpecification(
        name="decentriq.salesforce-worker",
        version="1",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "ddf17a7c5a3ef4515c4b1ad68cc590dd4de035610cc326c2577ba00e75dc119c"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DataSourceSalesforceWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.salesforce-worker:v2": EnclaveSpecification(
        name="decentriq.salesforce-worker",
        version="2",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "655077117b0445a998e08820a9f53623f604aa425b5666505f6cc4b8cbce2ecc"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DataSourceSalesforceWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.permutive-worker:v1": EnclaveSpecification(
        name="decentriq.permutive-worker",
        version="1",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "cc7d4a42538cf6facb683d5b21be8124bad7e470dc3910073fff451d7143de0f"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=PermutiveWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.dataset-sink-worker:v1": EnclaveSpecification(
        name="decentriq.dataset-sink-worker",
        version="1",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "3ffc8524bfc85837340ebfaabe4775f498b5040bbd84f30dcf62f2b1f86a61f4"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DatasetSinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.dataset-sink-worker:v2": EnclaveSpecification(
        name="decentriq.dataset-sink-worker",
        version="2",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "971a45b16095ee1dbff897d42058fa1c1b024d2a2ea2267deda1575f6be21e86"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DatasetSinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.dataset-sink-worker:v3": EnclaveSpecification(
        name="decentriq.dataset-sink-worker",
        version="3",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "bcb7afdc6bc64e638b44047515e3a8a4b8445282fee342fb9666f0531cd6fca4"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DatasetSinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.dataset-sink-worker:v5": EnclaveSpecification(
        name="decentriq.dataset-sink-worker",
        version="5",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "effbd9945e6e2efcebbb657cd9a9b456e0d2c3171878472a45b7f3f949d060b2"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DatasetSinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.dataset-sink-worker:v6": EnclaveSpecification(
        name="decentriq.dataset-sink-worker",
        version="6",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "57444a373aa9c0a451666c2b7cc838c4d2691de2da09c11eb1525b6475fc3d7e"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DatasetSinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.data-source-s3-worker:v1": EnclaveSpecification(
        name="decentriq.data-source-s3-worker",
        version="1",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "67b8fe452b4724d85e81210f163936dc3ad1cf9c8602939a27ebe9afa00673ff"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DataSourceS3WorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.data-source-s3-worker:v2": EnclaveSpecification(
        name="decentriq.data-source-s3-worker",
        version="2",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "f3e7b026ecd80b766bf3073b0aabcae4f55f91611c8de9cba8e671f1b9597ad7"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DataSourceS3WorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.data-source-s3-worker:v4": EnclaveSpecification(
        name="decentriq.data-source-s3-worker",
        version="4",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "e42ddd0aa4a355582bc35128c7008ba8aa197604f3b6c1745c74701438ac5605"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DataSourceS3WorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.data-source-s3-worker:v5": EnclaveSpecification(
        name="decentriq.data-source-s3-worker",
        version="5",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "2bbfda5a90e833bdff07ca84828d99cbce48cb55f61db2dab00106c03bd358b6"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DataSourceS3WorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.data-source-s3-worker:v6": EnclaveSpecification(
        name="decentriq.data-source-s3-worker",
        version="6",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "1a913c06eb2c8e1ea7d87d572424aa8421802374747aba12a2bd7c92ab00f621"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DataSourceS3WorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.data-source-snowflake-worker:v1": EnclaveSpecification(
        name="decentriq.data-source-snowflake-worker",
        version="1",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "303f2c98573b322a06b88fbebd05db398607aac0a04023e0cb8d80ea822cfd3e"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DataSourceSnowflakeWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.data-source-snowflake-worker:v2": EnclaveSpecification(
        name="decentriq.data-source-snowflake-worker",
        version="2",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "0ce5941c05297438d256c5d409afc3f444b09f6bf5a145accbc83525a68459ec"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DataSourceSnowflakeWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.data-source-snowflake-worker:v4": EnclaveSpecification(
        name="decentriq.data-source-snowflake-worker",
        version="4",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "31642671f42befad424cdf7389bfa7fe0ca08dab454d4f2cac46fb34f618d1ae"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DataSourceSnowflakeWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.data-source-snowflake-worker:v5": EnclaveSpecification(
        name="decentriq.data-source-snowflake-worker",
        version="5",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "b607c0b71e470c23b09ea0c2b9af22e4f350129a5df055887b17e02e02aba2e1"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DataSourceSnowflakeWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.meta-sink-worker:v1": EnclaveSpecification(
        name="decentriq.meta-sink-worker",
        version="1",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "b1cc081fa868d6acb4293ff3b287c3da075d11ce2e1eeeb692e311eac9711fff"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=MetaSinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.meta-sink-worker:v2": EnclaveSpecification(
        name="decentriq.meta-sink-worker",
        version="2",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "7d73f04c12338eafc8cc01747ee1817f2cf86d87ca435c27beda965f5ecd2d77"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=MetaSinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.meta-sink-worker:v4": EnclaveSpecification(
        name="decentriq.meta-sink-worker",
        version="4",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "785c9f94e339ec07e92dd2f39859b587da16a5104c89b879eb8589ba590ae947"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=MetaSinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.meta-sink-worker:v5": EnclaveSpecification(
        name="decentriq.meta-sink-worker",
        version="5",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "347cec31ae007bebfe8feedcea51c824688a5bad395e2342fefb9fb0adb7e5e1"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=MetaSinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.google-ad-manager-worker:v1": EnclaveSpecification(
        name="decentriq.google-ad-manager-worker",
        version="1",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "1502c2398e83de066b88050deec30376b2c3dbc54974ced2c7ef37950006a403"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GoogleAdManagerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.google-ad-manager-worker:v2": EnclaveSpecification(
        name="decentriq.google-ad-manager-worker",
        version="2",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "40ed3e2e9b82d1b23d2380e9cb293a59197a979a5ce2918cb0b50f64604bcfeb"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GoogleAdManagerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.google-ad-manager-worker:v3": EnclaveSpecification(
        name="decentriq.google-ad-manager-worker",
        version="3",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "eae60f5bc9ca4cb67fd253206a9a8b4d723f0ce799bb6c9c9b366eb9b7ba8cbd"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GoogleAdManagerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.google-dv-360-sink-worker:v1": EnclaveSpecification(
        name="decentriq.google-dv-360-sink-worker",
        version="1",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "3a00807af2ec87b9de3760188d112c494dd1a41877fbae30ecebb607ceafa3e7"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GoogleDv360SinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.google-dv-360-sink-worker:v3": EnclaveSpecification(
        name="decentriq.google-dv-360-sink-worker",
        version="3",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "b035a0bdb2ea9522ac96efce0008fbc6aa60a01228c2bc377b3aa0a683920b4a"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GoogleDv360SinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.google-dv-360-sink-worker:v4": EnclaveSpecification(
        name="decentriq.google-dv-360-sink-worker",
        version="4",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "3ec53f55dc174a812fd2898ac10c0a6135c3268b6bdd05bad29da35f102be51e"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GoogleDv360SinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.google-dv-360-sink-worker:v5": EnclaveSpecification(
        name="decentriq.google-dv-360-sink-worker",
        version="5",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "30a9ef92fc5cfbcddb9632de7a3c48d9d341004847ec44d1f6415e0ff3aa373e"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GoogleDv360SinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.azure-blob-storage-worker:v2": EnclaveSpecification(
        name="decentriq.azure-blob-storage-worker",
        version="2",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "2db293783d1d072aa7ce3ff148df4f504d091165db7053165fe81af80afab71f"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=AzureBlobStorageWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.azure-blob-storage-worker:v3": EnclaveSpecification(
        name="decentriq.azure-blob-storage-worker",
        version="3",
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "48df661285eae40318e02a50ff35b269e9f26bac29f369753da55633578a07c0"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                acceptDebug=False,
                acceptOutOfDate=False,
                acceptConfigurationNeeded=False,
                acceptRevoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=AzureBlobStorageWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.sqlite-container-worker-32-64:v1": EnclaveSpecification(
        name="decentriq.sqlite-container-worker-32-64",
        version="1",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "e7fbd9f884286e5c419bd13b6d1e91dfd4e93312b3f31461282b30674505d39641f4166f6e12dcdf8a61495cccc1c7a4"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.sqlite-container-worker-32-64:v2": EnclaveSpecification(
        name="decentriq.sqlite-container-worker-32-64",
        version="2",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "e984073ae4fe0f86cc57f6017c96e9b832ca28f33d595af1e21c9a03ad12717baca2e21fbb3209920e463fb9c321a5af"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.sqlite-container-worker-32-64:v4": EnclaveSpecification(
        name="decentriq.sqlite-container-worker-32-64",
        version="4",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "6bcbeb7611f50f91d9c906cdda9aa5ad7439439ff7876343fb7b47aadd4b345aecc2b75208eb60f9cee424fd04412980"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.sqlite-container-worker-32-64:v5": EnclaveSpecification(
        name="decentriq.sqlite-container-worker-32-64",
        version="5",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "049e736a02d9a7fa0d85a07edc51e42cadf8beee7c92838f791905f08acbc4a51d0b995dcbf3205068d0388c16bd4817"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.sqlite-container-worker-32-64:v6": EnclaveSpecification(
        name="decentriq.sqlite-container-worker-32-64",
        version="6",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "5a4a634beb5bc6422becdec1332f8cd5c5742599909ac71534e53b87f231a2d6194d3fdd4a801629621b92d05ce6f18c"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.sqlite-container-worker-32-64:v7": EnclaveSpecification(
        name="decentriq.sqlite-container-worker-32-64",
        version="7",
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "0c487e45b7f9719efa8e603bca3b8f5db0077a3979353133d3a065211dcf75457cb19cfa159ea2b8c703a89ec3c6d4c6"
                ),
                roughtimePubKey=roughtime_public_key,
                decentriqDer=decentriq_root_ca_der,
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
}


class EnclaveSpecifications:
    """
    Provider of the available enclave specifications provided by the Decentriq platform.

    Enclave specifications enable you to express which particular enclaves you trust.
    The field containing the measurement (e.g. `mrenclave` in the case of Intel SGX) identifies
    the exact binary that will process your data.
    Users of the Decentriq platform are encouraged to reproduce this value by building the enclave
    binary from audited source code and re-producing the measurement (in the case of Intel SGX,
    this would involve simply hashing the produced executable).

    When connecting to the driver enclave, the configured attestation algorithm will guarantee that the
    enclave you connect to is the one corresponding to the enclave specification you chose.
    The associated root certificate will be used to verify that the attestation was signed
    by the expected party (e.g. Intel/AMD/Amazon, depending on the CC technology used).

    Any communication between the driver enclave and worker enclaves handling your data will also
    first be secured by additional attestation procedures. Which enclaves are trusted by the
    driver enclave is controlled by choosing the additional enclave specs from the respective
    compute packages.

    A list of enclave specifications, each encoding your trust in a particular enclave type, can
    be obtained by selecting a subset of the enclave specifications provided by the object
    `decentriq_platform.enclave_specifications`. Selecting the subset of versions should be done
    by calling its `versions` method.
    """

    def __init__(self, specifications: Dict[str, EnclaveSpecification]):
        self.specifications = specifications

    def list(self) -> List[str]:
        """Get a list of all available enclave identifiers."""
        return sorted(self.specifications.keys())

    def versions(self, enclave_versions: List[str]) -> Dict[str, EnclaveSpecification]:
        """
        Get the enclave specifications for the given versioned enclave types.

        Make sure to always include the specification of a *driver enclave*, e.g.
        `"decentriq.driver:v1"` as this is the node with which you communicate directly.
        Add additional versioned enclaves depending on the compute module you use.
        Refer to the main documentation page of each compute module to learn which
        enclaves are available.
        """
        selected_specifications = {}
        for version in enclave_versions:
            enclave_type = version.split(":")[0]
            selected_specifications[enclave_type] = self.specifications[version]
        return selected_specifications

    def latest(self) -> Dict[str, EnclaveSpecification]:
        """Select the latest specification of each enclave type"""
        latest_spec_by_type = {}
        latest_version_by_type: Dict[str, str] = {}
        for enclave_identifier in self.specifications:
            enclave_type, enclave_version = enclave_identifier.split(":")
            previous_version = latest_version_by_type.get(enclave_type)
            if previous_version is None or previous_version < enclave_version:
                latest_spec_by_type[enclave_type] = self.specifications[
                    enclave_identifier
                ]
                latest_version_by_type[enclave_type] = enclave_version
        return latest_spec_by_type

    def all(self) -> List[EnclaveSpecification]:
        """Get a list of all available enclave specifications."""
        return list(self.specifications.values())

    def merge(self, other):
        """
        Merge two sets of enclave specifications into a single set.
        """
        return EnclaveSpecifications({**self.specifications, **other.specifications})


enclave_specifications: EnclaveSpecifications = EnclaveSpecifications(SPECIFICATIONS)
"""The main catalogue of enclave specifications available within the Decentriq platform."""
