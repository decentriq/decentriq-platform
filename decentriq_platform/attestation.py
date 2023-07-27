import base64
from typing import Dict, List, Tuple
from .types import EnclaveSpecification
from .compute import GcgDriverDecoder
from .post.compute import PostWorkerDecoder
from .sql.compute import SqlWorkerDecoder
from .container.compute import ContainerWorkerDecoder
from .s3_sink.compute import S3SinkWorkerDecoder
from .dataset_sink import DatasetSinkWorkerDecoder
from .meta_sink import MetaSinkWorkerDecoder
from .google_dv_360_sink import GoogleDv360SinkWorkerDecoder
from .data_source_s3 import DataSourceS3WorkerDecoder
from .data_source_snowflake import DataSourceSnowflakeWorkerDecoder
from .proto import (
    AttestationSpecification,
    AttestationSpecificationIntelDcap,
    AttestationSpecificationAwsNitro,
    AttestationSpecificationAmdSnp,
)
import asn1crypto.pem
from .certs import (
    aws_nitro_root_ca_pem,
    amd_snp_ark_pem,
    intel_sgx_dcap_root_ca,
    intel_sgx_ias_root_ca,
)


intel_sgx_dcap_root_ca_der = asn1crypto.pem.unarmor(intel_sgx_dcap_root_ca)[2]
intel_sgx_ias_root_ca_der = asn1crypto.pem.unarmor(intel_sgx_ias_root_ca)[2]
aws_nitro_root_ca_der = asn1crypto.pem.unarmor(aws_nitro_root_ca_pem)[2]
amd_snp_ark_der = asn1crypto.pem.unarmor(amd_snp_ark_pem)[2]


# From https://developers.cloudflare.com/time-services/roughtime/recipes/
roughtime_public_key = base64.b64decode("gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo=")
decentriq_root_ca_der = base64.b64decode("MIIBPjCB46ADAgECAgEBMAwGCCqGSM49BAMCBQAwEjEQMA4GA1UEAwwHUm9vdCBDQTAgFw0yMzAxMDEwMDAwMDBaGA8yMDcwMDEwMTAwMDAwMFowEjEQMA4GA1UEAwwHUm9vdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOnqVIfFUOqBS5tt8g5srIRfFJkYl61kbOKaAH3gi1QICmItg69K5hdtye3loMCUNiQGSnqS/TeGJuXjTqGpsSWjJjAkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMAwGCCqGSM49BAMCBQADSAAwRQIgX9UM7iEie/2Q5YJiXYn8qHT/FlAOy593VKACQZcqMgsCIQDyxkeooGwU85ilwj0oJOXg4YF7ohVZOuKagomsThIFKg==")

SPECIFICATIONS = {
    "decentriq.driver:v10": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "799044e44e189338553b18706e32284725300926569bbec19af576557abfba19"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GcgDriverDecoder(),
        clientProtocols=[3],
    ),
    "decentriq.driver:v11": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "661cb988c03197f60a619fc4b6e28980790fefb6ab710f9d8994d42e9d00d8ed"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GcgDriverDecoder(),
        clientProtocols=[4],
    ),
    "decentriq.driver:v12": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "b24067659124bebeb3e83d15733a50ad72669a162484c3bb5488dba8e743a1d7"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GcgDriverDecoder(),
        clientProtocols=[4],
    ),
    "decentriq.driver:v13": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "0858710d10692cfd2f00c3f93cda35d125413beb5076b5ca2a7741d8260ed540"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GcgDriverDecoder(),
        clientProtocols=[5],
    ),
    "decentriq.driver:v14": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "6be4c9677818e70e2b75229617cb3b25c0b53642a7ad50867f9babb1d904d38e"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GcgDriverDecoder(),
        clientProtocols=[5],
    ),
    "decentriq.sql-worker:v10": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "dcc9847948837a5cdb85d4fb13d6b77ff6ff5dab63bef35c95901adfa7f1a102"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=SqlWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.sql-worker:v11": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "6812cea56521a8c495d12e4940b7cf66c54d8dbc03859f587db2ea22f68051c8"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=SqlWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.post-worker:v5": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "52e363142aaefdfbb27e4cb248c3a96743bd917dcc97b05eb42ac1aa6b019860"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=PostWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.post-worker:v6": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "95ff137db91d6ed5f187c9c69eed4e936c4200291ef65fd68bdf2dbe775958e3"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=PostWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-ml-worker-32-64:v10": EnclaveSpecification(
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "9a6a0fd3d0652eae039011346c80cedf572c8e725cbb294a2067ce0a66e7c128c7baf370a77b1005eba3f98f467c9cde"
                ),
                roughtimePubKey=roughtime_public_key,
                authorizedChipIds=[
                    bytes.fromhex("372499d1b652b98aa1cde6d146136ad2b3e8f93b8223c367087577a73b76813928ad25545327032f7dc44a288965eb8e7f16179dbdb3a71fddc36cc19478ce47"),
                    bytes.fromhex("ce8a61aea3f76bbdd05706bcbfb4ade4c65b33ad41f49d0e89dec177951117d247781a3195de2e85399b7117d9eee2f6f2c2e5d21064a4d7e2815380212f0937"),
                    bytes.fromhex("86185338a275af6b5e26e06a21b4e0c65db0fc9033e4a24e27cb528321726dc152f28b08c05493c48e8fba3047aba6f0a0dd01d3eebb055b3318c1029c0a74ee"),
                    bytes.fromhex("7d2e30af8f43cc6de4e6c3ee59a7ab0d9ddfbff4caba3de0e54430215bd640c571d0e4b49d0cd1502fa74ae8a59475fe06dd9e7635500d584478e13f1191dc27"),
                    bytes.fromhex("02926acb4dab55b176946d75e5955154b11269dd8bfe7ff7bcd162b26ea47d8b9557bebd927e90667e34e6dbf9f1bb3bff4bdd36f41d2b755cccabf50270e324"),
                ],
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-ml-worker-32-64:v11": EnclaveSpecification(
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "683b9ad485cfd3eb25c5d49739d1392552f044e736a1c15a3039407edfb0c3bbd9e397dd27ab866c0417e6acdc0794ca"
                ),
                roughtimePubKey=roughtime_public_key,
                authorizedChipIds=[
                    bytes.fromhex("372499d1b652b98aa1cde6d146136ad2b3e8f93b8223c367087577a73b76813928ad25545327032f7dc44a288965eb8e7f16179dbdb3a71fddc36cc19478ce47"),
                    bytes.fromhex("ce8a61aea3f76bbdd05706bcbfb4ade4c65b33ad41f49d0e89dec177951117d247781a3195de2e85399b7117d9eee2f6f2c2e5d21064a4d7e2815380212f0937"),
                    bytes.fromhex("86185338a275af6b5e26e06a21b4e0c65db0fc9033e4a24e27cb528321726dc152f28b08c05493c48e8fba3047aba6f0a0dd01d3eebb055b3318c1029c0a74ee"),
                    bytes.fromhex("7d2e30af8f43cc6de4e6c3ee59a7ab0d9ddfbff4caba3de0e54430215bd640c571d0e4b49d0cd1502fa74ae8a59475fe06dd9e7635500d584478e13f1191dc27"),
                    bytes.fromhex("02926acb4dab55b176946d75e5955154b11269dd8bfe7ff7bcd162b26ea47d8b9557bebd927e90667e34e6dbf9f1bb3bff4bdd36f41d2b755cccabf50270e324"),
                ],
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-ml-worker-32-64:v12": EnclaveSpecification(
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "8c17b219d1c0e7ce224b9fd8716bca389f7e1c15df3d791ab7d8ef0dbb85554ae7fa3e7328d5d30cf277bedfd266ee5a"
                ),
                roughtimePubKey=roughtime_public_key,
                authorizedChipIds=[
                    bytes.fromhex("372499d1b652b98aa1cde6d146136ad2b3e8f93b8223c367087577a73b76813928ad25545327032f7dc44a288965eb8e7f16179dbdb3a71fddc36cc19478ce47"),
                    bytes.fromhex("ce8a61aea3f76bbdd05706bcbfb4ade4c65b33ad41f49d0e89dec177951117d247781a3195de2e85399b7117d9eee2f6f2c2e5d21064a4d7e2815380212f0937"),
                    bytes.fromhex("86185338a275af6b5e26e06a21b4e0c65db0fc9033e4a24e27cb528321726dc152f28b08c05493c48e8fba3047aba6f0a0dd01d3eebb055b3318c1029c0a74ee"),
                    bytes.fromhex("7d2e30af8f43cc6de4e6c3ee59a7ab0d9ddfbff4caba3de0e54430215bd640c571d0e4b49d0cd1502fa74ae8a59475fe06dd9e7635500d584478e13f1191dc27"),
                    bytes.fromhex("02926acb4dab55b176946d75e5955154b11269dd8bfe7ff7bcd162b26ea47d8b9557bebd927e90667e34e6dbf9f1bb3bff4bdd36f41d2b755cccabf50270e324"),
                ],
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-ml-worker-32-64:v13": EnclaveSpecification(
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "46b53ba8ff69e0c739cc8a10811bc90aba3d802fdec6bb14f89ca0dc37ff546a70302285f0153c7e41a3eb0872eb92e0"
                ),
                roughtimePubKey=roughtime_public_key,
                authorizedChipIds=[
                    bytes.fromhex("372499d1b652b98aa1cde6d146136ad2b3e8f93b8223c367087577a73b76813928ad25545327032f7dc44a288965eb8e7f16179dbdb3a71fddc36cc19478ce47"),
                    bytes.fromhex("ce8a61aea3f76bbdd05706bcbfb4ade4c65b33ad41f49d0e89dec177951117d247781a3195de2e85399b7117d9eee2f6f2c2e5d21064a4d7e2815380212f0937"),
                    bytes.fromhex("86185338a275af6b5e26e06a21b4e0c65db0fc9033e4a24e27cb528321726dc152f28b08c05493c48e8fba3047aba6f0a0dd01d3eebb055b3318c1029c0a74ee"),
                    bytes.fromhex("7d2e30af8f43cc6de4e6c3ee59a7ab0d9ddfbff4caba3de0e54430215bd640c571d0e4b49d0cd1502fa74ae8a59475fe06dd9e7635500d584478e13f1191dc27"),
                    bytes.fromhex("02926acb4dab55b176946d75e5955154b11269dd8bfe7ff7bcd162b26ea47d8b9557bebd927e90667e34e6dbf9f1bb3bff4bdd36f41d2b755cccabf50270e324"),
                    bytes.fromhex("7102b9671cb139729cf41529cffbd45504c2a644947d56c53ec187e6cdde1d4b136a58958049c6d081362d5c4eac518ba6cbce73fba66d56a288b4b26b36c6f3"),
                ],
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-ml-worker-32-64:v14": EnclaveSpecification(
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
    "decentriq.python-synth-data-worker-32-64:v10": EnclaveSpecification(
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "8b9f780b6524418f4fc8d4bc8b2450c82e09aefb17b36aebfcf0630b6dea8b1451f12c35203d6ddc9c94b74351db9a22"
                ),
                roughtimePubKey=roughtime_public_key,
                authorizedChipIds=[
                    bytes.fromhex("372499d1b652b98aa1cde6d146136ad2b3e8f93b8223c367087577a73b76813928ad25545327032f7dc44a288965eb8e7f16179dbdb3a71fddc36cc19478ce47"),
                    bytes.fromhex("ce8a61aea3f76bbdd05706bcbfb4ade4c65b33ad41f49d0e89dec177951117d247781a3195de2e85399b7117d9eee2f6f2c2e5d21064a4d7e2815380212f0937"),
                    bytes.fromhex("86185338a275af6b5e26e06a21b4e0c65db0fc9033e4a24e27cb528321726dc152f28b08c05493c48e8fba3047aba6f0a0dd01d3eebb055b3318c1029c0a74ee"),
                    bytes.fromhex("7d2e30af8f43cc6de4e6c3ee59a7ab0d9ddfbff4caba3de0e54430215bd640c571d0e4b49d0cd1502fa74ae8a59475fe06dd9e7635500d584478e13f1191dc27"),
                    bytes.fromhex("02926acb4dab55b176946d75e5955154b11269dd8bfe7ff7bcd162b26ea47d8b9557bebd927e90667e34e6dbf9f1bb3bff4bdd36f41d2b755cccabf50270e324"),
                ],
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-synth-data-worker-32-64:v11": EnclaveSpecification(
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "4b5c2949eddbe215607a81df61ba75084e705922c76af792d39e437c4ef1f33cc64e04d4bbd40e395bcc3d4bf8daef70"
                ),
                roughtimePubKey=roughtime_public_key,
                authorizedChipIds=[
                    bytes.fromhex("372499d1b652b98aa1cde6d146136ad2b3e8f93b8223c367087577a73b76813928ad25545327032f7dc44a288965eb8e7f16179dbdb3a71fddc36cc19478ce47"),
                    bytes.fromhex("ce8a61aea3f76bbdd05706bcbfb4ade4c65b33ad41f49d0e89dec177951117d247781a3195de2e85399b7117d9eee2f6f2c2e5d21064a4d7e2815380212f0937"),
                    bytes.fromhex("86185338a275af6b5e26e06a21b4e0c65db0fc9033e4a24e27cb528321726dc152f28b08c05493c48e8fba3047aba6f0a0dd01d3eebb055b3318c1029c0a74ee"),
                    bytes.fromhex("7d2e30af8f43cc6de4e6c3ee59a7ab0d9ddfbff4caba3de0e54430215bd640c571d0e4b49d0cd1502fa74ae8a59475fe06dd9e7635500d584478e13f1191dc27"),
                    bytes.fromhex("02926acb4dab55b176946d75e5955154b11269dd8bfe7ff7bcd162b26ea47d8b9557bebd927e90667e34e6dbf9f1bb3bff4bdd36f41d2b755cccabf50270e324"),
                ],
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.python-synth-data-worker-32-64:v12": EnclaveSpecification(
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
    "decentriq.r-latex-worker-32-32:v10": EnclaveSpecification(
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "5f0a74f6c0633d9d4781d8c112617ce386507b86869b341a89b2183c8e41f01032c3ec9821567530f023f26c0f8a846d"
                ),
                roughtimePubKey=roughtime_public_key,
                authorizedChipIds=[
                    bytes.fromhex("372499d1b652b98aa1cde6d146136ad2b3e8f93b8223c367087577a73b76813928ad25545327032f7dc44a288965eb8e7f16179dbdb3a71fddc36cc19478ce47"),
                    bytes.fromhex("ce8a61aea3f76bbdd05706bcbfb4ade4c65b33ad41f49d0e89dec177951117d247781a3195de2e85399b7117d9eee2f6f2c2e5d21064a4d7e2815380212f0937"),
                    bytes.fromhex("86185338a275af6b5e26e06a21b4e0c65db0fc9033e4a24e27cb528321726dc152f28b08c05493c48e8fba3047aba6f0a0dd01d3eebb055b3318c1029c0a74ee"),
                    bytes.fromhex("7d2e30af8f43cc6de4e6c3ee59a7ab0d9ddfbff4caba3de0e54430215bd640c571d0e4b49d0cd1502fa74ae8a59475fe06dd9e7635500d584478e13f1191dc27"),
                    bytes.fromhex("02926acb4dab55b176946d75e5955154b11269dd8bfe7ff7bcd162b26ea47d8b9557bebd927e90667e34e6dbf9f1bb3bff4bdd36f41d2b755cccabf50270e324"),
                ],
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.r-latex-worker-32-32:v11": EnclaveSpecification(
        proto=AttestationSpecification(
            amdSnp=AttestationSpecificationAmdSnp(
                amdArkDer=amd_snp_ark_der,
                measurement=bytes.fromhex(
                    "de88718b50772045dd4427f0a7b83e80aa5c6a4e33664b88bc37e9663677d724bb3708ede4fca930506f344662141997"
                ),
                roughtimePubKey=roughtime_public_key,
                authorizedChipIds=[
                    bytes.fromhex("372499d1b652b98aa1cde6d146136ad2b3e8f93b8223c367087577a73b76813928ad25545327032f7dc44a288965eb8e7f16179dbdb3a71fddc36cc19478ce47"),
                    bytes.fromhex("ce8a61aea3f76bbdd05706bcbfb4ade4c65b33ad41f49d0e89dec177951117d247781a3195de2e85399b7117d9eee2f6f2c2e5d21064a4d7e2815380212f0937"),
                    bytes.fromhex("86185338a275af6b5e26e06a21b4e0c65db0fc9033e4a24e27cb528321726dc152f28b08c05493c48e8fba3047aba6f0a0dd01d3eebb055b3318c1029c0a74ee"),
                    bytes.fromhex("7d2e30af8f43cc6de4e6c3ee59a7ab0d9ddfbff4caba3de0e54430215bd640c571d0e4b49d0cd1502fa74ae8a59475fe06dd9e7635500d584478e13f1191dc27"),
                    bytes.fromhex("02926acb4dab55b176946d75e5955154b11269dd8bfe7ff7bcd162b26ea47d8b9557bebd927e90667e34e6dbf9f1bb3bff4bdd36f41d2b755cccabf50270e324"),
                ],
            )
        ),
        workerProtocols=[1],
        decoder=ContainerWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.r-latex-worker-32-32:v12": EnclaveSpecification(
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
    "decentriq.s3-sink-worker:v2": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "963ca160598716c0c94722a8b376b5b647302cc369c0344b2f3bae3dfb1e8eb3"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=S3SinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.s3-sink-worker:v3": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "09c34e9750a6e18ec7b18d633a5ffb5533c9d5be2bf896eb280717e3da4f2024"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=S3SinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.dataset-sink-worker:v1": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "3ffc8524bfc85837340ebfaabe4775f498b5040bbd84f30dcf62f2b1f86a61f4"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DatasetSinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.dataset-sink-worker:v2": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "971a45b16095ee1dbff897d42058fa1c1b024d2a2ea2267deda1575f6be21e86"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DatasetSinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.dataset-sink-worker:v3": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "bcb7afdc6bc64e638b44047515e3a8a4b8445282fee342fb9666f0531cd6fca4"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DatasetSinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.data-source-s3-worker:v1": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "67b8fe452b4724d85e81210f163936dc3ad1cf9c8602939a27ebe9afa00673ff"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DataSourceS3WorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.data-source-s3-worker:v2": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "f3e7b026ecd80b766bf3073b0aabcae4f55f91611c8de9cba8e671f1b9597ad7"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DataSourceS3WorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.data-source-snowflake-worker:v1": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "303f2c98573b322a06b88fbebd05db398607aac0a04023e0cb8d80ea822cfd3e"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DataSourceSnowflakeWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.data-source-snowflake-worker:v2": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "0ce5941c05297438d256c5d409afc3f444b09f6bf5a145accbc83525a68459ec"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=DataSourceSnowflakeWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.meta-sink-worker:v1": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "b1cc081fa868d6acb4293ff3b287c3da075d11ce2e1eeeb692e311eac9711fff"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=MetaSinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.meta-sink-worker:v2": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "7d73f04c12338eafc8cc01747ee1817f2cf86d87ca435c27beda965f5ecd2d77"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=MetaSinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.google-dv-360-sink-worker:v1": EnclaveSpecification(
        proto=AttestationSpecification(
            intelDcap=AttestationSpecificationIntelDcap(
                mrenclave=bytes.fromhex(
                    "3a00807af2ec87b9de3760188d112c494dd1a41877fbae30ecebb607ceafa3e7"
                ),
                dcapRootCaDer=intel_sgx_dcap_root_ca_der,
                accept_debug=False,
                accept_out_of_date=False,
                accept_configuration_needed=False,
                accept_revoked=False,
            )
        ),
        workerProtocols=[1],
        decoder=GoogleDv360SinkWorkerDecoder(),
        clientProtocols=None,
    ),
    "decentriq.sqlite-container-worker-32-64:v1": EnclaveSpecification(
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
