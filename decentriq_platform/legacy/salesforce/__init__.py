from enum import Enum

from google.protobuf.json_format import MessageToDict

from ...proto import (
    ComputeNodeFormat,
    parse_length_delimited,
    serialize_length_delimited,
)
from ..node import Node
from .proto import Core, ImportRole, MarketingCloud, SalesforceWorkerConfiguration


class ProductType(Enum):
    CORE = 1
    MARKETING_CLOUD = 2


class DataSourceSalesforce(Node):
    """
    Compute node that fetches a dataset from Salesforce.
    """

    def __init__(
        self,
        name: str,
        credentialsDependency: str,
        domainUrl: str,
        apiName: str,
        productType: ProductType,
    ) -> None:
        importRole = (
            ImportRole(core=Core())
            if productType == ProductType.CORE
            else ImportRole(marketingCloud=MarketingCloud())
        )
        config = SalesforceWorkerConfiguration(
            credentialsDependency=credentialsDependency,
            importRole=importRole,
            domainUrl=domainUrl,
            apiName=apiName,
        )
        config_serialized = serialize_length_delimited(config)
        super().__init__(
            name,
            config=config_serialized,
            enclave_type="decentriq.salesforce-worker",
            dependencies=[credentialsDependency],
            output_format=ComputeNodeFormat.RAW,
        )


class DataSourceSalesforceWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = SalesforceWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


__all__ = [
    "DataSourceSalesforce",
]
