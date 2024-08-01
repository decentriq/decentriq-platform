from __future__ import annotations

from google.protobuf.json_format import MessageToDict

from .proto import (
    AzureBlobStorageWorkerConfiguration,
    ContainerWorkerConfiguration,
    DatasetSinkWorkerConfiguration,
    DataSourceS3WorkerConfiguration,
    DataSourceSnowflakeWorkerConfiguration,
    DriverTaskConfig,
    GoogleAdManagerWorkerConfiguration,
    GoogleDv360SinkWorkerConfiguration,
    MetaSinkWorkerConfiguration,
    PermutiveWorkerConfiguration,
    PostWorkerConfiguration,
    S3SinkWorkerConfiguration,
    SalesforceWorkerConfiguration,
    SqlWorkerConfiguration,
    MicrosoftDspWorkerConfiguration,
    AdformDspWorkerConfiguration,
    parse_length_delimited,
)


class GcgDriverDecoder:
    def decode(self, config: bytes):
        config_decoded = DriverTaskConfig()
        parse_length_delimited(config, config_decoded)
        config_decoded_json = MessageToDict(config_decoded)
        if config_decoded.HasField("staticContent"):
            content = config_decoded.staticContent.content.decode("utf-8")
            config_decoded_json["staticContent"]["content"] = content
        return config_decoded_json


class PostWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = PostWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


class AzureBlobStorageWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = AzureBlobStorageWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


class ContainerWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = ContainerWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


class DataSourceS3WorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = DataSourceS3WorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


class DataSourceSnowflakeWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = DataSourceSnowflakeWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


class DatasetSinkWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = DatasetSinkWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


class GoogleAdManagerWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = GoogleAdManagerWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


class GoogleDv360SinkWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = GoogleDv360SinkWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


class MetaSinkWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = MetaSinkWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


class PermutiveWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = PermutiveWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


class S3SinkWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = S3SinkWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


class DataSourceSalesforceWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = SalesforceWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


class SqlWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = SqlWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


class MicrosoftDspWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = MicrosoftDspWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)


class AdformDspWorkerDecoder:
    def decode(self, config: bytes):
        config_decoded = AdformDspWorkerConfiguration()
        parse_length_delimited(config, config_decoded)
        return MessageToDict(config_decoded)