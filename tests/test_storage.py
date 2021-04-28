import json
import pytest
import os
from decentriq_platform import Client, Key, Schema
from google.protobuf.json_format import MessageToJson

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, "fixtures")

def test_key_generation():
    key = Key(bytes(32), bytes(16))
    assert key.id == bytes([
        132,  74,  24, 239,  16, 147, 241,  93,
        166, 255,  74,  72,  81,  88, 211,  36,
        213,  96, 105, 184,  63, 178, 111, 128,
        252,  23, 186,  89, 161, 230,   9, 102
        ])

    
def test_schema_parsing():
    with pytest.raises(Exception, match="No CREATE TABLE statements found"):
        Schema("")

    schema = Schema(
            "CREATE TABLE data_provider_table ("
            + "name TEXT,"
            + "salary BIGINT NOT NULL"
            + ")"
    )
    assert schema.table_name == "data_provider_table"
    assert json.loads(MessageToJson(schema.proto_schema)) == {
            "namedColumns": [
                {
                    "columnType": {
                        "primitiveType": "STRING",
                        "nullable": True,
                    },
                    "name": "name",
                    },
                {
                    "columnType": {
                        "primitiveType": "INT64",
                        "nullable": False,
                    },
                    "name": "salary",
                    },
                ],
            }


def test_dataset_uploading():
    user_email = os.environ["TEST_USER_ID_1"]
    api_token = os.environ["TEST_API_TOKEN_1"]
    client_id = os.environ["DECENTRIQ_CLIENT_ID"]

    client = Client(api_token=api_token, client_id=client_id)
    schema = Schema(
            "CREATE TABLE data_provider_table ("
            + "name TEXT NOT NULL,"
            + "salary BIGINT NOT NULL"
            + ")"
    )
    encryption_key = Key()

    with open(os.path.join(fixtures_dir, "data.csv"), "r", buffering=1024 ** 2) as data_stream:
        client.upload_dataset(
                email=user_email,
                name="Test dataset",
                csv_input_stream=data_stream,
                schema=schema,
                key=encryption_key,
        )
