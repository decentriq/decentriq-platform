import os

from avato.client import Client
from avato.storage import ColumnType

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, "fixtures")
user_email = os.environ["TEST_USER_ID_1"]

client = Client(
    api_token=os.environ["TEST_API_TOKEN_1"],
    instance_types=[],
)


def test_ingestion_complete():
    client.get_user_files_collection(user_email)
    key = b'hellofriendhellofriendhelloworld'

    # Data provider uploads data source file
    uploaded_file = client.upload_csv_table(
        user_email,
        "test.csv",
        os.path.join(fixtures_dir, "test.csv"),
        schema=[
            ("year", ColumnType.INT64),
            ("industry_code_ANZSIC", ColumnType.STRING),
            ("industry_name_ANZSIC", ColumnType.STRING),
            ("rme_size_grp", ColumnType.STRING),
            ("variable", ColumnType.STRING),
            ("value", ColumnType.INT64),
            ("unit", ColumnType.STRING),
        ],
        extra_entropy=bytes(),  # TODO
        key=key,
    )
    assert uploaded_file.get("fileId") in list(
        map(lambda x: x.get("fileId"), client.get_user_files_collection(user_email)))

    requested_file = client.get_user_file(user_email, uploaded_file.get("fileId"))
    assert requested_file == uploaded_file

    client.delete_user_file(user_email, uploaded_file.get("fileId"))
    assert uploaded_file.get("fileId") not in list(
        map(lambda x: x.get("fileId"), client.get_user_files_collection(user_email)))
