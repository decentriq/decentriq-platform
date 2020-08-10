import os

from avato.client import Client
from avato.storage import FileFormat

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, "fixtures")
user_email = os.environ["TEST_USER_ID_1"]

client = Client(
    api_token=os.environ["TEST_API_TOKEN_1"],
    instance_types=[],
)


def test_ingestion_complete():
    client.get_user_files_collection(user_email)
    uploaded_file = client.upload_user_file(
            user_email,
            "test.csv",
            os.path.join(fixtures_dir, "test.csv"),
            FileFormat.CSV
        )
    assert uploaded_file.get("id") in list(
            map(lambda x: x.get("id"), client.get_user_files_collection(user_email)))

    requested_file = client.get_user_file(user_email, uploaded_file.get("id"))
    assert requested_file == uploaded_file

    client.delete_user_file(user_email, uploaded_file.get("id"))
    assert uploaded_file.get("id") not in list(
            map(lambda x: x.get("id"), client.get_user_files_collection(user_email)))