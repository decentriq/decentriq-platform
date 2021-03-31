import os
from decentriq_platform import Client

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, "fixtures")
user_email = os.environ["TEST_USER_ID_1"]
api_token = os.environ["TEST_API_TOKEN_1"]

def test_get_root_certificate():
    client = Client(api_token=api_token)
    client.get_ca_root_certificate()

def test_create_session_auth():
    client = Client(api_token=api_token)
    client.create_auth(user_email)
