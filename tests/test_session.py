import os
from decentriq_platform import Client, SessionOptions, VerificationOptions

def test_session_creation():
    api_token = os.environ["TEST_API_TOKEN_1"]
    user_email = os.environ["TEST_USER_ID_1"]
    client_id = os.environ["DECENTRIQ_CLIENT_ID"]

    client = Client(api_token=api_token, client_id=client_id)
    enclave_identifier = client.get_enclave_identifiers()[0]

    auth = client.create_auth(user_email)
    client.create_session(enclave_identifier, {"role": auth}, SessionOptions(

        VerificationOptions(
            accept_debug=True,
            accept_group_out_of_date=True,
            accept_configuration_needed=True
            )
        )
    )
