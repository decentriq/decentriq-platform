import os
from avato import Client

client = Client(
    username=os.environ["TEST_USER_ID"], password=os.environ["TEST_USER_PASSWORD"]
)


def test_user_does_exist():
    assert client.check_user_exists("avato@decentriq.ch") == True


def test_user_does_not_exist():
    assert client.check_user_exists("test@test.com") == False
