import runpy
import os

os.environ["USER_MAIL_1"] = os.environ["TEST_USER_ID_1"]
os.environ["API_TOKEN_1"] = os.environ["TEST_API_TOKEN_1"]

os.environ["USER_MAIL_2"] = os.environ["TEST_USER_ID_2"]
os.environ["API_TOKEN_2"] = os.environ["TEST_API_TOKEN_2"]


def test_example():
    runpy.run_path("../example/demo.py", run_name="__main__")
