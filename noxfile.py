import os
import nox


@nox.session(python=["python3.6", "python3.7"])
def tests(session):
    env = {
        "TEST_USER_ID": os.environ["TEST_USER_ID"],
        "TEST_USER_PASSWORD": os.environ["TEST_USER_PASSWORD"],
    }
    session.install("pytest")
    session.run("pip", "install", ".")
    session.run("pytest", "tests/", env=env)
