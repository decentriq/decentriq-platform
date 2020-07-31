import os
import nox


@nox.session(python=["python3.6", "python3.7", "python3.8"])
def tests(session):
    session.install("pytest")
    session.run("pip", "install", ".")
    session.run("pytest", "tests/")
