import os
import setuptools

with open(os.path.join(os.path.dirname(__file__), "requirements.txt"), "r") as f:
    requirements = f.read().splitlines()

with open(os.path.join(os.path.dirname(__file__), "README.md"), "r") as f:
    long_description = f.read()

setuptools.setup(
    name="avato",  # Replace with your own username
    version="0.2.1",
    author="Enrico Ghirardi",
    author_email="enrico.ghirardi@decentriq.ch",
    description="Python client library for the avato platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    classifiers=["Programming Language :: Python :: 3"],
    python_requires=">=3.6",
    install_requires=requirements,
)
