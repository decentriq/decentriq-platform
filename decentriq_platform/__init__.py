"""
.. include:: ../../decentriq_platform_docs/gcg_getting_started.md
___
"""

from .client import Client, create_client, Session
from .storage import Key
from .attestation import enclave_specifications, EnclaveSpecifications

from .endorsement import Endorser
from .keychain import Keychain, KeychainEntry

from . import analytics
from . import lookalike_media
from . import legacy
from . import data_lab
from . import session

__docformat__ = "restructuredtext"

__pdoc__ = {
    "api": False,
    "attestation": True,
    "authentication": True,
    "builders": False,
    "certs": False,
    "client": False,
    "compute": False,
    "config": False,
    "graphql": False,
    "helpers": False,
    "proto": False,
    "lookalike_media": True,
    "session": False,
    "storage": False,
    "types": False,
    "verification": False,
    "data_lab": True,
    "legacy": True,
    "decoder": False,
}

__all__ = [
    "create_client",
    "Client",
    "Session",
    "enclave_specifications",
    "EnclaveSpecifications",
    "Key",
    "KeychainEntry",
    "lookalike_media",
    "storage",
    "attestation",
    "types",
    "authentication",
    "session",
    "Endorser",
    "Keychain",
    "data_lab",
    "legacy",
    "analytics",
]
