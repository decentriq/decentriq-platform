"""
.. include:: ../../decentriq_platform_docs/gcg_getting_started.md
___
"""

from . import (
    analytics,
    data_lab,
    legacy,
    lookalike_media,
    session,
    types,
    authentication,
)
from .attestation import EnclaveSpecifications, enclave_specifications
from .client import Client, Session, create_client
from .endorsement import Endorser
from .keychain import Keychain, KeychainEntry
from .storage import Key

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
