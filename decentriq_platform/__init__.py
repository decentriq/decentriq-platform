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
    data_connectors,
    ab_media,
)
from .attestation import EnclaveSpecifications, enclave_specifications
from .client import Client, Session, create_client, SecretStoreOptions
from .endorsement import Endorser
from .storage import Key
from .archv2 import SessionV2, Secret

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
    "data_connectors": True,
    "ab_media": True,
}

__all__ = [
    "create_client",
    "Client",
    "Session",
    "enclave_specifications",
    "EnclaveSpecifications",
    "Key",
    "lookalike_media",
    "storage",
    "attestation",
    "types",
    "authentication",
    "session",
    "Endorser",
    "data_lab",
    "legacy",
    "analytics",
    "data_connectors",
    "ab_media",
    "SessionV2",
    "Secret",
    "SecretStoreOptions",
]
