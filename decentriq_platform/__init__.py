"""
.. include:: ../../decentriq_platform_docs/gcg_getting_started.md
---
"""
__docformat__ = "restructuredtext"

from .types import JobId
from .client import Client, create_client, Session
from .platform import ClientPlatformFeatures
from .builders import DataRoomBuilder
from .compute import Noop, StaticContent
from .permission import Permissions
from .storage import Key
from .attestation import enclave_specifications, EnclaveSpecifications


__all__ = [
    "create_client",
    "Client",
    "Session",
    "ClientPlatformFeatures",
    "DataRoomBuilder",
    "Permissions",
    "enclave_specifications",
    "EnclaveSpecifications",
    "Key",
    "StaticContent",
    "Noop",
    "JobId",
    "sql",
    "container",
]
