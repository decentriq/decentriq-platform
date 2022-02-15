"""
.. include:: ../../../decentriq_platform_docs/container_getting_started.md
---
"""
__docformat__ = "restructuredtext"

from .compute import StaticContainerCompute
from .attestation import EnclaveSpecification

__all__ = [
    "StaticContainerCompute",
    "EnclaveSpecification",
]
