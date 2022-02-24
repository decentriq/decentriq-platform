"""
.. include:: ../../../decentriq_platform_docs/container_getting_started.md
---
"""
__docformat__ = "restructuredtext"

from .compute import StaticContainerCompute
from .helpers import read_result_as_zipfile


__all__ = [
    "StaticContainerCompute",
    "read_result_as_zipfile",
]
