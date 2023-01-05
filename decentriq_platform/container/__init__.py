"""
.. include:: ../../../decentriq_platform_docs/container_getting_started.md
___
"""
__docformat__ = "restructuredtext"
__pdoc__ = {
    "compute": False,
    "helpers": False,
    "proto": False,
}

from .compute import StaticContainerCompute
from .helpers import read_result_as_zipfile


__all__ = [
    "StaticContainerCompute",
    "read_result_as_zipfile",
]
