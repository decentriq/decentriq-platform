"""
.. include:: ../docs/getting_started.md

## The proto definitions

### DataRoom
```proto
.. include:: ../proto/data_room.proto
```

---

"""
__docformat__ = "restructuredtext"
from .client import Client

__all__ = ["Client", "session", "authentication", "storage", "proto", "types"]
