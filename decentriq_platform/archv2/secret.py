from dataclasses import dataclass
from decentriq_dcr_compiler.schemas.secret_store_entry_state import SecretStoreEntryState

@dataclass
class Secret:
    secret: bytes
    state: SecretStoreEntryState