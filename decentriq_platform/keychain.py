from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Literal, Optional, Tuple, get_args
from typing_extensions import Self

if TYPE_CHECKING:
    from .client import Client, KeychainInstance

import cbor2
import chily

KeychainEntryKind = Literal[
    "dataset_key",
    "other_secret",
    "dataset_metadata",
    "pending_dataset_import",
]


class KeychainEntry:
    kind: KeychainEntryKind
    key: str
    value: bytes

    def __init__(self, kind: KeychainEntryKind, key: str, value: bytes):
        self.kind = kind
        self.key = key
        self.value = value


class KeychainDecryptException(Exception):
    def __init__(self) -> None:
        super().__init__()


def _convert_binary_type(value):
    """
    The JS implementation of the keychain deals with keys in terms
    of Uint8Arrays that are encoded to the CBOR type with tag number 64 (= "uint8 typed arrays").
    Python's cbor2 transates bytestrings into the CBOR  "byte string" type (tag nr. 2),
    which are read as Uint8Arrays by JS. The issue arises with Python
    reading values of type "uint8 typed arrays".

    See: https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml
    """
    if value and isinstance(value, cbor2.CBORTag) and value.tag == 64:
        return value.value # this will be a simple bytestring
    else:
        return value


class Keychain:
    _client: Client
    _store: Dict[str, bytes]
    _secret_wrapper: chily.SecretWrapper
    _keychain_instance: KeychainInstance

    def __init__(
        self,
        client: Client,
        secret_wrapper: chily.SecretWrapper,
        keychain_instance: KeychainInstance,
        store: Dict[str, bytes],
    ):
        self._client = client
        self._store = store
        self._secret_wrapper = secret_wrapper
        self._keychain_instance = keychain_instance

    @staticmethod
    def _serialize_store(store: Dict[str, bytes]) -> bytes:
        return cbor2.dumps(store, value_sharing=False)

    @staticmethod
    def _deserialize_store(plaintext: bytes) -> Dict[str, bytes]:
        return cbor2.loads(plaintext)

    def _namespaced_key(self, kind: KeychainEntryKind, key: str) -> str:
        return f"{kind}/{key}"

    @staticmethod
    def _parse_namespaced_key(ns_key: str) -> Tuple[KeychainEntryKind, str]:
        splitted = ns_key.split("/")
        if len(splitted) < 2:
            raise Exception("Invalid namespaced key: no `/` found")
        if splitted[0] not in get_args(KeychainEntryKind):
            raise Exception(f"Invalid namespaced key kind: found {splitted[0]}")
        remainder = "/".join(splitted[1:])
        return [splitted[0], remainder]

    @staticmethod
    def _encrypt_store_static(
        user_email: str, secret_wrapper: chily.SecretWrapper, store: Dict[str, bytes]
    ) -> bytes:
        return secret_wrapper.wrap_secret(user_email, Keychain._serialize_store(store))

    def _encrypt_store(
        self,
    ):
        self._keychain_instance["encrypted"] = Keychain._encrypt_store_static(
            self._client.user_email, self._secret_wrapper, self._store
        )

    @staticmethod
    def _decrypt_store_static(
        user_email: str, secret_wrapper: chily.SecretWrapper, encrypted: bytes
    ) -> Dict[str, bytes]:
        try:
            decrypted = secret_wrapper.unwrap_secret(user_email, encrypted)
        except:
            raise KeychainDecryptException()
        return Keychain._deserialize_store(decrypted)

    def _decrypt_store(self):
        self._store = Keychain._decrypt_store_static(
            self._client.user_email,
            self._secret_wrapper,
            self._keychain_instance["encrypted"],
        )

    def _set_keychain_instance(self, keychain_instance: KeychainInstance):
        self._keychain_instance = keychain_instance
        self._decrypt_store()

    def _set_store(self, store: Dict[str, bytes]):
        self._store = store
        self._encrypt_store()

    @staticmethod
    def _init_keychain_instance(client: Client) -> KeychainInstance:
        keychain_instance = client.get_keychain_instance()
        if not keychain_instance:
            raise Exception(
                "Cannot init Keychain, no instance exists in the server, create a new instance first"
            )
        return keychain_instance

    @staticmethod
    def _has_keychain_instance(client: Client) -> bool:
        keychain_instance = client.get_keychain_instance()
        return bool(keychain_instance)

    @staticmethod
    def _create_new_keychain_with_secret_wrapper(
        client: Client,
        secret_wrapper: chily.SecretWrapper,
        check_for_existing_keychain: bool = True,
    ) -> Optional[Keychain]:
        if check_for_existing_keychain and Keychain._has_keychain_instance(client):
            return None
        store: Dict[str, bytes] = {}
        encrypted = secret_wrapper.wrap_secret(
            client.user_email, Keychain._serialize_store(store)
        )
        keychain_instance = client.create_keychain_instance(
            secret_wrapper.salt, encrypted
        )
        return Keychain(client, secret_wrapper, keychain_instance, store)

    @staticmethod
    def create_new_keychain(
        client: Client,
        password: bytes,
        check_for_existing_keychain: bool = True,
    ) -> Optional[Self]:
        """
        Create a new keychain that is encrypted using the given password.

        If the user already has a keychain setup (for example by already having
        logged into the Decentriq UI), this method will return None.

        See the method `get_or_create_unlocked_keychain` for a convenience
        method that will not throw an error if the keychain already exists.
        """
        secret_wrapper = chily.SecretWrapper.init(password)
        return Keychain._create_new_keychain_with_secret_wrapper(
            client, secret_wrapper, check_for_existing_keychain
        )

    @staticmethod
    def get_or_create_unlocked_keychain(
        client: Client,
        password: bytes,
    ) -> Self:
        """
        Get and unlock the user's keychain using the provided password.

        If the user did not already create a keychain, a new keychain will
        be created automatically.
        If a keychain exists but the provided password does not match,
        an exception will be thrown.

        Note that the password must be given as a `bytes` object.
        """
        keychain_instance = client.get_keychain_instance()
        if not keychain_instance:
            keychain = Keychain.create_new_keychain(
                client,
                password,
                check_for_existing_keychain=False,
            )
            if keychain:
                keychain._decrypt_store()
            else:
                raise Exception(
                    "Received an undefined keychain even though it should exist"
                )
            return keychain
        else:
            return Keychain._decrypt_store_with_password(
                client, keychain_instance, password
            )

    @staticmethod
    def create_new_keychain_with_master_key(
        client: Client,
        master_key: bytes,
        salt: str,
    ) -> Optional[Self]:
        """
        Create a new keychain with the given master key.

        If the user already has a keychain setup (for example by already having
        logged into the Decentriq UI), this method will return None.
        """
        secret_wrapper = chily.SecretWrapper.with_master_key(master_key, salt)
        return Keychain._create_new_keychain_with_secret_wrapper(client, secret_wrapper)

    @staticmethod
    def init_with_master_key(client: Client, master_key: bytes) -> Self:
        """
        Decrypt an existing keychain with the given master key.

        If no keychain has been created already or if the key
        does not match the keychain, an error will be thrown.

        See the method `get_or_create_unlocked_keychain` for a convenience
        method that will create the keychain if it does not exist already.
        """
        keychain_instance = Keychain._init_keychain_instance(client)
        secret_wrapper = chily.SecretWrapper.with_master_key(
            master_key, keychain_instance["salt"]
        )
        store = Keychain._decrypt_store_static(
            client.user_email, secret_wrapper, keychain_instance["encrypted"]
        )
        return Keychain(client, secret_wrapper, keychain_instance, store)

    @staticmethod
    def init_with_password(client: Client, password: bytes) -> Self:
        """
        Decrypt an existing keychain with the given password.

        If no keychain has been created already or if the password
        does not match the keychain, an error will be thrown.

        See the method `get_or_create_unlocked_keychain` for a convenience
        method that will create the keychain if it does not exist already.
        """
        keychain_instance = Keychain._init_keychain_instance(client)
        return Keychain._decrypt_store_with_password(
            client, keychain_instance, password
        )

    @staticmethod
    def _decrypt_store_with_password(
        client: Client, keychain_instance: KeychainInstance, password: bytes
    ) -> Self:
        secret_wrapper = chily.SecretWrapper.with_password(
            password, keychain_instance["salt"]
        )
        store = Keychain._decrypt_store_static(
            client.user_email, secret_wrapper, keychain_instance["encrypted"]
        )
        return Keychain(client, secret_wrapper, keychain_instance, store)

    def _download(self):
        keychain_instance = self._client.get_keychain_instance()
        if not keychain_instance:
            raise Exception("Keychain instance has not been created yet")

        if self._secret_wrapper.salt != keychain_instance["salt"]:
            raise Exception(
                "Keychain salt has changed upstream. Reinitialize Keychain with password first"
            )

        if keychain_instance["casIndex"] != self._keychain_instance["casIndex"]:
            self._set_keychain_instance(keychain_instance)
        return

    def get(self, kind: KeychainEntryKind, key: str) -> Optional[KeychainEntry]:
        self._download()
        ns_key = self._namespaced_key(kind, key)
        value = self._store.get(ns_key)
        if value:
            return KeychainEntry(kind, key, _convert_binary_type(value))
        else:
            return None

    def items(self) -> List[KeychainEntry]:
        self._download()
        items = []
        for ns_key, value in self._store.items():
            kind, key = Keychain._parse_namespaced_key(ns_key)
            items.append(KeychainEntry(kind, key, _convert_binary_type(value)))
        return items

    def _insert_local(self, entry: KeychainEntry):
        ns_key = self._namespaced_key(entry.kind, entry.key)
        if self._store.get(ns_key):
            raise Exception(
                "Cannot insert new entry: an entry already exists for this (kind, key) pair"
            )
        if entry.kind in ["dataset_key", "other_secret"]:
            self._store[ns_key] = entry.value
        else:
            raise Exception(f"Invalid entry kind: {entry.kind}")
        self._encrypt_store()
        return

    def _compare_and_swap(self) -> bool:
        return self._client.compare_and_swap_keychain(
            self._keychain_instance["casIndex"],
            self._keychain_instance["salt"],
            self._keychain_instance["encrypted"],
        )

    def insert(self, entry: KeychainEntry):
        while True:
            self._insert_local(entry)
            if self._compare_and_swap():
                return
            self._download()

    def remove(self, kind: KeychainEntryKind, key: str):
        ns_key = self._namespaced_key(kind, key)
        while True:
            if self._store.pop(ns_key):
                self._encrypt_store()
                if self._compare_and_swap():
                    return
                self._download()
            else:
                raise Exception("Cannot delete entry: Entry does not exist")

    @staticmethod
    def reset(client: Client):
        return client.reset_keychain()

    def clear(self):
        while True:
            self._set_store({})
            if self._compare_and_swap():
                return
            self._download()

    def change_password(self, new_password: bytes):
        new_secret_wrapper = chily.SecretWrapper.with_password(
            new_password, self._secret_wrapper.salt
        )
        return self.change_master_key(new_secret_wrapper.master_key)

    def change_master_key(self, new_master_key: bytes):
        new_secret_wrapper = chily.SecretWrapper.with_master_key(
            new_master_key, self._secret_wrapper.salt
        )
        while True:
            new_keychain = Keychain(
                self._client, new_secret_wrapper, self._keychain_instance, self._store
            )
            new_keychain._encrypt_store()
            if new_keychain._compare_and_swap():
                self.__dict__.update(new_keychain.__dict__)
                return
            self._download()

    def get_master_key(self) -> bytes:
        return self._secret_wrapper.master_key
