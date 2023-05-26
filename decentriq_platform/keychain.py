from __future__ import annotations
import typing
from typing import Dict, Literal, Optional, Union, Tuple, List
from .client import Client, KeychainInstance
import cbor2
import chily
from base64 import b64encode

KeychainEntryKind = Literal["dataset_key", "other_secret"]

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
        if splitted[0] not in typing.get_args(KeychainEntryKind):
            raise Exception(f"Invalid namespaced key kind: found {splitted[0]}")
        remainder = "/".join(splitted[1:])
        return [splitted[0], remainder]

    @staticmethod    
    def _encrypt_store_static(
            user_email: str,
            secret_wrapper: chily.SecretWrapper,
            store: Dict[str, bytes]
    ) -> bytes:
        return secret_wrapper.wrap_secret(user_email, Keychain._serialize_store(store))

    def _encrypt_store(
            self,
    ):
        self._keychain_instance["encrypted"] = Keychain._encrypt_store_static(
            self._client.user_email,
            self._secret_wrapper,
            self._store
        )

    @staticmethod
    def _decrypt_store_static(
            user_email: str,
            secret_wrapper: chily.SecretWrapper,
            encrypted: bytes
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
            self._keychain_instance["encrypted"]
        )

    def _set_keychain_instance(self, keychain_instance: KeychainInstance):
        self._keychain_instance = keychain_instance
        self._decrypt_store()

    def _set_store(self, store: Dict[str, bytes]):
        self._store = store
        self._encrypt_store()

    def _init_keychain_instance(client: Client) -> KeychainInstance:
        keychain_instance = client.get_keychain_instance()
        if not keychain_instance:
            raise Exception("Cannot init Keychain, no instance exists in the server, create a new instance first")
        return keychain_instance
    
    def _has_keychain_instance(client: Client) -> bool:
        keychain_instance = client.get_keychain_instance()
        return bool(keychain_instance)
    
    def _create_new_keychain_with_secret_wrapper(
            client: Client,
            secret_wrapper: chily.SecretWrapper
    ) -> Optional[Keychain]:
        if (Keychain._has_keychain_instance(client)):
            return None
        store: Dict[str, bytes] = {}
        encrypted = secret_wrapper.wrap_secret(client.user_email, Keychain._serialize_store(store))
        keychain_instance = client.create_keychain_instance(secret_wrapper.salt, encrypted)
        return Keychain(client, secret_wrapper, keychain_instance, store)
    
    def create_new_keychain(client: Client, password: bytes) -> Keychain:
        secret_wrapper = chily.SecretWrapper.init(password)
        return Keychain._create_new_keychain_with_secret_wrapper(client, secret_wrapper)
    
    def create_new_keychain_with_master_key(
            client: Client,
            master_key: bytes,
            salt: str,
    ) -> Optional[Keychain]:
        secret_wrapper = chily.SecretWrapper.with_master_key(master_key, salt)
        return Keychain._create_new_keychain_with_secret_wrapper(client, secret_wrapper)

    def init_with_master_key(client: Client, master_key: bytes) -> Keychain:
        keychain_instance = Keychain._init_keychain_instance(client)
        secret_wrapper = chily.SecretWrapper.with_master_key(master_key, keychain_instance["salt"])
        store = Keychain._decrypt_store_static(client.user_email, secret_wrapper, keychain_instance["encrypted"])
        return Keychain(client, secret_wrapper, keychain_instance, store)

    def init_with_password(client: Client, password: bytes) -> Keychain:
        keychain_instance = Keychain._init_keychain_instance(client)
        secret_wrapper = chily.SecretWrapper.with_password(password, keychain_instance["salt"])
        store = Keychain._decrypt_store_static(client.user_email, secret_wrapper, keychain_instance["encrypted"])
        return Keychain(client, secret_wrapper, keychain_instance, store)
    
    def _download(self):
        keychain_instance = self._client.get_keychain_instance()
        if not keychain_instance:
            raise Exception("Keychain instance has not been created yet")
        
        if self._secret_wrapper.salt != keychain_instance["salt"]:
            raise Exception("Keychain salt has changed upstream. Reinitialize Keychain with password first")
        
        if keychain_instance["casIndex"] != self._keychain_instance["casIndex"]:
            self._set_keychain_instance(keychain_instance)
        return
        
    def get(self, kind: KeychainEntryKind, key: str) -> Optional[KeychainEntry]:
        self._download()
        ns_key = self._namespaced_key(kind, key)
        value = self._store.get(ns_key)
        if value:
            return KeychainEntry(kind, key, value)
        else:
            return None
        
    def items(self) -> List[KeychainEntry]:
        self._download()
        items = []
        for ns_key, value in self._store.items():
            kind, key = Keychain._parse_namespaced_key(ns_key)
            items.append(KeychainEntry(kind, key, value))
        return items
    
    def _insert_local(self, entry: KeychainEntry):
        ns_key = self._namespaced_key(entry.kind, entry.key)
        if self._store.get(ns_key):
            raise Exception("Cannot insert new entry: an entry already exists for this (kind, key) pair")
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
            
    def reset(client: Client):
        return client.reset_keychain()
    
    def clear(self):
        while True:
            self._set_store({})
            if self._compare_and_swap():
                return
            self._download()

    def change_password(self, new_password: bytes):
        new_secret_wrapper = chily.SecretWrapper.with_password(new_password, self._secret_wrapper.salt)
        return self.change_master_key(new_secret_wrapper.master_key)
    
    def change_master_key(self, new_master_key: bytes):
        new_secret_wrapper = chily.SecretWrapper.with_master_key(new_master_key, self._secret_wrapper.salt)
        while True:
            new_keychain = Keychain(self._client, new_secret_wrapper, self._keychain_instance, self._store)
            new_keychain._encrypt_store()
            if new_keychain._compare_and_swap():
                self = new_keychain
                return
            self._download()

    def get_master_key(self) -> bytes:
        return self._secret_wrapper.master_key