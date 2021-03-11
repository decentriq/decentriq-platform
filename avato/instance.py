import chily
import json
from base64 import b64encode, b64decode
from abc import ABCMeta, abstractmethod
from functools import wraps
from .proto.encrypted_message import encode, decode
from .proto.avato_enclave_pb2 import Request, Response
from .proto.length_delimited import parse_length_delimited, serialize_length_delimited
from .verification import Verification, Fatquote
from .api import Endpoints
from .authentication import Pki, Sigma
import hkdf
import hashlib
import hmac

class MetaInstance(ABCMeta):
    @property
    def type(cls):
        return cls.get_type()


class Instance(metaclass=MetaInstance):
    class ValidFatquoteRequiredError(Exception):
        """Raised when calling a function that requires a valid fatquote"""

        pass

    class SecretRequiredError(Exception):
        """Raised when calling a function that requires an avato secret"""

        pass

    class AdminRequiredError(Exception):
        """Raised when calling a function that requires admin permissions"""

        pass

    class DataParsingError(Exception):
        """Raised when the data could not be parsed"""

        pass

    class DataSerializationError(Exception):
        """Raised when data serialization fails"""

        pass

    @classmethod
    @abstractmethod
    def get_type(cls):
        pass

    @property
    def type(self):
        return self.get_type()

    def __init__(self, client, id, owner, mrenclave):
        self.client = client
        self.id = id
        self.owner = owner
        self.mrenclave = mrenclave
        self.quote = None
        self.secret = None
        self.fatquote = None
        self.auth_pki = None

    def _valid_fatquote_required(f):
        @wraps(f)
        def wrapped(inst, *args, **kwargs):
            if not inst.quote:
                raise Instance.ValidFatquoteRequiredError
            return f(inst, *args, **kwargs)
        return wrapped

    def _secret_required(f):
        @wraps(f)
        def wrapped(inst, *args, **kwargs):
            if not inst.secret:
                raise Instance.SecretRequiredError
            return f(inst, *args, **kwargs)
        return wrapped

    def set_secret(self, secret):
        self.secret = secret

    def set_pki_auth(self, pki: Pki):
        self.auth_pki: Pki = pki

    def get_info(self):
        url = Endpoints.SESSION.replace(":instanceId", self.id)
        response = self.client.api.get(url)
        return response.json()

    def validate_fatquote(
        self,
        expected_measurement=None,
        accept_debug=False,
        accept_configuration_needed=False,
        accept_group_out_of_date=False,
    ):
        url = Endpoints.SESSION_FATQUOTE.replace(":instanceId", self.id)
        response = self.client.api.get(url)
        fatquote = response.json()
        certificate = fatquote["certificate"].encode("utf-8")
        message = fatquote["response"].encode("utf-8")
        signature = bytes(fatquote["signature"]["data"])
        self.fatquote = Fatquote(fatquote)
        verification = Verification(
            expected_measurement=expected_measurement,
            accept_debug=accept_debug,
            accept_configuration_needed=accept_configuration_needed,
            accept_group_out_of_date=accept_group_out_of_date,
        )
        self.quote = verification.verify(certificate, message, signature)

    @_valid_fatquote_required
    def _get_enclave_pubkey(self):
        pub_keyB = bytearray(self.quote.reportdata[:32])
        return chily.PublicKey.from_bytes(pub_keyB)

    def _encrypt_and_encode_data(self, data):
        nonce = chily.Nonce.from_random()
        cipher = chily.Cipher(
            self.secret.keypair.secret, self._get_enclave_pubkey()
        )
        enc_data = cipher.encrypt(data, nonce)
        sigma_auth = None
        if self.auth_pki is not None:
            public_keys = bytes(self.secret.keypair.public_key.bytes) + bytes(self._get_enclave_pubkey().bytes)
            signature = self.auth_pki.sign(public_keys)
            shared_key = bytes(self.secret.keypair.secret.diffie_hellman(self._get_enclave_pubkey()).bytes)
            kdf = hkdf.Hkdf(b'', shared_key, hash=hashlib.sha512)
            mac_key = kdf.expand(b"IdP KDF Context", 64)
            mac_tag = hmac.digest(mac_key, self.auth_pki.get_user_id().encode(), 'sha512')
            sigma_auth = Sigma(signature, mac_tag, self.auth_pki)
        return encode(
            bytes(enc_data),
            bytes(nonce.bytes),
            bytes(self.secret.keypair.public_key.bytes),
            sigma_auth=sigma_auth
        )

    def _decode_and_decrypt_data(self, data):
        dec_data, nonceB, _ = decode(data)
        cipher = chily.Cipher(
            self.secret.keypair.secret, self._get_enclave_pubkey()
        )
        return cipher.decrypt(dec_data, chily.Nonce.from_bytes(nonceB))

    def _send_message(self, message, response_object):
        encrypted = self._encrypt_and_encode_data(serialize_length_delimited(message))
        request = Request()
        request.avatoRequest = encrypted
        url = Endpoints.SESSION_COMMANDS.replace(":instanceId", self.id)
        serialized_request = serialize_length_delimited(request)
        enclave_message = {
            "data": b64encode(serialized_request).decode("ascii")
        }
        response = self.client.api.post(
            url, json.dumps(enclave_message), {"Content-type": "application/json"}
        )
        enclave_response = response.json()
        enclave_response_bytes: bytes = b64decode(enclave_response["data"])
        response_container = Response()
        parse_length_delimited(enclave_response_bytes, response_container)
        if response_container.HasField("unsuccessfulResponse"):
            raise Exception(response_container.unsuccessfulResponse)
        decrypted_response = self._decode_and_decrypt_data(response_container.successfulResponse)
        parse_length_delimited(decrypted_response, response_object)
