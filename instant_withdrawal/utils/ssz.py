from dataclasses import dataclass
from eth_utils import encode_hex, remove_0x_prefix
from hashlib import sha256
from ssz import (
    bytes48,
    bytes32,
    bytes96
)

@dataclass
class ValidatorProfileSigningMessage:
    pubkey: bytes48
    recipient: str
    domain: str

    def to_bytes(self):
        result = b''
        result += self.pubkey
        result += self.recipient.encode()
        result += self.domain.encode()
        return result

    @property
    def pubkey_hex(self):
        return remove_0x_prefix(encode_hex(self.pubkey))

    @property
    def msg_value(self):
        return f'{self.pubkey.hex()}(pubkey){self.recipient}(recipient){self.domain}(domain)'

    @property
    def msg_hash(self):
        return sha256(self.to_bytes()).digest()

    @property
    def msg_hash_hex(self):
        return remove_0x_prefix(encode_hex(self.msg_hash))

    def as_dict(self):
        return self.__dict__

@dataclass
class ValidatorProfileSignedData:
    pubkey: bytes48
    domain: bytes32
    recipient: bytes32
    signature: bytes96

    def to_bytes(self):
        result = b''
        result += self.pubkey
        result += self.recipient
        result += self.domain
        result += self.signature
        return result

    @property
    def signed_signature(self):
        return remove_0x_prefix(encode_hex(self.signature))

    def as_dict(self):
        return self.__dict__
