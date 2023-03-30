import binascii
import simplejson as json
import os
import time
import click
from enum import Enum
from typing import Dict, List, Optional
from eth_typing import Address, HexAddress
from eth_utils import to_canonical_address, encode_hex, to_checksum_address, remove_0x_prefix
from py_ecc.bls import G2ProofOfPossession as bls
from instant_withdrawal.key_handling.key_derivation.path import mnemonic_and_path_to_key
from instant_withdrawal.utils.click import pretty_text
from instant_withdrawal.utils.constants import BLS_WITHDRAWAL_PREFIX, ETH1_ADDRESS_WITHDRAWAL_PREFIX, PARASPACE_SIGN_DOMAIN, PARASPACE_SIGN_CLI_VERSION
from instant_withdrawal.utils.crypto import SHA256
from instant_withdrawal.utils.intl import load_text
from instant_withdrawal.utils.ssz import (
    ValidatorProfileSigningMessage,
    ValidatorProfileSignedData,
)


class WithdrawalType(Enum):
    BLS_WITHDRAWAL = 0
    ETH1_ADDRESS_WITHDRAWAL = 1


class ParaSpaceValidatorCredential:
    """
    A Credential object contains all of the information for a single validator and the corresponding functionality.
    Once created, it is the only object that should be required to perform any processing for a validator.
    """

    def __init__(self, *, mnemonic: str, mnemonic_password: str,
                 index: int, hex_eth1_withdrawal_address: Optional[HexAddress]):
        # Set path as EIP-2334 format
        # https://eips.ethereum.org/EIPS/eip-2334
        purpose = '12381'
        coin_type = '3600'
        account = str(index)
        withdrawal_key_path = f'm/{purpose}/{coin_type}/{account}/0'
        self.account_index = index
        self.signing_key_path = f'{withdrawal_key_path}/0'

        self.withdrawal_sk = mnemonic_and_path_to_key(
            mnemonic=mnemonic, path=withdrawal_key_path, password=mnemonic_password)
        self.signing_sk = mnemonic_and_path_to_key(
            mnemonic=mnemonic, path=self.signing_key_path, password=mnemonic_password)
        self.paraspace_sign_domain = PARASPACE_SIGN_DOMAIN
        self.hex_eth1_withdrawal_address = hex_eth1_withdrawal_address

    @property
    def signing_pk(self) -> bytes:
        return bls.SkToPk(self.signing_sk)

    @property
    def withdrawal_pk(self) -> bytes:
        return bls.SkToPk(self.withdrawal_sk)

    @property
    def eth1_withdrawal_address(self) -> Optional[Address]:
        if self.hex_eth1_withdrawal_address is None:
            return None
        return to_canonical_address(self.hex_eth1_withdrawal_address)

    @property
    def withdrawal_prefix(self) -> bytes:
        if self.eth1_withdrawal_address is not None:
            return ETH1_ADDRESS_WITHDRAWAL_PREFIX
        else:
            return BLS_WITHDRAWAL_PREFIX

    @property
    def withdrawal_type(self) -> WithdrawalType:
        if self.withdrawal_prefix == BLS_WITHDRAWAL_PREFIX:
            return WithdrawalType.BLS_WITHDRAWAL
        elif self.withdrawal_prefix == ETH1_ADDRESS_WITHDRAWAL_PREFIX:
            return WithdrawalType.ETH1_ADDRESS_WITHDRAWAL
        else:
            raise ValueError(
                f"Invalid withdrawal_prefix {self.withdrawal_prefix.hex()}")

    @property
    def withdrawal_credentials(self) -> bytes:
        if self.withdrawal_type == WithdrawalType.BLS_WITHDRAWAL:
            withdrawal_credentials = BLS_WITHDRAWAL_PREFIX
            withdrawal_credentials += SHA256(self.withdrawal_pk)[1:]
        elif (
            self.withdrawal_type == WithdrawalType.ETH1_ADDRESS_WITHDRAWAL
            and self.eth1_withdrawal_address is not None
        ):
            withdrawal_credentials = ETH1_ADDRESS_WITHDRAWAL_PREFIX
            withdrawal_credentials += b'\x00' * 11
            withdrawal_credentials += self.eth1_withdrawal_address
        else:
            raise ValueError(f"Invalid withdrawal_type {self.withdrawal_type}")
        return withdrawal_credentials

    @property
    def paraspace_sign_message(self) -> ValidatorProfileSigningMessage:
        return ValidatorProfileSigningMessage(
            pubkey=self.signing_pk,
            # encode_hex(),
            domain=self.paraspace_sign_domain,
            recipient=to_checksum_address(self.eth1_withdrawal_address),
            # withdrawal_credentials=encode_hex(self.withdrawal_credentials)
        )

    @property
    def paraspace_signed_data(self) -> ValidatorProfileSignedData:
        signed_data = ValidatorProfileSignedData(
            **self.paraspace_sign_message.as_dict(),
            signature=bls.Sign(
                self.signing_sk, self.paraspace_sign_message.msg_hash)
        )
        return signed_data

    @property
    def sign_datum_dict(self) -> Dict[str, bytes]:
        """
        Return a single sign datum for 1 validator including all
        the information needed to verify and process the signing.
        """
        msg = self.paraspace_sign_message
        datum_dict = {}
        datum_dict.update({'pubkey': msg.pubkey_hex})
        datum_dict.update({'recipient': msg.recipient})
        datum_dict.update({'domain': msg.domain})
        datum_dict.update(
            {'signature': self.paraspace_signed_data.signed_signature})
        datum_dict.update({'raw_msg_data': msg.raw_msg})
        datum_dict.update({'raw_msg_hash': msg.msg_hash_hex})
        datum_dict.update(
            {'paraspace_sign_cli_version': PARASPACE_SIGN_CLI_VERSION})
        return datum_dict

    def sign(self, msg: bytes) -> bytes:
        return bls.Sign(self.signing_sk, msg)

    def verify(self, msg: bytes, signature: bytes) -> bool:
        return bls.Verify(self.signing_pk, msg, signature)

    def __repr__(self):
        return f'ParaSpaceValidatorCredential({encode_hex(self.signing_pk)})' \
            f' with eth1_withdrawal_address={to_checksum_address(self.eth1_withdrawal_address)}' \
            f' and withdrawal_credentials={encode_hex(self.withdrawal_credentials)}'

    # def verify_withdrawal_address(self, withdrawal_address: Address) -> bool:
    #     if self.eth1_withdrawal_address is None:
    #         return False
    #     return self.eth1_withdrawal_address == withdrawal_address

    # def verify_keystore(self, keystore_file_folder: str, password: str) -> bool:
    #     saved_keystore = Keystore.from_file(keystore_file_folder)
    #     secret_bytes = saved_keystore.decrypt(password)
    #     return self.signing_sk == int.from_bytes(secret_bytes, 'big')
    # def signing_keystore(self, password: str) -> Keystore:
    #     secret = self.signing_sk.to_bytes(32, 'big')
    #     return ScryptKeystore.encrypt(secret=secret, password=password, path=self.signing_key_path)
    # def save_signing_keystore(self, password: str, folder: str) -> str:
    #     keystore = self.signing_keystore(password)
    #     file_folder = os.path.join(
    #         folder, 'keystore-%s-%i.json' % (keystore.path.replace('/', '_'), time.time()))
    #     keystore.save(file_folder)
    #     return file_folder


class ParaSpaceValidatorCredentialList:
    """
    A collection of multiple Credentials, one for each validator.
    """

    def __init__(self, credentials: List[ParaSpaceValidatorCredential]):
        self.credentials = credentials

    @classmethod
    def from_mnemonic(cls,
                      *,
                      mnemonic: str,
                      mnemonic_password: str,
                      num_keys: int,
                      start_index: int,
                      hex_eth1_withdrawal_address: Optional[HexAddress]) -> 'ParaSpaceValidatorCredentialList':
        key_indices = range(start_index, start_index + num_keys)
        with click.progressbar(key_indices, label=load_text(['msg_key_loading']),
                               show_percent=False, show_pos=True) as indices:
            return cls([ParaSpaceValidatorCredential(mnemonic=mnemonic, mnemonic_password=mnemonic_password,
                                                     index=index, hex_eth1_withdrawal_address=hex_eth1_withdrawal_address)
                        for index in indices])

    # def verify_keystores(self, keystore_file_folders: List[str], password: str) -> bool:
    #     with click.progressbar(zip(self.credentials, keystore_file_folders),
    #                            label=load_text(['msg_keystore_verification']),
    #                            length=len(self.credentials), show_percent=False, show_pos=True) as items:
    #         return all(credential.verify_keystore(keystore_file_folder=file_folder, password=password)
    #                    for credential, file_folder in items)

    # def export_keystores(self, password: str, folder: str) -> List[str]:
    #     with click.progressbar(self.credentials, label=load_text(['msg_keystore_creation']),
    #                            show_percent=False, show_pos=True) as credentials:
    #         return [credential.save_signing_keystore(password=password, folder=folder) for credential in credentials]

    def export_sign_data_json(self, folder: str) -> str:
        with click.progressbar(self.credentials, label=load_text(['msg_sign_data_creation']),
                               show_percent=False, show_pos=True) as credentials:
            paraspace_sign_data = [
                cred.sign_datum_dict for cred in credentials]
        file_folder = os.path.join(
            folder, 'paraspace_sign_data-%i.json' % time.time())
        print(pretty_text(
            f"Saving signature to {file_folder}", color='magenta'))
        with open(file_folder, 'w') as f:
            json.dump(paraspace_sign_data, f)
        if os.name == 'posix':
            os.chmod(file_folder, int('440', 8))  # Read for owner & group
        return file_folder

    def show_signatures(self):
        for credential in self.credentials:
            signed_data = credential.paraspace_signed_data
            validator_pubkey = remove_0x_prefix(encode_hex(signed_data.pubkey))
            validator_index = credential.account_index
            print(pretty_text(
                f'Signing for {validator_pubkey} (index: {validator_index}):', color='magenta'))
            print(pretty_text('Recipient(NFT): ' +
                  signed_data.recipient, color='magenta'))
            print(pretty_text('Signature: ' +
                  signed_data.signed_signature, color='magenta'))

    def show_validator_keys(self):
        for credential in self.credentials:
            print(pretty_text(f'validator index: {credential.account_index}'))
            print(pretty_text('signing_pk: ' + encode_hex(credential.signing_pk)))
            print(pretty_text('withdraw_pk: ' +
                  encode_hex(credential.withdrawal_pk)))
