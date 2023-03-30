import click
import json
import re
from typing import Any, Dict, Sequence

from eth_typing import (
    BLSPubkey,
    BLSSignature,
    HexAddress,
)
from eth_utils import is_hex_address, is_checksum_address, to_normalized_address
from py_ecc.bls import G2ProofOfPossession as bls
from instant_withdrawal.utils.click import pretty_echo

from instant_withdrawal.utils.intl import load_text
from instant_withdrawal.utils.ssz import (
    ValidatorProfileSigningMessage,
    ValidatorProfileSignedData,
)
from instant_withdrawal.utils.exceptions import ValidationError
from instant_withdrawal.credentials import (
    ParaSpaceValidatorCredential,
)
from instant_withdrawal.utils.constants import (
    BLS_WITHDRAWAL_PREFIX,
    ETH1_ADDRESS_WITHDRAWAL_PREFIX,
    PARASPACE_SIGN_DOMAIN,
)
from instant_withdrawal.utils.crypto import SHA256


def verify_sign_data_json(file_folder: str, credentials: Sequence[ParaSpaceValidatorCredential]) -> bool:
    """
    Validate every signing found in the sign-data JSON file folder.
    """
    with open(file_folder, 'r') as f:
        sign_json = json.load(f)
        with click.progressbar(sign_json, label=load_text(['msg_sign_verification']),
                               show_percent=False, show_pos=True) as signings:
            return all([validate_sign(signing, credential) for signing, credential in zip(signings, credentials)])


def validate_sign(sign_data_dict: Dict[str, Any], credential: ParaSpaceValidatorCredential) -> bool:
    pubkey = BLSPubkey(bytes.fromhex(sign_data_dict['pubkey']))
    recipient = sign_data_dict['recipient']
    domain = sign_data_dict['domain']
    signature = BLSSignature(bytes.fromhex(sign_data_dict['signature']))

    # Verify pubkey
    if len(pubkey) != 48:
        return False
    if pubkey != credential.signing_pk:
        return False

    # Verify recipient
    if not is_hex_address(recipient):
        return False

    # Verify domain
    if domain != PARASPACE_SIGN_DOMAIN:
        return False

    # Verify withdrawal credential
    # if len(withdrawal_credentials) != 32:
    #     return False
    # if withdrawal_credentials[:1] == BLS_WITHDRAWAL_PREFIX == credential.withdrawal_prefix:
    #     if withdrawal_credentials[1:] != SHA256(credential.withdrawal_pk)[1:]:
    #         return False
    # elif withdrawal_credentials[:1] == ETH1_ADDRESS_WITHDRAWAL_PREFIX == credential.withdrawal_prefix:
    #     if withdrawal_credentials[1:12] != b'\x00' * 11:
    #         return False
    #     if credential.eth1_withdrawal_address is None:
    #         return False
    #     if withdrawal_credentials[12:] != credential.eth1_withdrawal_address:
    #         return False
    # else:
    #     return False

    # Verify sign signature && pubkey
    sign_message = ValidatorProfileSigningMessage(
        pubkey=pubkey,
        recipient=recipient,
        domain=domain)

    return bls.Verify(pubkey, sign_message.msg_hash, signature)


def validate_password_strength(password: str) -> str:
    if len(password) < 8:
        raise ValidationError(load_text(['msg_password_length'], color='red'))
    return password


def validate_int_range(num: Any, low: int, high: int) -> int:
    '''
    Verifies that `num` is an `int` andlow <= num < high
    '''
    try:
        num_int = int(num)  # Try cast to int
        assert num_int == float(num)  # Check num is not float
        assert low <= num_int < high  # Check num in range
        return num_int
    except (ValueError, AssertionError):
        raise ValidationError(load_text(['err_not_positive_integer']))


def validate_eth1_withdrawal_address(cts: click.Context, param: Any, address: str) -> HexAddress:
    if address is None:
        return None
    if not is_hex_address(address):
        raise ValidationError(load_text(['err_invalid_ECDSA_hex_addr']))
    if not is_checksum_address(address):
        raise ValidationError(
            load_text(['err_invalid_ECDSA_hex_addr_checksum']))

    normalized_address = to_normalized_address(address)
    pretty_echo('\n%s\n' % load_text(['msg_ECDSA_hex_addr_withdrawal']))
    return normalized_address

