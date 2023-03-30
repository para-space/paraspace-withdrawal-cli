import os
import click
from typing import (
    Any,
    Callable,
)
from eth_typing import HexAddress
from instant_withdrawal.credentials import ParaSpaceValidatorCredential, ParaSpaceValidatorCredentialList
from instant_withdrawal.utils.ascii_art import PARASPACE_ASCII_ART
from instant_withdrawal.utils.exceptions import ValidationError
from instant_withdrawal.utils.constants import (
    DEFAULT_VALIDATOR_KEYS_FOLDER_NAME,
)
from instant_withdrawal.utils.click import (
    captive_prompt_callback,
    jit_option,
    pretty_echo,
    pretty_text,
)
from instant_withdrawal.utils.intl import (
    load_text,
)
from instant_withdrawal.utils.validation import validate_eth1_withdrawal_address, validate_int_range, validate_password_strength, verify_sign_data_json

def get_password(text: str) -> str:
    return click.prompt(text, hide_input=True, show_default=False, type=str)


def sign_data_arguments_decorator(function: Callable[..., Any]) -> Callable[..., Any]:
    '''
    This is a decorator that, when applied to a parent-command, implements the
    to obtain the necessary arguments for the sign_data() subcommand.
    '''
    decorators = [
        jit_option(
            callback=captive_prompt_callback(
                lambda num: validate_int_range(num, 1, 2**32),
                lambda: load_text(['num_validators', 'prompt'],
                                  func='sign_data_arguments_decorator')
            ),
            default=1,
            help=lambda: load_text(
                ['num_validators', 'help'], func='sign_data_arguments_decorator'),
            param_decls="--num_validators",
            prompt=lambda: load_text(
                ['num_validators', 'prompt'], func='sign_data_arguments_decorator'),
        ),
        jit_option(
            default=os.getcwd(),
            help=lambda: load_text(
                ['folder', 'help'], func='sign_data_arguments_decorator'),
            param_decls='--folder',
            type=click.Path(exists=True, file_okay=False, dir_okay=True),
        ),
        jit_option(
            callback=captive_prompt_callback(
                lambda address: validate_eth1_withdrawal_address(
                    None, None, address),
                lambda: load_text(
                    ['arg_execution_address', 'prompt'], func='sign_data_arguments_decorator'),
                lambda: load_text(
                    ['arg_execution_address', 'confirm'], func='sign_data_arguments_decorator'),
                lambda: load_text(
                    ['arg_execution_address', 'mismatch'], func='sign_data_arguments_decorator'),
            ),
            default='',
            help=lambda: load_text(
                ['arg_execution_address', 'help'], func='sign_data_arguments_decorator'),
            param_decls=['--execution_address', '--eth1_withdrawal_address'],
            prompt=lambda: load_text(
                ['arg_execution_address', 'prompt'], func='sign_data_arguments_decorator'),
        ),
    ]
    for decorator in reversed(decorators):
        function = decorator(function)
    return function


@click.command()
@click.pass_context
def sign_data(ctx: click.Context, validator_start_index: int,
              num_validators: int, folder: str,
              execution_address: HexAddress, **kwargs: Any) -> None:

    mnemonic = ctx.obj['mnemonic']
    mnemonic_password = ctx.obj['mnemonic_password']
    folder = os.path.join(folder, DEFAULT_VALIDATOR_KEYS_FOLDER_NAME)
    if not os.path.exists(folder):
        os.mkdir(folder)
    click.clear()
    # pretty_echo(PARASPACE_ASCII_ART)
    pretty_echo(load_text(['msg_key_loading']))
    credentials = ParaSpaceValidatorCredentialList.from_mnemonic(
        mnemonic=mnemonic,
        mnemonic_password=mnemonic_password,
        num_keys=num_validators,
        start_index=validator_start_index,
        hex_eth1_withdrawal_address=execution_address,
    )
    credentials.show_validator_keys()

    print(pretty_text(f'credentials: {credentials.credentials}'))
    credentials.show_signatures()
    print(pretty_text('You can copy the above data and send it to the ParaSpace.'))

    sign_file = credentials.export_sign_data_json(folder=folder)
    if not verify_sign_data_json(sign_file, credentials.credentials):
        raise ValidationError(load_text(['err_verify_sign']))
    pretty_echo(load_text(['msg_signed_success']) + folder)
    click.pause(load_text(['msg_pause']))
