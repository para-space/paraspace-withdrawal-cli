import click
from typing import (
    Any,
    Callable,
)

from instant_withdrawal.key_handling.key_derivation.mnemonic import (
    reconstruct_mnemonic,
)
from instant_withdrawal.utils.ascii_art import PARASPACE_ASCII_ART
from instant_withdrawal.utils.click import (
    captive_prompt_callback,
    jit_option,
    pretty_text,
)
from instant_withdrawal.utils.constants import (
    INSTANT_WITHDRAWAL_EXPLANATION,
    MNEMONIC_LANG_OPTIONS,
    WORD_LISTS_PATH,
)
from instant_withdrawal.utils.exceptions import ValidationError
from instant_withdrawal.utils.intl import (
    load_text,
    get_first_options,
)
from instant_withdrawal.utils.validation import validate_int_range

from .sign_data import (
    sign_data,
    sign_data_arguments_decorator,
)

print(pretty_text(INSTANT_WITHDRAWAL_EXPLANATION))
print(pretty_text(PARASPACE_ASCII_ART))
languages = get_first_options(MNEMONIC_LANG_OPTIONS)

def validate_mnemonic(ctx: click.Context, param: Any, mnemonic: str) -> str:
    mnemonic = reconstruct_mnemonic(mnemonic, WORD_LISTS_PATH)
    if mnemonic is not None:
        return mnemonic
    else:
        raise ValidationError(load_text(['err_invalid_mnemonic'], color='red'))

def load_mnemonic_arguments_decorator(function: Callable[..., Any]) -> Callable[..., Any]:
    '''
    This is a decorator that, when applied to a parent-command, implements the
    to obtain the necessary arguments for the generate_keys() subcommand.
    '''
    decorators = [
        jit_option(
            callback=validate_mnemonic,
            help=lambda: load_text(['arg_mnemonic', 'help'], func='sign_agreement'),
            hide_input=True,
            param_decls='--mnemonic',
            prompt=lambda: load_text(['arg_mnemonic', 'prompt'], func='sign_agreement'),
            type=str,
        ),
        jit_option(
            callback=captive_prompt_callback(
                lambda x: x,
                lambda: load_text(['arg_mnemonic_password', 'prompt'], func='sign_agreement'),
                lambda: load_text(['arg_mnemonic_password', 'confirm'], func='sign_agreement'),
                lambda: load_text(['arg_mnemonic_password', 'mismatch'], func='sign_agreement'),
                True,
            ),
            default='',
            help=lambda: load_text(['arg_mnemonic_password', 'help'], func='sign_agreement'),
            hide_input=True,
            param_decls='--mnemonic-password',
            prompt=lambda: load_text(['arg_mnemonic_password', 'prompt'], func='sign_agreement'),
        ),
    ]
    for decorator in reversed(decorators):
        function = decorator(function)
    return function


@click.command(
    help=load_text(['arg_sign_agreement', 'help'], func='sign_agreement'),
)
@load_mnemonic_arguments_decorator
@jit_option(
    callback=captive_prompt_callback(
        lambda num: validate_int_range(num, 0, 2**32),
        lambda: load_text(['arg_validator_start_index', 'prompt'], func='sign_agreement'),
    ),
    default=0,
    help=lambda: load_text(['arg_validator_start_index', 'help'], func='sign_agreement'),
    param_decls="--validator_start_index",
    prompt=lambda: load_text(['arg_validator_start_index', 'prompt'], func='sign_agreement'),
)
@sign_data_arguments_decorator
@click.pass_context
def sign_agreement(ctx: click.Context, mnemonic: str, mnemonic_password: str, **kwargs: Any) -> None:
    # Create a new ctx.obj if it doesn't exist
    ctx.obj = {} if ctx.obj is None else ctx.obj

    ctx.obj.update({'mnemonic': mnemonic, 'mnemonic_password': mnemonic_password })
    ctx.forward(sign_data)
