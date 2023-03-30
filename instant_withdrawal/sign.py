import click
import sys
from instant_withdrawal.cli.sign_agreement import sign_agreement
from instant_withdrawal.utils.click import (
    captive_prompt_callback,
    choice_prompt_func,
    jit_option,
    pretty_text,
)
from instant_withdrawal.utils import config
from instant_withdrawal.utils.constants import INTL_LANG_OPTIONS
from instant_withdrawal.utils.intl import (
    get_first_options,
    fuzzy_reverse_dict_lookup,
    load_text,
)

def check_python_version() -> None:
    '''
    Checks that the python version running is sufficient and exits if not.
    '''
    if sys.version_info < (3, 7):
        click.pause(load_text(['err_python_version']))
        sys.exit()


@click.group()
@click.pass_context
@jit_option(
    '--language',
    callback=captive_prompt_callback(
        lambda language: fuzzy_reverse_dict_lookup(
            language, INTL_LANG_OPTIONS),
        choice_prompt_func(lambda: 'Please choose your language: ',
                           get_first_options(INTL_LANG_OPTIONS)),
    ),
    default='English',
    help='The language you wish to use the CLI in.',
    prompt=choice_prompt_func(
        lambda: 'Please choose your language: ', get_first_options(INTL_LANG_OPTIONS))(),
    type=str,
)
@click.option(
    '--non_interactive',
    default=False,
    is_flag=True,
    help='Disables interactive prompts. Warning: with this flag, there will be no confirmation step(s) to verify the input value(s). Please use it carefully.',  # noqa: E501
    hidden=False,
)
def cli(ctx: click.Context, language: str, non_interactive: bool) -> None:
    config.language = language
    config.non_interactive = non_interactive  # Remove interactive commands


cli.add_command(sign_agreement)

if __name__ == '__main__':
    pretty_text('\n***Using the tool on an offline and secure device is highly recommended to keep your mnemonic safe.***\n', color='red')
    check_python_version()
    cli()
