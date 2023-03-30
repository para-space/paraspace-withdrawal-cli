import os
from typing import (
    Dict,
    List,
)

INSTANT_WITHDRAWAL_EXPLANATION='Using ParaSpace ETH instant withdrawal cli, you can verify your NFT recipient by signing a message with your validator key.\n- The message will be signed by your validator key **offline**\n- Then you should save the signature and sent to the ParaSpace.\n- The ParaSpace will verify the signature and mint the NFT to your recipient address.'
PARASPACE_SIGN_CLI_VERSION = '1.0.0'
PARASPACE_SIGN_DOMAIN = 'Paraspace'

ZERO_BYTES32 = b'\x00' * 32

# Execution-spec constants taken from https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md
BLS_WITHDRAWAL_PREFIX = bytes.fromhex('00')
ETH1_ADDRESS_WITHDRAWAL_PREFIX = bytes.fromhex('01')

# File/folder constants
WORD_LISTS_PATH = os.path.join(
    'instant_withdrawal', 'key_handling', 'key_derivation', 'word_lists')
DEFAULT_VALIDATOR_KEYS_FOLDER_NAME = 'validator_keys'

# Internationalisation constants
INTL_CONTENT_PATH = os.path.join('instant_withdrawal', 'intl')


def _add_index_to_options(d: Dict[str, List[str]]) -> Dict[str, List[str]]:
    '''
    Adds the (1 indexed) index (in the dict) to the first element of value list.
    eg. {'en': ['English', 'en']} -> {'en': ['1. English', '1', 'English', 'en']}
    Requires dicts to be ordered (Python > 3.6)
    '''
    keys = list(
        d.keys())  # Force copy dictionary keys top prevent iteration over changing dict
    for i, key in enumerate(keys):
        d.update({key: ['%s. %s' % (i + 1, d[key][0]), str(i + 1)] + d[key]})
    return d


INTL_LANG_OPTIONS = _add_index_to_options({
    'en': ['English', 'en'],
    'zh-CN': ['简体中文', 'zh-CN', 'zh', 'Chinese'],
})
MNEMONIC_LANG_OPTIONS = _add_index_to_options({
    'english': ['English', 'en'],
    'chinese_simplified': ['简体中文', 'zh', 'zh-CN', 'Chinese Simplified'],
    'chinese_traditional': ['繁體中文', 'zh-tw', 'Chinese Traditional'],
    'czech': ['čeština', 'český jazyk', 'cs', 'Czech'],
    'italian': ['Italiano', 'it', 'Italian'],
    'korean': ['한국어', '조선말', '韓國語', 'ko', 'Korean'],
    # Portuguese mnemonics are in both pt & pt-BR
    'portuguese': ['Português', 'Português do Brasil', 'pt', 'pt-BR', 'Portuguese'],
    'spanish': ['Español', 'es', 'Spanish'],
})

# Sundry constants
UNICODE_CONTROL_CHARS = list(range(0x00, 0x20)) + list(range(0x7F, 0xA0))
