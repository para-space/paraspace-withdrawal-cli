# ParaSpace Withdrawal CLI

## Overview

- The CLI follows the [github.com/ethereum/staking-deposit-cli](https://github.com/ethereum/staking-deposit-cli) implementation for security, please use it **offline** ⛳️.
- The CLI designed to simplify the withdrawal process for ParaSpace users.
  - With this tool, users can effortlessly initiate and sign the message provided by ParaSpace.

[![asciicast](https://asciinema.org/a/572235.svg)](https://asciinema.org/a/572235)

## Usage

> If you are getting permission denied errors when handling your keystores, consider changing which user/group owns the file (with chown) or, if need be, change the file permissions with chmod.

### Run From Source

#### Build Requirements

- **Python 3.8+**
- **pip3**

#### Build Steps

```shell
# Clone the repo
git clone https://github.com/para-space/paraspace-withdrawal-cli
# Install the dependencies
make init
# Install the CLI package to global
make install
# Run the CLI
make sign
```

### Run From Binary

#### For MacOS user

1. See [releases page](https://github.com/para-space/paraspace-withdrawal-cli/releases) to download and decompress the corresponding binary files.

   - `wget https://github.com/para-space/paraspace-withdrawal-cli/releases/download/v1.0.1/paraspace-withdrawal-cli-c67c1fa-darwin-arm64.tar.gz`

2. Unzip the file

   - `tar -zxvf paraspace-withdrawal-cli-c67c1fa-darwin-arm64.tar.gz`

3. Run the executable file

   - `./sign sign-agreement`

#### For Linux user

1. See [releases page](https://github.com/para-space/paraspace-withdrawal-cli/releases) to download and decompress the corresponding binary files.

   - `wget https://github.com/para-space/paraspace-withdrawal-cli/releases/download/v1.0.1/paraspace-withdrawal-cli-c67c1fa-linux-amd64.tar.gz`

2. Unzip the file

   - `tar -zxvf paraspace-withdrawal-cli-c67c1fa-linux-amd64.tar.gz`

3. Run the executable file

   - `./sign sign-agreement`

#### For Windows user

TODO

## Acknowledgement

- https://github.com/ethereum/staking-deposit-cli
