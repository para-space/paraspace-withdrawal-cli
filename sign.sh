#!/bin/bash

if [[ "$OSTYPE" == "linux"* ]] || [[ "$OSTYPE" == "linux-android"* ]] || [[ "$OSTYPE" == "darwin"* ]]; then
    echo $OSTYPE
    echo "Running instant-withdraw-cli..."
    python3 ./instant_withdrawal/sign.py "$@"

elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
    echo $OSTYPE
    echo "Running instant-withdraw-cli..."
    python ./instant_withdrawal/sign.py "$@"

else
    echo "Sorry, to run instant-withdraw-cli on" $(uname -s)", please see the trouble-shooting on https://github.com/para-space/instant-withdraw-cli"
    exit 1
fi
