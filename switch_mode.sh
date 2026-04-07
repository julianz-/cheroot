#!/bin/bash

# Define your paths once here
OPENSSL_PATH="/Users/julian/Documents/GitHub/openssl"
PYOPENSSL_PATH="/Users/julian/Documents/GitHub/pyopenssl"
PYTHON_BIN="./.venv/bin/python"

if [ "$1" = "debug" ]; then
    echo "🚀 Switching to DEBUG mode (Local C + Local Python)..."

    # Force the environment to see your GitHub OpenSSL
    export DYLD_LIBRARY_PATH="/Users/julian/Documents/GitHub/openssl"
    export DYLD_INSERT_LIBRARIES="/Users/julian/Documents/GitHub/openssl/libssl.dylib"
    
    # 1. Force reinstall Cryptography linked to your GitHub OpenSSL
    LDFLAGS="-L$OPENSSL_PATH" \
    CPPFLAGS="-I$OPENSSL_PATH/include" \
    $PYTHON_BIN -m pip install --no-binary :all: --force-reinstall cryptography
    
    # 2. Install pyOpenSSL in editable mode
    $PYTHON_BIN -m pip install -e "$PYOPENSSL_PATH"
    
    echo "✅ Success: Now using OpenSSL from $OPENSSL_PATH"

elif [ "$1" = "std" ]; then
    echo "📦 Switching to STANDARD mode (Official Binaries)..."

    # NEW: Clear the overrides so they don't haunt the session
    unset DYLD_LIBRARY_PATH
    unset DYLD_INSERT_LIBRARIES
    
    # 1. Reinstall official Cryptography (removes the local link)
    $PYTHON_BIN -m pip install --force-reinstall cryptography
    
    # 2. Reinstall official pyOpenSSL (removes the -e link)
    $PYTHON_BIN -m pip uninstall -y pyopenssl
    $PYTHON_BIN -m pip install pyopenssl
    
    echo "✅ Success: Now using standard PyPI packages."

else
    echo "Usage: ./switch_mode.sh [debug|std]"
fi
