#!/usr/bin/env bash
# Creates the pre-shared secret used to authenticate the DH handshake.
# Copy the same file to both devices (here: both run in this VM).
cd "$(dirname "$0")/.."
if [ -f psk.key ]; then echo "psk.key already exists (delete it to create a new one)"; exit 0; fi
umask 077
openssl rand -hex 32 > psk.key
echo "Created psk.key (kept out of git by .gitignore)."
