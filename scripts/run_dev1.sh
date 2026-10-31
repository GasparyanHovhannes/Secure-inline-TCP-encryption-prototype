#!/usr/bin/env bash
# Device1 = initiator. Extra arguments are passed through (e.g. --tamper, -v).
cd "$(dirname "$0")/.."
exec sudo ip netns exec dev1 python3 src/device.py --role initiator --peer 10.0.12.2 \
  --psk-file psk.key "$@"
