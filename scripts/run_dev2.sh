#!/usr/bin/env bash
# Device2 = responder. Start it first.
cd "$(dirname "$0")/.."
exec sudo ip netns exec dev2 python3 src/device.py --role responder --bind 10.0.12.2 \
  --psk-file psk.key "$@"
