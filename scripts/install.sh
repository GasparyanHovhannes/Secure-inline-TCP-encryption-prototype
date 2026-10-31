#!/usr/bin/env bash
# Ubuntu 22.04 / 24.04: install everything needed.
set -e
sudo apt update
sudo apt install -y iptables iproute2 ethtool tcpdump netcat-openbsd openssl \
  python3 python3-pip python3-cryptography python3-pytest \
  build-essential python3-dev libnetfilter-queue-dev libnfnetlink-dev
# NetfilterQueue is not packaged consistently; the devices run as root with the
# system python, so install it system-wide.
python3 -c "import netfilterqueue" 2>/dev/null || \
  sudo pip3 install NetfilterQueue --break-system-packages 2>/dev/null || \
  sudo pip3 install NetfilterQueue
sudo modprobe nfnetlink_queue && echo "nfnetlink_queue OK"
python3 -c "from netfilterqueue import NetfilterQueue; print('netfilterqueue OK')"
