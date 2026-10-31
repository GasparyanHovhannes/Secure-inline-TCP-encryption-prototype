#!/usr/bin/env python3
"""Inspect a tcpdump -w capture taken BETWEEN the two devices.

Checks, per sending device (grouped by Ethernet source MAC):
  * every payload-bearing segment on the protected port is >= 25 bytes
    (1 byte data + 16 tag + 8 counter), i.e. nothing travels in clear;
  * the 8-byte counter at the end of each payload is UNIQUE (=> unique AES-GCM
    nonce, retransmissions included);
  * the largest Ethernet frame stays within a 1500-byte MTU.

Usage: check_wire.py capture.pcap [--port 5000] [--mtu 1500]
Exit status 0 = all good.
"""
import argparse
import struct
import sys
from collections import defaultdict


def read_pcap(path):
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        end = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        end = ">"
    else:
        sys.exit("not a classic pcap file (capture with: tcpdump -w file.pcap)")
    _, _, _, _, _, linktype = struct.unpack(end + "HHiIII", data[4:24])
    if linktype != 1:
        sys.exit(f"unsupported link type {linktype} (need Ethernet)")
    off = 24
    while off + 16 <= len(data):
        _, _, incl, orig = struct.unpack(end + "IIII", data[off:off + 16])
        off += 16
        yield data[off:off + incl]
        off += incl


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--mtu", type=int, default=1500)
    a = ap.parse_args()

    ctrs = defaultdict(list)
    short = max_frame = n_data = 0
    for fr in read_pcap(a.pcap):
        if len(fr) < 14 + 20 + 20 or fr[12:14] != b"\x08\x00":
            continue
        ip = fr[14:]
        ihl = (ip[0] & 0xF) * 4
        if ip[9] != 6:
            continue
        total = struct.unpack("!H", ip[2:4])[0]
        tcp = ip[ihl:total]
        sport, dport = struct.unpack("!HH", tcp[:4])
        if a.port not in (sport, dport):
            continue
        thl = (tcp[12] >> 4) * 4
        payload = tcp[thl:]
        max_frame = max(max_frame, len(fr))
        if not payload:
            continue
        n_data += 1
        if len(payload) < 25:
            short += 1
            continue
        ctrs[fr[6:12].hex(":")].append(int.from_bytes(payload[-8:], "big"))

    ok = True
    print(f"payload-bearing segments: {n_data}, largest frame: {max_frame} bytes")
    for mac, lst in ctrs.items():
        dup = len(lst) - len(set(lst))
        print(f"  sender {mac}: {len(lst)} segments, {len(set(lst))} distinct counters, "
              f"{dup} duplicates, range {min(lst)}..{max(lst)}")
        ok &= dup == 0
    if n_data == 0:
        print("FAIL: no protected data segments captured"); ok = False
    if short:
        print(f"FAIL: {short} payload segments too short to be protected (cleartext?)"); ok = False
    if max_frame > a.mtu + 14:
        print(f"FAIL: frame of {max_frame} bytes exceeds MTU {a.mtu}"); ok = False
    print("RESULT:", "OK" if ok else "PROBLEM")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
