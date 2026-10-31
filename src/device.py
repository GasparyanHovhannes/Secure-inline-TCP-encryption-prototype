"""Inline secure-channel device (runs as Device1 = initiator or Device2 = responder).

1. Authenticated DH handshake with the peer device (control TCP connection).
2. Only after it succeeds, bind two NFQUEUEs:
     queue 1: packets coming from the HOST side  -> encrypt payload, send to peer
     queue 2: packets coming from the PEER side  -> verify, decrypt, send to host
   Before the handshake finishes nobody listens on the queues, so the iptables
   NFQUEUE rules drop all selected traffic (fail closed).
"""
import argparse
import logging
import os
import signal
import sys
import threading

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from netfilterqueue import NetfilterQueue

import handshake
from crypto import NonceCounter, ReplayWindow
from packet import protect, unprotect

log = logging.getLogger("device")

MIN_PSK_LEN = 16


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.c = {"encrypted": 0, "decrypted": 0, "dropped": 0, "passed": 0}

    def inc(self, k):
        with self.lock:
            self.c[k] += 1

    def __str__(self):
        return " ".join(f"{k}={v}" for k, v in self.c.items())


def worker(qnum, fn, stats, kind):
    """Run one NFQUEUE. fn(raw) -> new bytes, or None to drop the packet."""

    def cb(pkt):
        raw = pkt.get_payload()
        try:
            out = fn(raw)
        except Exception:
            log.exception("error while processing a packet, dropped")
            out = None
        if out is None:
            stats.inc("dropped")
            pkt.drop()
        else:
            stats.inc(kind if out != raw else "passed")
            pkt.set_payload(out)
            pkt.accept()

    q = NetfilterQueue()
    q.bind(qnum, cb)
    q.run()


def load_psk(args) -> bytes:
    psk = None
    if args.psk_file:
        with open(args.psk_file, "r") as f:
            psk = f.read().strip()
    elif os.environ.get("SECURE_CHANNEL_PSK"):
        psk = os.environ["SECURE_CHANNEL_PSK"].strip()
    if not psk:
        sys.exit("No pre-shared key. Run scripts/gen_psk.sh (creates psk.key) "
                 "or set SECURE_CHANNEL_PSK.")
    if len(psk) < MIN_PSK_LEN:
        sys.exit(f"PSK too short (need at least {MIN_PSK_LEN} characters).")
    return psk.encode()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--role", choices=["initiator", "responder"], required=True)
    ap.add_argument("--peer", help="initiator: IP of the other device")
    ap.add_argument("--bind", default="0.0.0.0", help="responder: listen IP")
    ap.add_argument("--port", type=int, default=9000, help="handshake TCP port")
    ap.add_argument("--psk-file", default=None,
                    help="file with the pre-shared secret (default: env SECURE_CHANNEL_PSK)")
    ap.add_argument("--tamper", action="store_true",
                    help="DEMO: corrupt every outgoing protected packet")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(name)s %(message)s")
    if a.role == "initiator" and not a.peer:
        ap.error("--peer is required for the initiator")
    psk = load_psk(a)

    # 1. Handshake FIRST. Protected traffic stays blocked until it succeeds.
    try:
        if a.role == "initiator":
            k_i2r, k_r2i = handshake.run_initiator(a.peer, a.port, psk)
            send_key, recv_key = k_i2r, k_r2i
            send_prefix, recv_prefix = b"\x00\x00\x00\x01", b"\x00\x00\x00\x02"
        else:
            k_i2r, k_r2i = handshake.run_responder(a.bind, a.port, psk)
            send_key, recv_key = k_r2i, k_i2r
            send_prefix, recv_prefix = b"\x00\x00\x00\x02", b"\x00\x00\x00\x01"
    except (handshake.HandshakeError, OSError) as e:
        # No session -> no queue is bound -> selected traffic stays blocked.
        log.error("Handshake failed: %s. Protected traffic remains blocked.", e)
        sys.exit(1)
    log.info("Session established (DH + HKDF, keys confirmed). "
             "Starting packet processing.")

    send_aead, recv_aead = AESGCM(send_key), AESGCM(recv_key)
    counters, window, stats = NonceCounter(), ReplayWindow(), Stats()

    enc = lambda raw: protect(raw, send_aead, send_prefix, counters, a.tamper)
    dec = lambda raw: unprotect(raw, recv_aead, recv_prefix, window)

    # 2. Queue 1 = encrypt (host side), queue 2 = decrypt (peer side).
    threading.Thread(target=worker, args=(2, dec, stats, "decrypted"),
                     daemon=True).start()
    threading.Thread(target=worker, args=(1, enc, stats, "encrypted"),
                     daemon=True).start()

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    while not stop.wait(30):
        log.info("stats: %s", stats)
    log.info("stopping, stats: %s", stats)
    # Exiting closes the queues; the NFQUEUE rules then drop selected traffic.


if __name__ == "__main__":
    main()
