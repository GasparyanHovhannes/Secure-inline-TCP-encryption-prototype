"""Authenticated finite-field Diffie-Hellman handshake between the two devices.

Runs on its own TCP connection between the devices' own addresses (a control
channel). It is never forwarded through the protected data path, so it adds
no header of any kind to protected packets.

    I -> R : A || nI || HMAC_psk("I", A, nI)
    R -> I : B || nR || HMAC_psk("R", A, nI, B, nR)
    both   : shared = DH(A, B);  k_i2r, k_r2i, k_conf = HKDF(shared, A|B|nI|nR)
    I -> R : HMAC_kconf("C", A, B, nI, nR)        (key confirmation)
    R -> I : HMAC_kconf("S", A, B, nI, nR)

The pre-shared key authenticates the DH values (stops a man in the middle);
the fresh nonces make every session unique; the confirmation MACs prove both
sides derived the same keys before any protected traffic flows.
"""
import hashlib
import hmac
import logging
import os
import socket
import struct
import time

from cryptography.hazmat.primitives.asymmetric import dh

from crypto import derive_keys
from dhgroup import G, P, PUB_LEN, Q

log = logging.getLogger("handshake")

NONCE_LEN = 32
MAC_LEN = 32
MSG_TIMEOUT = 10  # seconds allowed for each handshake step

_PARAM_NUMBERS = dh.DHParameterNumbers(P, G)
_PARAMS = _PARAM_NUMBERS.parameters()


class HandshakeError(Exception):
    pass


# --------------------------------------------------------------------- helpers
def _mac(key: bytes, *parts: bytes) -> bytes:
    """HMAC-SHA256 over length-prefixed parts (unambiguous encoding)."""
    h = hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        h.update(struct.pack("!H", len(p)) + p)
    return h.digest()


def _generate():
    priv = _PARAMS.generate_private_key()
    y = priv.public_key().public_numbers().y
    return priv, y.to_bytes(PUB_LEN, "big")


def _peer_pub(raw: bytes):
    """Validate and load the peer's public value (range + subgroup check)."""
    if len(raw) != PUB_LEN:
        raise HandshakeError("bad DH public value length")
    y = int.from_bytes(raw, "big")
    if not 2 <= y <= P - 2:
        raise HandshakeError("DH public value out of range")
    if pow(y, Q, P) != 1:
        raise HandshakeError("DH public value not in the prime-order subgroup")
    return dh.DHPublicNumbers(y, _PARAM_NUMBERS).public_key()


def _recv_exact(s, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise ConnectionError("peer closed the connection")
        buf += c
    return buf


def _send(s, data: bytes):
    s.sendall(struct.pack("!H", len(data)) + data)


def _recv(s, expected_len: int) -> bytes:
    (n,) = struct.unpack("!H", _recv_exact(s, 2))
    if n != expected_len:  # fixed-size messages: never allocate attacker-chosen sizes
        raise HandshakeError("unexpected message length")
    return _recv_exact(s, n)


# ------------------------------------------------------------------- initiator
def run_initiator(peer_ip: str, port: int, psk: bytes, timeout: float = 60):
    """Returns (k_i2r, k_r2i). Keeps retrying the connection until `timeout`."""
    deadline = time.time() + timeout
    while True:
        try:
            s = socket.create_connection((peer_ip, port), timeout=5)
            break
        except OSError:
            if time.time() > deadline:
                raise
            time.sleep(1)
    with s:
        s.settimeout(MSG_TIMEOUT)
        try:
            return _initiator_session(s, psk)
        except (ConnectionError, socket.timeout) as e:
            raise HandshakeError(
                "responder closed the connection or timed out: it rejected "
                f"us (wrong PSK?) or is not a secure-channel device ({e})") from e


def _initiator_session(s, psk: bytes):
    priv, A = _generate()
    nI = os.urandom(NONCE_LEN)
    _send(s, A + nI + _mac(psk, b"I", A, nI))

    msg = _recv(s, PUB_LEN + NONCE_LEN + MAC_LEN)
    B, nR, tag = (msg[:PUB_LEN], msg[PUB_LEN:PUB_LEN + NONCE_LEN],
                  msg[-MAC_LEN:])
    if not hmac.compare_digest(tag, _mac(psk, b"R", A, nI, B, nR)):
        raise HandshakeError("responder authentication failed (wrong PSK?)")

    shared = priv.exchange(_peer_pub(B))
    k_i2r, k_r2i, k_conf = derive_keys(shared, A + B + nI + nR)

    _send(s, _mac(k_conf, b"C", A, B, nI, nR))
    confirm = _recv(s, MAC_LEN)
    if not hmac.compare_digest(confirm, _mac(k_conf, b"S", A, B, nI, nR)):
        raise HandshakeError("key confirmation failed")
    return k_i2r, k_r2i


# ------------------------------------------------------------------- responder
def _responder_session(conn, psk: bytes):
    conn.settimeout(MSG_TIMEOUT)
    msg = _recv(conn, PUB_LEN + NONCE_LEN + MAC_LEN)
    A, nI, tag = (msg[:PUB_LEN], msg[PUB_LEN:PUB_LEN + NONCE_LEN],
                  msg[-MAC_LEN:])
    if not hmac.compare_digest(tag, _mac(psk, b"I", A, nI)):
        raise HandshakeError("initiator authentication failed (wrong PSK?)")
    peer = _peer_pub(A)

    priv, B = _generate()
    nR = os.urandom(NONCE_LEN)
    _send(conn, B + nR + _mac(psk, b"R", A, nI, B, nR))

    shared = priv.exchange(peer)
    k_i2r, k_r2i, k_conf = derive_keys(shared, A + B + nI + nR)

    confirm = _recv(conn, MAC_LEN)
    if not hmac.compare_digest(confirm, _mac(k_conf, b"C", A, B, nI, nR)):
        raise HandshakeError("key confirmation failed")
    _send(conn, _mac(k_conf, b"S", A, B, nI, nR))
    return k_i2r, k_r2i


def run_responder(bind_ip: str, port: int, psk: bytes, listener=None):
    """Wait for a valid initiator. Bad / unauthenticated connections are logged
    and ignored, so a stray connection cannot kill or block the device.
    Returns (k_i2r, k_r2i).

    `listener` may be a pre-bound listening socket (used by the tests)."""
    srv = listener
    if srv is None:
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((bind_ip, port))
        srv.listen(4)
    try:
        while True:
            conn, addr = srv.accept()
            try:
                with conn:
                    return _responder_session(conn, psk)
            except (HandshakeError, OSError) as e:
                log.warning("handshake attempt from %s rejected: %s", addr[0], e)
    finally:
        srv.close()
