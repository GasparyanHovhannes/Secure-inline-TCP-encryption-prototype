import os
import socket
import struct
import threading

import pytest

import handshake
from dhgroup import P, PUB_LEN, Q

PSK = b"correct horse battery staple"


def listener():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0)); s.listen(4)
    return s, s.getsockname()[1]


def run_pair(psk_i, psk_r, timeout=5):
    srv, port = listener()
    res = {}

    def resp():
        try:
            res["r"] = handshake.run_responder("127.0.0.1", port, psk_r, listener=srv)
        except Exception as e:
            res["r_err"] = e

    t = threading.Thread(target=resp, daemon=True); t.start()
    try:
        res["i"] = handshake.run_initiator("127.0.0.1", port, psk_i, timeout=timeout)
    except Exception as e:
        res["i_err"] = e
    return t, res


def test_both_sides_derive_identical_distinct_keys():
    t, res = run_pair(PSK, PSK)
    t.join(5)
    assert res["i"] == res["r"]
    k_i2r, k_r2i = res["i"]
    assert len(k_i2r) == len(k_r2i) == 32 and k_i2r != k_r2i


def test_every_session_has_fresh_keys():
    t1, r1 = run_pair(PSK, PSK); t1.join(5)
    t2, r2 = run_pair(PSK, PSK); t2.join(5)
    assert r1["i"][0] != r2["i"][0] and r1["i"][1] != r2["i"][1]


def test_wrong_psk_rejected_by_initiator():
    t, res = run_pair(b"a-totally-different-secret", PSK)
    assert "i" not in res and "i_err" in res
    assert isinstance(res["i_err"], (handshake.HandshakeError, ConnectionError, OSError))


def _frame(b):
    return struct.pack("!H", len(b)) + b


def test_responder_ignores_garbage_and_wrong_psk_then_accepts_real_peer():
    srv, port = listener()
    res = {}
    t = threading.Thread(
        target=lambda: res.update(r=handshake.run_responder("127.0.0.1", port, PSK, listener=srv)),
        daemon=True)
    t.start()
    # 1. connection that sends garbage
    with socket.create_connection(("127.0.0.1", port)) as c:
        c.sendall(b"GET / HTTP/1.1\r\n\r\n")
    # 2. connection that closes immediately
    socket.create_connection(("127.0.0.1", port)).close()
    # 3. well-formed message, wrong MAC
    with socket.create_connection(("127.0.0.1", port)) as c:
        c.sendall(_frame(os.urandom(PUB_LEN + 32 + 32)))
    # 4. the real initiator still succeeds
    keys = handshake.run_initiator("127.0.0.1", port, PSK, timeout=10)
    t.join(10)
    assert res["r"] == keys


@pytest.mark.parametrize("y", [0, 1, P - 1, P, 2 ** 2048 - 1])
def test_invalid_dh_values_rejected(y):
    with pytest.raises(handshake.HandshakeError):
        handshake._peer_pub(y.to_bytes(PUB_LEN, "big"))


def test_non_subgroup_value_rejected():
    # a quadratic non-residue has order 2q, i.e. is outside the order-q subgroup
    y = next(v for v in range(3, 100) if pow(v, Q, P) != 1)
    with pytest.raises(handshake.HandshakeError):
        handshake._peer_pub(y.to_bytes(PUB_LEN, "big"))


def test_wrong_length_rejected():
    with pytest.raises(handshake.HandshakeError):
        handshake._peer_pub(b"\x02" * 10)


def test_honest_public_value_accepted():
    _, pub = handshake._generate()
    assert handshake._peer_pub(pub) is not None
