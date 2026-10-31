import os
import struct

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto import NonceCounter, ReplayWindow
from packet import OVERHEAD, assemble, csum, protect, split, unprotect

PFX = b"\x00\x00\x00\x01"


def make_packet(payload=b"hello world", tcp_opts=b"", flags=0x18, seq=1000,
                sport=40000, dport=5000):
    ip = bytearray(20); ip[0] = 0x45; ip[8] = 64; ip[9] = 6
    ip[12:16] = bytes([10, 0, 1, 2]); ip[16:20] = bytes([10, 0, 2, 2])
    tcp = bytearray(20) + tcp_opts
    tcp[0:2] = struct.pack("!H", sport); tcp[2:4] = struct.pack("!H", dport)
    tcp[4:8] = struct.pack("!I", seq); tcp[12] = (len(tcp) // 4) << 4
    tcp[13] = flags
    return assemble(bytes(ip), bytes(tcp), payload)


def checksums_ok(raw):
    ip, tcp, data = split(raw)
    pseudo = ip[12:20] + struct.pack("!BBH", 0, 6, len(tcp) + len(data))
    return csum(ip) == 0 and csum(pseudo + tcp + data) == 0


def setup():
    return AESGCM(AESGCM.generate_key(256)), NonceCounter()


def test_csum_known_vector():
    # classic IPv4 header example, checksum field 0xb861
    hdr = bytes.fromhex("4500007300004000" "4011" "b861" "c0a80001" "c0a800c7")
    assert csum(hdr) == 0
    assert csum(hdr[:10] + b"\x00\x00" + hdr[12:]) == 0xB861


def test_roundtrip_and_checksums():
    aead, ctr = setup()
    orig = make_packet()
    enc = protect(orig, aead, PFX, ctr)
    assert split(enc)[2] != b"hello world"
    assert b"hello world" not in enc
    assert len(enc) == len(orig) + OVERHEAD          # 16 tag + 8 counter
    assert checksums_ok(enc)
    dec = unprotect(enc, aead, PFX, ReplayWindow())
    assert dec == orig and checksums_ok(dec)


@pytest.mark.parametrize("n", [1, 2, 15, 16, 17, 100, 1400, 1436])
def test_roundtrip_many_sizes(n):
    aead, ctr = setup()
    orig = make_packet(os.urandom(n))
    enc = protect(orig, aead, PFX, ctr)
    assert checksums_ok(enc)
    assert unprotect(enc, aead, PFX, ReplayWindow()) == orig


def test_tcp_options_and_headers_preserved():
    aead, ctr = setup()
    opts = bytes.fromhex("0204 05b4 0402 0103 0307")      # MSS, SACK-perm, NOP, WS (12 bytes)
    orig = make_packet(b"data", tcp_opts=opts, seq=123456, sport=1234, dport=5000)
    enc = protect(orig, aead, PFX, ctr)
    (ip0, tcp0, _), (ip1, tcp1, _) = split(orig), split(enc)
    # everything except IP length/checksum and TCP checksum is identical
    assert ip0[:2] == ip1[:2] and ip0[4:10] == ip1[4:10] and ip0[12:] == ip1[12:]
    assert tcp0[:16] == tcp1[:16] and tcp0[18:] == tcp1[18:]


def test_tamper_detected_everywhere():
    aead, ctr = setup()
    enc = protect(make_packet(), aead, PFX, ctr)
    start = len(enc) - (11 + OVERHEAD)                    # first ciphertext byte
    for i in range(start, len(enc)):                       # ciphertext, tag and counter
        bad = bytearray(enc); bad[i] ^= 1
        assert unprotect(bytes(bad), aead, PFX, ReplayWindow()) is None, i


def test_wrong_key():
    aead, ctr = setup()
    enc = protect(make_packet(), aead, PFX, ctr)
    assert unprotect(enc, AESGCM(AESGCM.generate_key(256)), PFX, ReplayWindow()) is None


def test_wrong_direction_prefix():
    aead, ctr = setup()
    enc = protect(make_packet(), aead, PFX, ctr)
    assert unprotect(enc, aead, b"\x00\x00\x00\x02", ReplayWindow()) is None


def test_replay_rejected_and_reorder_accepted():
    aead, ctr = setup(); win = ReplayWindow()
    p = [protect(make_packet(b"x%d" % i, seq=1000 + i), aead, PFX, ctr) for i in range(3)]
    assert unprotect(p[2], aead, PFX, win) is not None
    assert unprotect(p[0], aead, PFX, win) is not None    # reordered, still fine
    assert unprotect(p[0], aead, PFX, win) is None        # duplicate
    assert unprotect(p[2], aead, PFX, win) is None


def test_forged_packet_does_not_poison_window():
    aead, ctr = setup(); win = ReplayWindow()
    good = protect(make_packet(), aead, PFX, ctr)
    forged = bytearray(good); forged[-1] = 0xFF; forged[-2] = 0xFF   # huge counter
    assert unprotect(bytes(forged), aead, PFX, win) is None
    assert unprotect(good, aead, PFX, win) is not None


@pytest.mark.parametrize("field,off", [("dst port", 22), ("src port", 20),
                                       ("seq", 24), ("dst ip", 16), ("src ip", 12)])
def test_headers_are_authenticated(field, off):
    aead, ctr = setup()
    enc = bytearray(protect(make_packet(), aead, PFX, ctr))
    enc[off] ^= 0x01
    assert unprotect(bytes(enc), aead, PFX, ReplayWindow()) is None


def test_retransmission_gets_fresh_nonce():
    aead, ctr = setup()
    pkt = make_packet(b"same data", seq=777)
    a, b = protect(pkt, aead, PFX, ctr), protect(pkt, aead, PFX, ctr)
    assert a != b                                          # same plaintext+seq, different counter/ciphertext
    assert split(a)[2][-8:] != split(b)[2][-8:]


def test_empty_payload_untouched():
    aead, ctr = setup()
    for flags in (0x02, 0x10, 0x11, 0x04):                 # SYN, ACK, FIN+ACK, RST
        pkt = make_packet(b"", flags=flags)
        assert protect(pkt, aead, PFX, ctr) == pkt
        assert unprotect(pkt, aead, PFX, ReplayWindow()) == pkt


def test_cleartext_with_payload_is_dropped_by_receiver():
    aead, _ = setup()
    assert unprotect(make_packet(b"plain data from an attacker"), aead, PFX, ReplayWindow()) is None
    assert unprotect(make_packet(b"short"), aead, PFX, ReplayWindow()) is None


def test_malformed_and_fragments_never_forwarded():
    aead, ctr = setup()
    pkt = bytearray(make_packet())
    frag = bytearray(pkt); frag[6] |= 0x20                 # MF flag
    assert protect(bytes(frag), aead, PFX, ctr) is None
    assert protect(b"\x45\x00", aead, PFX, ctr) is None
    udp = bytearray(pkt); udp[9] = 17
    assert protect(bytes(udp), aead, PFX, ctr) is None
    trunc = bytes(pkt)[:30]
    assert protect(trunc, aead, PFX, ctr) is None


def test_link_padding_is_stripped():
    aead, ctr = setup()
    orig = make_packet(b"hi")
    enc = protect(orig + b"\x00" * 6, aead, PFX, ctr)
    assert unprotect(enc, aead, PFX, ReplayWindow()) == orig


def test_oversize_rejected():
    aead, ctr = setup()
    assert protect(make_packet(b"a" * 60000), aead, PFX, ctr) is not None
    with pytest.raises(ValueError):                         # IPv4 total length is 16 bit
        assemble(b"\x45" + bytes(19), bytes(20), b"a" * 65520)
