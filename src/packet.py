"""Packet-level logic: encrypt / decrypt the TCP payload of one IPv4 packet.

Wire format of a protected data segment (nothing else changes):

    IP header | TCP header (+options) | ciphertext | 16-byte GCM tag | 8-byte counter

* IP and TCP headers are kept; only IP total length, IP header checksum and
  TCP checksum are rewritten (that is required, the payload got longer).
* The counter is the per-direction packet counter that, together with a
  4-byte direction prefix, forms the 12-byte GCM nonce. It is not secret.
* Segments without payload (SYN, pure ACK, FIN, RST ...) pass untouched.
"""
import logging
import struct

from cryptography.exceptions import InvalidTag

from crypto import make_nonce

TAG, CTR = 16, 8
OVERHEAD = TAG + CTR
log = logging.getLogger("packet")


def csum(data: bytes) -> int:
    """Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def split(raw: bytes):
    """-> (ip_header, tcp_header, payload), or None if this is not a complete,
    unfragmented, well-formed IPv4/TCP packet."""
    if len(raw) < 20 or raw[0] >> 4 != 4 or raw[9] != 6:
        return None
    ihl = (raw[0] & 0x0F) * 4
    if ihl < 20 or len(raw) < ihl + 20:
        return None
    if struct.unpack("!H", raw[6:8])[0] & 0x3FFF:       # MF flag or fragment offset
        return None
    total = struct.unpack("!H", raw[2:4])[0]
    if total < ihl + 20 or total > len(raw):
        return None
    raw = raw[:total]                                    # strip link-layer padding
    thl = (raw[ihl + 12] >> 4) * 4
    if thl < 20 or ihl + thl > total:
        return None
    return raw[:ihl], raw[ihl:ihl + thl], raw[ihl + thl:]


def assemble(ip_hdr: bytes, tcp_hdr: bytes, payload: bytes) -> bytes:
    """Rebuild the packet; recalculate IP total length, IP and TCP checksums."""
    total = len(ip_hdr) + len(tcp_hdr) + len(payload)
    if total > 65535:
        raise ValueError("packet would exceed 65535 bytes")
    ip, tcp = bytearray(ip_hdr), bytearray(tcp_hdr)
    ip[2:4] = struct.pack("!H", total)
    ip[10:12] = b"\x00\x00"
    ip[10:12] = struct.pack("!H", csum(bytes(ip)))
    tcp[16:18] = b"\x00\x00"
    pseudo = bytes(ip[12:20]) + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    tcp[16:18] = struct.pack("!H", csum(pseudo + bytes(tcp) + payload))
    return bytes(ip) + bytes(tcp) + payload


def _aad(ip: bytes, tcp: bytes) -> bytes:
    """Authenticated-but-not-encrypted header fields that never change on the
    path: src IP, dst IP, src port, dst port, TCP sequence number."""
    return ip[12:20] + tcp[0:8]


def protect(raw, aead, prefix, counters, tamper=False):
    """Device next to the sender. Returns the new packet, or None = drop."""
    parts = split(raw)
    if parts is None:
        return None                  # fragments / malformed: never forward in clear
    ip, tcp, data = parts
    if not data:
        return raw                   # no payload: untouched
    ctr = counters.next()            # a fresh value for EVERY packet, retransmits too
    blob = aead.encrypt(make_nonce(prefix, ctr), data, _aad(ip, tcp))  # ciphertext||tag
    if tamper:                       # demo only: corrupt one tag byte
        blob = blob[:-1] + bytes([blob[-1] ^ 1])
    return assemble(ip, tcp, blob + ctr.to_bytes(CTR, "big"))


def unprotect(raw, aead, peer_prefix, window):
    """Device next to the receiver. Returns the restored packet, or None = drop."""
    parts = split(raw)
    if parts is None:
        return None
    ip, tcp, data = parts
    if not data:
        return raw
    if len(data) < OVERHEAD + 1:
        log.warning("payload too short for a protected segment: packet dropped")
        return None
    ctr = int.from_bytes(data[-CTR:], "big")
    if not window.check(ctr):                            # cheap early replay test
        log.warning("replayed/old counter %d: packet dropped", ctr)
        return None
    try:
        plain = aead.decrypt(make_nonce(peer_prefix, ctr), data[:-CTR], _aad(ip, tcp))
    except InvalidTag:
        log.warning("TAG VERIFICATION FAILED (counter %d): packet dropped", ctr)
        return None
    if not window.update(ctr):                           # only authenticated packets move the window
        log.warning("replayed/old counter %d: packet dropped", ctr)
        return None
    return assemble(ip, tcp, plain)
