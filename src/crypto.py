"""Crypto helpers: key derivation, nonce construction, replay protection."""
import hashlib
import threading

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Hard ceiling for packets per key. Far below 2**64; when it is reached the
# device refuses to encrypt (fail closed) and the session must be re-established.
COUNTER_LIMIT = 2 ** 48


def derive_keys(shared: bytes, transcript: bytes):
    """HKDF-SHA256 over the DH secret.

    Returns three independent 256-bit keys:
      k_i2r  - AES-GCM key, initiator -> responder
      k_r2i  - AES-GCM key, responder -> initiator
      k_conf - key used only for the handshake key-confirmation MACs
    """
    salt = hashlib.sha256(transcript).digest()
    okm = HKDF(algorithm=hashes.SHA256(), length=96, salt=salt,
               info=b"secure-channel v2").derive(shared)
    return okm[:32], okm[32:64], okm[64:96]


class NonceCounter:
    """Hands out every counter value exactly once (thread-safe, never resets)."""

    def __init__(self, start: int = 0, limit: int = COUNTER_LIMIT):
        self._v, self._limit = start, limit
        self._lock = threading.Lock()

    def next(self) -> int:
        with self._lock:
            if self._v >= self._limit:
                raise RuntimeError("counter exhausted: re-run the handshake")
            v = self._v
            self._v += 1
            return v


def make_nonce(prefix: bytes, counter: int) -> bytes:
    """12-byte GCM nonce = 4-byte direction prefix || 8-byte big-endian counter."""
    if len(prefix) != 4:
        raise ValueError("prefix must be 4 bytes")
    return prefix + counter.to_bytes(8, "big")


class ReplayWindow:
    """IPsec-style sliding anti-replay window.

    Out-of-order packets inside the window are accepted once; duplicates and
    anything older than the window are rejected. Use it in two phases:
      check(ctr)   - cheap test BEFORE decrypting
      update(ctr)  - record the counter only AFTER the tag verified
    so forged packets can never move the window.
    """

    def __init__(self, size: int = 1024):
        self.size = size
        self.top = -1          # highest authenticated counter
        self.bitmap = 0        # bit d set  <=>  counter (top - d) was seen
        self._mask = (1 << size) - 1
        self._lock = threading.Lock()

    def check(self, ctr: int) -> bool:
        with self._lock:
            if ctr > self.top:
                return True
            d = self.top - ctr
            if d >= self.size:
                return False
            return not (self.bitmap >> d) & 1

    def update(self, ctr: int) -> bool:
        """Record ctr; returns False if it is a duplicate / too old."""
        with self._lock:
            if ctr > self.top:
                shift = ctr - self.top
                self.bitmap = ((self.bitmap << shift) | 1) & self._mask
                self.top = ctr
                return True
            d = self.top - ctr
            if d >= self.size or (self.bitmap >> d) & 1:
                return False
            self.bitmap |= 1 << d
            return True
