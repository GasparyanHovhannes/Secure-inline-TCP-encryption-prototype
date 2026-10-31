import threading

import pytest

from crypto import NonceCounter, make_nonce


def test_100k_unique_nonces():
    c, prefix = NonceCounter(), b"\x00\x00\x00\x01"
    nonces = {make_nonce(prefix, c.next()) for _ in range(100_000)}
    assert len(nonces) == 100_000


def test_unique_across_threads():
    """8 threads hammering one counter must never receive the same value."""
    c, out = NonceCounter(), []
    lock = threading.Lock()

    def run():
        mine = [c.next() for _ in range(20_000)]
        with lock:
            out.extend(mine)

    ts = [threading.Thread(target=run) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert len(out) == 160_000 and len(set(out)) == 160_000


def test_counter_never_resets_and_is_exhaustible():
    c = NonceCounter(start=5, limit=8)
    assert [c.next() for _ in range(3)] == [5, 6, 7]
    with pytest.raises(RuntimeError):
        c.next()          # refuses to hand out a value again (fail closed)


def test_nonce_format_and_direction_prefixes_differ():
    a = make_nonce(b"\x00\x00\x00\x01", 7)
    b = make_nonce(b"\x00\x00\x00\x02", 7)
    assert len(a) == 12 and a != b
    with pytest.raises(ValueError):
        make_nonce(b"\x01", 7)
