from crypto import ReplayWindow


def test_in_order_and_duplicate():
    w = ReplayWindow()
    for i in range(10):
        assert w.check(i) and w.update(i)
    assert not w.check(5) and not w.update(5)


def test_out_of_order_inside_window_accepted_once():
    w = ReplayWindow(size=64)
    assert w.update(10)
    assert w.check(7) and w.update(7)       # late but fresh
    assert not w.check(7)                   # now a duplicate
    assert w.update(8) and w.update(9)


def test_too_old_rejected():
    w = ReplayWindow(size=64)
    assert w.update(1000)
    assert not w.check(1000 - 64)           # exactly outside the window
    assert w.check(1000 - 63)


def test_big_jump_slides_window():
    w = ReplayWindow(size=64)
    for i in range(5):
        w.update(i)
    assert w.update(10_000)
    assert not w.check(4)                   # fell out of the window
    assert not w.check(10_000)


def test_check_does_not_modify_state():
    w = ReplayWindow()
    assert w.check(50) and w.check(50)      # forged packets cannot burn counters
    assert w.top == -1
