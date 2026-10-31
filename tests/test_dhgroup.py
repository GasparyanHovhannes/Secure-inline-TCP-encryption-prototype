import dhgroup


def is_probable_prime(n, rounds=12):
    import random
    if n < 4:
        return n in (2, 3)
    if n % 2 == 0:
        return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2; r += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def test_group_is_rfc7919_ffdhe2048_safe_prime():
    p = dhgroup.P
    assert p.bit_length() == 2048 and dhgroup.PUB_LEN == 256
    assert hex(p).startswith("0xffffffffffffffffadf85458a2bb4a9a")
    assert hex(p).endswith("886b423861285c97ffffffffffffffff")
    assert is_probable_prime(p)
    assert is_probable_prime(dhgroup.Q)                     # safe prime: (p-1)/2 prime too


def test_generator_has_prime_order_q():
    assert pow(dhgroup.G, dhgroup.Q, dhgroup.P) == 1
