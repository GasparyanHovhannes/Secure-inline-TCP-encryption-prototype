"""Diffie-Hellman group: RFC 7919 ffdhe2048 (2048-bit safe prime, generator 2).

p = 2q + 1 with q prime, so the generator 2 has prime order q.  Every honest
public value therefore satisfies  y^q mod p == 1,  which lets us reject
small-subgroup / invalid public values (see handshake._peer_pub).

Nothing secret lives here: the group is public and fixed, so both devices
always agree on it without a parameter file.  (Cross-check: the value equals
`openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe2048`.)
"""

P = int(
    "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695"
    "A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617A"
    "D3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935"
    "984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797A"
    "BC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4"
    "AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F61"
    "9172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005"
    "C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF"
, 16)
G = 2
Q = (P - 1) // 2
PUB_LEN = (P.bit_length() + 7) // 8   # 256 bytes
