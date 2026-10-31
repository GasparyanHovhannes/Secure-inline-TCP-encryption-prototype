# Secure-inline-TCP-encryption-prototype

Prototype of two Linux middleboxes that transparently protect selected TCP/IPv4
traffic between two hosts:

```
 PC1 ───────► Device1 ═══════════════════► Device2 ───────► PC2
 10.0.1.2     encrypts TCP payload          verifies, decrypts,   10.0.2.2
 (unmodified) AES-GCM, DH-derived key       fixes lengths+checksums (unmodified)
                      ◄──── handshake: authenticated DH (control TCP :9000) ────►
```

PC1 and PC2 are ordinary hosts and know nothing about the devices. All four
machines run in one Ubuntu VM as network namespaces (`pc1`, `dev1`, `dev2`, `pc2`).

## How it works

1. **Handshake first.** Device1 (initiator) and Device2 (responder) run an
   authenticated finite-field Diffie-Hellman exchange (RFC 7919 `ffdhe2048`)
   on a separate control connection. The DH values are authenticated with a
   pre-shared key (HMAC-SHA256), fresh nonces make each session unique, and
   HKDF-SHA256 derives **one AES-256 key per direction**. Both sides prove they
   derived the same keys (key-confirmation MACs) before anything else happens.
2. **Fail closed.** The NFQUEUE listeners are only started after the handshake.
   Until then (or if a device is down) iptables drops all selected traffic.
3. **Encrypt.** The device next to the sender encrypts *only the TCP payload*
   with AES-256-GCM, keeps the IP and TCP headers, appends the tag, and rewrites
   the IP total length, IP checksum and TCP checksum. The packet goes straight
   to the peer device: no UDP, no tunnel, no custom header.
4. **Verify and decrypt.** The device next to the receiver checks the tag
   (and the replay window), decrypts, strips tag and counter, restores the
   original packet, recalculates the lengths/checksums and forwards it.
   Anything that fails verification is dropped.

### Packet format

```
 ┌──────────┬────────────────────┬──────────────┬───────────┬───────────┐
 │ IP hdr   │ TCP hdr (+options) │ ciphertext   │ GCM tag   │ counter   │
 │ (kept)   │ (kept)             │ = len(data)  │ 16 bytes  │ 8 bytes   │
 └──────────┴────────────────────┴──────────────┴───────────┴───────────┘
   unchanged   unchanged           └──────── TCP payload on the wire ────┘
```

Overhead is **24 bytes per data segment** (16 tag + 8 counter). Segments without
payload (SYN, pure ACK, FIN, RST) pass through untouched. Example: a 19-byte
line (`hello secure world` + newline) is a 43-byte payload on the wire.

* **Authenticated, not encrypted (AAD):** source IP, destination IP, source
  port, destination port, TCP sequence number.
* **Not authenticated:** fields that legitimately change or are not
  protected (TTL, flags, ACK number, window, options). See limitations.

### Nonce strategy (never reuse a nonce under the same key)

* Separate AES key per direction (`k_i2r`, `k_r2i`) **and** a 4-byte direction
  prefix in the nonce.
* Nonce (12 bytes) = 4-byte direction prefix || 8-byte packet counter.
* One thread-safe counter per direction, starts at 0 for every session
  (every session has fresh keys), only ever increments, **never resets**.
  *Every* encrypted packet takes a new value, so TCP retransmissions get a new
  nonce as well; reuse of a nonce for two plaintexts is impossible.
* The counter travels at the end of the payload so the receiver can rebuild the
  nonce without a header and without keeping lock-step state (packets may be
  lost, reordered or retransmitted between the devices).
* Hard limit 2^48 packets per key: afterwards the device refuses to encrypt
  (fail closed) and the session must be re-established.
* Receiver: IPsec-style sliding replay window (1024); the window only moves
  after the tag verified, so forged packets cannot disturb it.

### Selecting traffic

`PORT` (default 5000), matched as **source or destination** port, so a TCP
connection started from either PC is protected. Queue 1 = packets arriving from
the host side (encrypt), queue 2 = packets arriving from the peer device
(decrypt). MSS in SYNs is lowered to 1400 (only when larger) so that
payload + 24 bytes + TCP options still fit a 1500-byte MTU. NIC offloads
(TSO/GSO/GRO/checksum) are disabled on the lab links.

## Files

| Path | Purpose |
|---|---|
| `src/device.py` | device program (handshake, then two NFQUEUE workers) |
| `src/handshake.py` | authenticated DH handshake, key confirmation |
| `src/dhgroup.py` | RFC 7919 ffdhe2048 safe-prime group |
| `src/crypto.py` | HKDF, nonce counter, replay window |
| `src/packet.py` | protect / unprotect, header and checksum handling |
| `scripts/` | lab setup/teardown, device launchers, PSK generator, wire checker, end-to-end test |
| `tests/` | 50 unit tests (nonces, replay, packets, handshake, DH group) |
| `docs/` | test results, captures, comparison with the original guide |

## Run it (Ubuntu 22.04 / 24.04 VM, not WSL2)

```bash
chmod +x scripts/*.sh scripts/*.py   # once, if your unzip lost the executable bits
./scripts/install.sh            # packages + NetfilterQueue
python3 -m pytest -v            # 50 unit tests, no root needed
./scripts/gen_psk.sh            # creates psk.key (git-ignored)
sudo ./scripts/e2e_test.sh      # builds the lab and proves everything automatically
```

### Manual demo (VS Code: Terminal ▸ Run Task…, or separate terminals)

```bash
sudo ./scripts/setup_lab.sh && sudo ip netns exec pc1 ping -c2 10.0.2.2
./scripts/run_dev2.sh                                  # terminal 1 (start first)
./scripts/run_dev1.sh                                  # terminal 2  -> both: "Session established"
sudo ip netns exec pc2 nc -l 5000                      # terminal 3
sudo ip netns exec dev1 tcpdump -i d1-d2 -X -n port 5000 -c 8 | tee docs/capture_between_devices.txt   # terminal 4
sudo ip netns exec pc1 nc 10.0.2.2 5000                # terminal 5: type "hello secure world"
```

Between the devices the payload is unreadable; on the host side
(`tcpdump -i d1-p1`) it is clear text. Type in terminal 3 to see the reverse
direction. Stop: `sudo pkill -f src/device.py; sudo ./scripts/teardown_lab.sh`.

Tamper demo: `./scripts/run_dev1.sh --tamper` → Device2 logs
`TAG VERIFICATION FAILED ... packet dropped`, PC2 receives nothing.

## What the automated tests prove (`docs/e2e_results_sandbox_run.txt`)

* handshake succeeds; before it, selected traffic is blocked
* PC1→PC2 **and** PC2→PC1 connections work; file hashes identical (3 MB random)
* marker text visible on the host side, **not visible between the devices**
* every captured counter unique, no cleartext data segment, frames ≤ MTU
* unselected port stays untouched
* tampered packets are dropped and logged; wrong PSK → device refuses to start
* no devices / handshake pending → no data; clean restart works

## Limitations (prototype)

* IPv4/TCP only; IP fragments are dropped, never forwarded in clear.
* Strictly one session per device pair; handshake attempts are served one at a time.
