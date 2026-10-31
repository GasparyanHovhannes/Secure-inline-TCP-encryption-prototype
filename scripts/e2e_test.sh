#!/usr/bin/env bash
# Automated end-to-end proof tests on the namespace lab.   Run:  sudo ./scripts/e2e_test.sh
# Builds the lab, starts both devices and checks: handshake, both directions,
# secrecy on the wire, unique nonces, MTU, selectivity, tamper, no-handshake-no-data,
# wrong PSK.  Results are also written to docs/e2e_results.txt
set -u
[ "$EUID" -eq 0 ] || { echo "run with sudo"; exit 1; }
cd "$(dirname "$0")/.."
ROOT="$PWD"
T="$(mktemp -d)"
PASS=0; FAIL=0
exec > >(tee "$ROOT/docs/e2e_results.txt") 2>&1

ok()  { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
chk() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
hdr() { echo; echo "== $1"; }

stop_all() { pkill -f "src/device.py" 2>/dev/null; pkill -x nc 2>/dev/null; pkill -x tcpdump 2>/dev/null; sleep 0.5; }
cleanup()  { stop_all; "$ROOT/scripts/teardown_lab.sh" >/dev/null; }
trap cleanup EXIT

start_devices() {  # $1 = extra args for Device1, $2 = psk file for Device1
  local psk1="${2:-psk.key}"
  : > "$T/dev1.log"; : > "$T/dev2.log"
  ip netns exec dev2 python3 src/device.py --role responder --bind 10.0.12.2 --psk-file psk.key >"$T/dev2.log" 2>&1 &
  sleep 0.7
  ip netns exec dev1 python3 src/device.py --role initiator --peer 10.0.12.2 --psk-file "$psk1" ${1:-} >"$T/dev1.log" 2>&1 &
  for _ in $(seq 1 40); do
    grep -q "Session established" "$T/dev1.log" && grep -q "Session established" "$T/dev2.log" && return 0
    sleep 0.5
  done
  return 1
}

cap_start() { ip netns exec "$1" tcpdump -i "$2" -U -w "$3" "$4" >/dev/null 2>&1 & echo $! > "$3.pid"; sleep 1; }
cap_stop()  { sleep 0.7; kill -INT "$(cat "$1.pid")" 2>/dev/null; sleep 0.5; }

xfer() {  # sender-ns receiver-ns dest-ip port in out
  rm -f "$6"
  ip netns exec "$2" timeout 40 nc -l "$4" > "$6" &
  local lp=$!
  sleep 0.8
  ip netns exec "$1" timeout 40 nc -N "$3" "$4" < "$5"
  wait $lp 2>/dev/null
}

hdr "Setup"
scripts/teardown_lab.sh >/dev/null; scripts/setup_lab.sh
[ -f psk.key ] || scripts/gen_psk.sh
head -c 3M /dev/urandom > "$T/rand.bin"
yes "TOPSECRET-MARKER-98765 confidential payload line" | head -c 400000 > "$T/marker.txt"
echo "this-is-another-valid-but-different-psk-0123456789" > "$T/other.key"

hdr "1. Plain network works, ICMP untouched"
chk "ping PC1 -> PC2 through both devices" "ip netns exec pc1 ping -c2 -W2 10.0.2.2 >/dev/null"

hdr "2. Before the handshake nothing selected gets through, then the handshake"
ip netns exec pc2 timeout 8 nc -l 5000 >/dev/null &
sleep 0.8
chk "no session yet: connection PC1 -> PC2:5000 is blocked" "! ip netns exec pc1 nc -w 3 -z 10.0.2.2 5000"
pkill -x nc 2>/dev/null; sleep 0.5
chk "both devices report 'Session established'" "start_devices"

hdr "3. PC1 -> PC2 (PC1 is the client), 400 KB of text with a marker, captured on both sides"
cap_start dev1 d1-d2 "$T/wire.pcap" "tcp port 5000"
cap_start dev1 d1-p1 "$T/host.pcap" "tcp port 5000"
xfer pc1 pc2 10.0.2.2 5000 "$T/marker.txt" "$T/out1.txt"
cap_stop "$T/wire.pcap"; cap_stop "$T/host.pcap"
chk "PC2 received an identical file" "cmp -s $T/marker.txt $T/out1.txt"
chk "marker IS visible on the host side (PC1<->Device1)" "grep -qa TOPSECRET-MARKER $T/host.pcap"
chk "marker is NOT visible between the devices" "! grep -qa TOPSECRET-MARKER $T/wire.pcap"
python3 scripts/check_wire.py "$T/wire.pcap" | sed 's/^/    /'
chk "wire check: unique counters, no cleartext data, frames within MTU" "python3 scripts/check_wire.py $T/wire.pcap >/dev/null"

hdr "4. Connection started from PC2 towards PC1:5000 (reverse direction)"
cap_start dev1 d1-d2 "$T/wire4.pcap" "tcp port 5000"
xfer pc2 pc1 10.0.1.2 5000 "$T/marker.txt" "$T/out4.txt"
cap_stop "$T/wire4.pcap"
chk "PC1 received an identical file" "cmp -s $T/marker.txt $T/out4.txt"
chk "marker is NOT visible between the devices" "! grep -qa TOPSECRET-MARKER $T/wire4.pcap"
chk "wire check passes" "python3 scripts/check_wire.py $T/wire4.pcap >/dev/null"

hdr "5. Larger transfer with random data (3 MB), hash comparison"
xfer pc1 pc2 10.0.2.2 5000 "$T/rand.bin" "$T/out5.bin"
sha256sum "$T/rand.bin" "$T/out5.bin"
chk "identical SHA-256" "cmp -s $T/rand.bin $T/out5.bin"
stop_all; sleep 1
grep -h "stopping" "$T/dev1.log" "$T/dev2.log" | sed 's/^/    /'
chk "Device1 encrypted packets" "grep -Eq 'encrypted=[1-9]' $T/dev1.log"
chk "Device2 decrypted packets, dropped none" "grep -Eq 'decrypted=[1-9]' $T/dev2.log && grep -q 'dropped=0' $T/dev2.log"

hdr "6. Selectivity: unselected port 6000 is NOT touched"
chk "devices restart" "start_devices"
cap_start dev1 d1-d2 "$T/wire6.pcap" "tcp port 6000"
xfer pc1 pc2 10.0.2.2 6000 "$T/marker.txt" "$T/out6.txt"
cap_stop "$T/wire6.pcap"
chk "file arrives" "cmp -s $T/marker.txt $T/out6.txt"
chk "traffic on port 6000 stays in clear (not selected)" "grep -qa TOPSECRET-MARKER $T/wire6.pcap"

hdr "7. Tamper: Device1 corrupts every protected packet"
stop_all
chk "devices restart with --tamper" "start_devices --tamper"
rm -f "$T/out7.txt"
ip netns exec pc2 timeout 12 nc -l 5000 > "$T/out7.txt" &
sleep 0.8
echo "this must never arrive" | ip netns exec pc1 timeout 8 nc -N 10.0.2.2 5000
sleep 1
chk "Device2 logged TAG VERIFICATION FAILED" "grep -q 'TAG VERIFICATION FAILED' $T/dev2.log"
chk "PC2 received nothing" "[ ! -s $T/out7.txt ]"

hdr "8. No handshake, no data"
stop_all
ip netns exec pc2 timeout 10 nc -l 5000 > "$T/out8.txt" &
sleep 0.8
chk "both devices down: connection to PC2:5000 fails" "! ip netns exec pc1 nc -w 3 -z 10.0.2.2 5000"
ip netns exec dev1 python3 src/device.py --role initiator --peer 10.0.12.2 --psk-file psk.key >"$T/dev1.log" 2>&1 &
sleep 2
chk "only Device1 up (handshake pending): connection still fails" "! ip netns exec pc1 nc -w 3 -z 10.0.2.2 5000"
stop_all

hdr "9. Wrong pre-shared key"
ip netns exec dev2 python3 src/device.py --role responder --bind 10.0.12.2 --psk-file psk.key >"$T/dev2.log" 2>&1 &
sleep 0.7
ip netns exec dev1 python3 src/device.py --role initiator --peer 10.0.12.2 --psk-file "$T/other.key" >"$T/dev1.log" 2>&1
chk "Device1 refuses to start (clear error, exit)" "grep -q 'Handshake failed' $T/dev1.log"
chk "Device2 logged the rejected attempt" "grep -q 'rejected' $T/dev2.log"
chk "no data flows" "! ip netns exec pc1 nc -w 3 -z 10.0.2.2 5000"
stop_all

hdr "10. Clean restart works again"
chk "devices come up" "start_devices"
xfer pc1 pc2 10.0.2.2 5000 "$T/marker.txt" "$T/out10.txt"
chk "file arrives intact after restart" "cmp -s $T/marker.txt $T/out10.txt"

echo
echo "RESULT: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
