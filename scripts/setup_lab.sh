#!/usr/bin/env bash
# PC1 (10.0.1.2) -> Device1 -> Device2 -> PC2 (10.0.2.2), all as network namespaces.
#   PORT      protected TCP port (default 5000; matches source OR destination port,
#             so a connection started from either side is protected)
#   MSS_CLAMP MSS announced in SYNs (default 1400: leaves room for the 24-byte
#             overhead plus TCP options inside a 1500-byte MTU)
set -euo pipefail
[ "$EUID" -eq 0 ] || { echo "run with sudo"; exit 1; }
PORT="${PORT:-5000}"
MSS_CLAMP="${MSS_CLAMP:-1400}"

for ns in pc1 dev1 dev2 pc2; do ip netns add $ns; ip -n $ns link set lo up; done
ip link add p1-d1 type veth peer name d1-p1
ip link add d1-d2 type veth peer name d2-d1
ip link add d2-p2 type veth peer name p2-d2
ip link set p1-d1 netns pc1;  ip link set d1-p1 netns dev1
ip link set d1-d2 netns dev1; ip link set d2-d1 netns dev2
ip link set d2-p2 netns dev2; ip link set p2-d2 netns pc2

ip -n pc1  addr add 10.0.1.2/24  dev p1-d1
ip -n dev1 addr add 10.0.1.1/24  dev d1-p1
ip -n dev1 addr add 10.0.12.1/24 dev d1-d2
ip -n dev2 addr add 10.0.12.2/24 dev d2-d1
ip -n dev2 addr add 10.0.2.1/24  dev d2-p2
ip -n pc2  addr add 10.0.2.2/24  dev p2-d2

# Offloads must be off, otherwise the devices would see oversized / half-checksummed packets.
up() {
  ip -n "$1" link set "$2" up
  ip netns exec "$1" ethtool -K "$2" tso off gso off gro off lro off tx off rx off >/dev/null 2>&1 || true
  if ip netns exec "$1" ethtool -k "$2" 2>/dev/null | grep -Eq '^(tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload|tx-checksumming|rx-checksumming): on'; then
    echo "WARNING: could not disable all offloads on $1/$2 (check: ethtool -k $2)"
  fi
}
up pc1 p1-d1; up dev1 d1-p1; up dev1 d1-d2
up dev2 d2-d1; up dev2 d2-p2; up pc2 p2-d2

ip -n pc1  route add default via 10.0.1.1
ip -n pc2  route add default via 10.0.2.1
ip -n dev1 route add 10.0.2.0/24 via 10.0.12.2
ip -n dev2 route add 10.0.1.0/24 via 10.0.12.1
for d in dev1 dev2; do
  ip netns exec $d sysctl -qw net.ipv4.ip_forward=1
  ip netns exec $d sysctl -qw net.ipv4.conf.all.rp_filter=0
done

# Only LOWER an MSS that is too big; never raise a smaller one.
for d in dev1 dev2; do
  ip netns exec $d iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN \
    -m multiport --ports "$PORT" -m tcpmss --mss "$((MSS_CLAMP + 1)):65535" \
    -j TCPMSS --set-mss "$MSS_CLAMP"
done

# "Selected traffic" = TCP port $PORT as source OR destination, so connections
# started from either side are protected.  Queue 1 = encrypt (packet came from
# the host side), queue 2 = decrypt (packet came from the peer device).
# No --queue-bypass: if a device is down or has no session, selected traffic is DROPPED.
ip netns exec dev1 iptables -A FORWARD -i d1-p1 -p tcp -m multiport --ports "$PORT" -j NFQUEUE --queue-num 1
ip netns exec dev1 iptables -A FORWARD -i d1-d2 -p tcp -m multiport --ports "$PORT" -j NFQUEUE --queue-num 2
ip netns exec dev2 iptables -A FORWARD -i d2-p2 -p tcp -m multiport --ports "$PORT" -j NFQUEUE --queue-num 1
ip netns exec dev2 iptables -A FORWARD -i d2-d1 -p tcp -m multiport --ports "$PORT" -j NFQUEUE --queue-num 2

echo "Lab ready (protected port $PORT, MSS clamp $MSS_CLAMP)."
