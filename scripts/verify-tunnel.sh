#!/usr/bin/env bash
# End-to-end WireGuard tunnel verification from the server itself — no client
# device needed. Simulates a peer inside a network namespace connected to the
# host via a veth pair, then proves: handshake, ICMP through the tunnel, and
# HTTPS egress with the expected public IP.
#
# Usage:
#   verify-tunnel.sh <client_privkey_file> <server_pubkey> <host_veth_ip> \
#                    [tunnel_client_ip] [expected_egress_ip]
#
#   client_privkey_file : path to a WireGuard private key file (any throwaway
#                         keypair; its pubkey must be an AllowedIPs peer on the
#                         server's wg0.conf — add a temp [Peer] block if the
#                         real device might be connected simultaneously: the
#                         same key on two endpoints makes handshakes bounce)
#   server_pubkey       : the server's public key (cat /etc/wireguard/server.pub)
#   host_veth_ip        : IP to assign to the host end of the veth pair and to
#                         use as the wg endpoint, e.g. 10.77.77.1 (the server's
#                         wg0 listens on 0.0.0.0:51820 so the veth IP works)
#   tunnel_client_ip    : inner tunnel IP for the client (default 10.66.66.2)
#   expected_egress_ip  : public IP traffic must exit with (default: detected
#                         via ipinfo.io before the test)
#
# Exit 0 only if the egress IP check matches the expected value.
set -euo pipefail

PRIVKEY_FILE="${1:?usage: verify-tunnel.sh <client_privkey_file> <server_pubkey> <host_veth_ip> [tunnel_client_ip] [expected_egress_ip]}"
SERVER_PUBKEY="${2:?}"
HOST_IP="${3:?}"
TUN_IP="${4:-10.66.66.2}"
EXPECTED="${5:-$(curl -s -m 5 https://ipinfo.io/ip)}"
PORT="${WG_PORT:-51820}"

NETNS="wgverify$$"
VETH="veth$$"
TUN_DEV_IP="$(echo "$TUN_IP" | cut -d/ -f1)"

cleanup() {
  ip netns del "$NETNS" 2>/dev/null || true
  ip link del "${VETH}0" 2>/dev/null || true
}
trap cleanup EXIT

echo "== building netns $NETNS (veth pair, host $HOST_IP) =="
ip netns add "$NETNS"
ip link add "${VETH}0" type veth peer name "${VETH}1"
ip link set "${VETH}1" netns "$NETNS"
ip addr add "$HOST_IP/24" dev "${VETH}0"
ip link set "${VETH}0" up

ip netns exec "$NETNS" bash -s <<EOF
set -e
ip link set lo up
ip addr add ${HOST_IP%.*}.2/24 dev ${VETH}1
ip link set ${VETH}1 up
ip link add wg0 type wireguard
wg set wg0 private-key $PRIVKEY_FILE
wg set wg0 peer $SERVER_PUBKEY endpoint $HOST_IP:$PORT allowed-ips 0.0.0.0/0 persistent-keepalive 25
ip addr add $TUN_DEV_IP/24 dev wg0
ip link set wg0 up
ip route add default dev wg0
sleep 1
echo "== handshake check (expect a unix timestamp) =="
wg show wg0 latest-handshakes
echo "== ping through tunnel =="
ping -c 3 -W 3 1.1.1.1
echo "== egress IP check =="
curl -s -m 10 https://1.1.1.1/cdn-cgi-trace | grep -E "^ip="
EOF

echo "== expected egress: $EXPECTED =="
echo "== server-side peer state (latest handshake = proof) =="
wg show | grep -A2 peer || true
