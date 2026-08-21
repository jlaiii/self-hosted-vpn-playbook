# 01 — WireGuard VPN Core

Stand up a self-hosted WireGuard exit on a Linux VPS and provision clients
(iPhone primary use case) via QR code. Proven on Ubuntu 24.04 with Docker
co-resident. Roughly 15 minutes.

## Tool choice (2026 consensus)

| Option | Verdict | Setup | Speed | Third party |
|---|---|---|---|---|
| **WireGuard** | Best for full control + performance | ~15 min, manual per device | Kernel-level, near link speed | None |
| **Tailscale** | Easiest DIY, mesh, NAT traversal | <1 min in-app | ~10-15% tax (userspace) | Yes — control plane |
| **OpenVPN** | Legacy / TCP:443 masquerade only | Hours, PKI certs | 3-4x slower | None |
| **Headscale** | Tailscale UX, self-hosted control plane | More moving parts | Same as Tailscale | None |

Rule: for ONE phone exiting through a VPS that already has a public IP, use
WireGuard — Tailscale's wins (NAT traversal, multi-device mesh, no
port-forwarding) don't apply. Caveat either way: streaming services may block
datacenter IPs.

## 1. Install + keys

```bash
apt-get install -y wireguard wireguard-tools qrencode iptables
mkdir -p /etc/wireguard && chmod 700 /etc/wireguard && umask 077
wg genkey > /etc/wireguard/server.key
wg pubkey < /etc/wireguard/server.key > /etc/wireguard/server.pub
wg genkey > /etc/wireguard/client.key
wg pubkey < /etc/wireguard/client.key > /etc/wireguard/client.pub
```

## 2. Server config — /etc/wireguard/wg0.conf

Dual-stack, Docker-coexistent (see Pitfalls):

```ini
[Interface]
Address = 10.66.66.1/24, fd00:66:66::1/64
ListenPort = 51820
PrivateKey = <server.key>
PostUp = iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o eth0 -j MASQUERADE
PostUp = ip6tables -t nat -A POSTROUTING -s fd00:66:66::/64 -o eth0 -j MASQUERADE
PostUp = iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT
PostUp = iptables -A FORWARD -i eth0 -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
PostUp = ip6tables -A FORWARD -i wg0 -o eth0 -j ACCEPT
PostUp = ip6tables -A FORWARD -i eth0 -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
PostDown = <mirror each PostUp with -D>
[Peer]
PublicKey = <client.pub>
AllowedIPs = 10.66.66.2/32, fd00:66:66::2/128
```

```bash
cat > /etc/sysctl.d/99-wireguard.conf <<EOF
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF
sysctl --system -q
systemctl enable --now wg-quick@wg0
```

## 3. Client config (phone, full tunnel)

```ini
[Interface]
PrivateKey = <client.key>
Address = 10.66.66.2/24, fd00:66:66::2/64
DNS = 1.1.1.1

[Peer]
PublicKey = <server.pub>
Endpoint = <PUBLIC_IP>:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

- `AllowedIPs 0.0.0.0/0, ::/0` = full tunnel. MUST include `::/0` — phones on
  cellular get IPv6 and v6 traffic bypasses an IPv4-only tunnel (leak).
- `PersistentKeepalive = 25` keeps the CGNAT binding alive behind cellular.
- QR: `qrencode -t PNG -o wg-qr.png -s 10 -m 4 < client.conf`. The conf holds
  the client private key — fine in the owner's own DM, never shared channels.

## 4. Verify BEFORE handing over (no phone needed)

Run `scripts/verify-tunnel.sh` — network namespace + veth pair + a WireGuard
client inside the netns proving: handshake, ICMP through the tunnel, and HTTPS
egress with the server's public IP (`curl https://1.1.1.1/cdn-cgi/trace` →
`ip=` line; no DNS needed inside the netns). Use a throwaway keypair + temp
`[Peer]` block if the real device might connect simultaneously (same key on two
endpoints makes handshakes bounce).

## 5. Phone onboarding

1. Install the official WireGuard app (free, App Store / Play Store)
2. **+** → **Create from QR code** → scan the delivered image
3. Toggle to connect; optional On-Demand: tunnel → Edit → On-Demand Activation
   → Cellular + Wi-Fi on (auto-connects off home wifi)
4. Server-side proof: `wg show wg0` — a `latest handshake` timestamp on the
   peer means the phone is inside the tunnel. Phone-side: ip.me shows the VPS IP.

## Operations

- **Add a peer:** new keypair, append `[Peer]` block, `wg syncconf wg0
  <(wg-quick strip wg0)` (no downtime) or restart the unit.
- **Reboot safety:** `systemctl enable wg-quick@wg0` + PostUp rules = fully
  self-restoring.
- **Kernel module** (in-kernel on 5.6+/6.x) loads on interface up —
  `lsmod | grep wireguard` empty before first `wg-quick up` is normal.

## Pitfalls

- **Docker sets FORWARD policy to DROP — kills all forwarded VPN traffic
  silently.** Handshake completes, interface looks up, zero packets flow.
  ALWAYS add the FORWARD ACCEPT rules above when Docker is co-resident.
  Check: `iptables -L FORWARD -n` (policy DROP + DOCKER-USER chain = trigger).
- **Generic UDP port checkers report "closed" for a working WireGuard server**
  — wg answers only valid handshake packets. Never verify with nmap/online UDP
  checkers; use the netns test or the real client.
- **ufw inactive is fine** — raw iptables rules handle it. If ufw IS active,
  additionally `ufw allow 51820/udp`.
- **`DNS=` belongs in the CLIENT config only** — server-side it pulls in
  resolvconf deps.
- **Old wireguard-tools version (v1.0.20210914 on Ubuntu 24.04) is fine** —
  crypto is in-kernel; tools are just key/config plumbing.
- **Restarting wg-quick drops all tunnels** for a second — prefer `wg syncconf`
  when adding peers on a live box.
- **Hermes terminal lifecycle guard bug:** shell chains that `chmod +x` then
  invoke a binary can crash the guard (null-byte bug in lifecycle_guard.py).
  Workaround: stage files in /opt (write_file), `mv` them into /etc, and let
  systemd exec the binary.
