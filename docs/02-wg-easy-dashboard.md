# 02 — wg-easy Dashboard (optional, self-service clients)

wg-easy (Docker image `ghcr.io/wg-easy/wg-easy:latest`, v14+, 2026) gives a web
UI where users add/remove VPN devices, view QR codes, and toggle clients —
no terminal needed. This doc covers fresh setup AND migrating an existing raw
wg-quick tunnel.

## Fresh setup

```yaml
# docker-compose.yml
services:
  wg-easy:
    image: ghcr.io/wg-easy/wg-easy:latest
    container_name: wg-easy
    restart: unless-stopped
    network_mode: host            # host netns keeps DNS/adblock at the tunnel IP working
    cap_add:
      - NET_ADMIN
    environment:
      - WG_HOST=<VPS_PUBLIC_IP>
      - PASSWORD_HASH=<BCRYPT_HASH>       # NOT PASSWORD — v14 renamed it
      - WG_PORT=51820
      - WG_DEFAULT_ADDRESS=10.66.66.x     # literal x template, NOT CIDR
      - WG_DEFAULT_DNS=10.66.66.1
      - WG_PERSISTENT_KEEPALIVE=25
      - WG_ALLOWED_IPS=0.0.0.0/0
      - TZ=America/Chicago
    volumes:
      - ./config:/etc/wireguard
```

Generate the bcrypt hash (any method; wg-easy validates it):

```bash
python3 -c "import bcrypt; print(bcrypt.hashpw(b'YOUR_PASSWORD', bcrypt.gensalt(rounds=10)).decode())"
```

```bash
docker compose up -d
# NOTE: logging is disabled for this container (driver: none) — there is
# deliberately NO `docker logs` output (zero-logging policy, see README).
# Verify via the UI/API instead:
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:51821/   # 200
docker ps --filter name=wg-easy --format '{{.Status}}'             # healthy
```

## Firewall: the legacy/nft trap (CRITICAL)

wg-easy's container ships **iptables-legacy**; modern Docker hosts use the
**nft** backend. When nft tables own a hook, the kernel **ignores legacy rules**.
Symptom signature: `wg show` shows a handshake, tunnel-DNS works (local path),
but `ping 1.1.1.1` is 100% loss and egress dies — no FORWARD accept, no
MASQUERADE in the tables that matter.

Fix: add the rules with the HOST's nft `iptables` and persist via systemd
oneshot (idempotent `-C || -A`):

```
/etc/systemd/system/wg-nft-rules.service
[Unit]
Description=WireGuard nft firewall rules (wg-easy co-resident)
After=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'iptables -t nat -C POSTROUTING -s 10.66.66.0/24 -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.66.66.0/24 -o eth0 -j MASQUERADE; iptables -C FORWARD -i wg0 -o eth0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT; iptables -C FORWARD -i eth0 -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i eth0 -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables -C INPUT -i eth0 -p tcp --dport 51821 -j DROP 2>/dev/null || iptables -A INPUT -i eth0 -p tcp --dport 51821 -j DROP'
[Install]
WantedBy=multi-user.target
```

The last rule keeps the dashboard reachable **only through the tunnel**
(10.66.66.1:51821) and localhost — never from the public internet.

## API (for scripts/agents)

All API routes need a session cookie first:

```bash
curl -s -c cookies.txt -X POST http://localhost:51821/api/session \
  -H 'Content-Type: application/json' -d '{"password":"<plain>"}'
curl -s -b cookies.txt -X POST http://localhost:51821/api/wireguard/client \
  -H 'Content-Type: application/json' -d '{"name":"My-Phone"}'   # → {"success":true}
curl -s -b cookies.txt http://localhost:51821/api/wireguard/client   # list
curl -s -b cookies.txt -X DELETE http://localhost:51821/api/wireguard/client/<id>
```

Client private keys are NOT in API responses — read the volume file:

```
config/wg0.json → clients.<uuid>.{privateKey,publicKey,preSharedKey,address}
```

`scripts/add-wg-profile.py` wraps all of this: session → create → read key →
emit `.conf` + QR.

## Migration from raw wg-quick (proven path)

1. Back up: `cp /etc/wireguard/wg0.conf /etc/wireguard/wg0.conf.pre-wgeasy`
2. `systemctl stop wg-quick@wg0 && systemctl disable wg-quick@wg0`
3. Bring up the compose stack; add the nft rules unit; `systemctl enable --now`
4. Recreate every client in the dashboard (new server key = all clients must
   re-import profiles; expect it)
5. Re-run `scripts/verify-tunnel.sh` against a freshly minted client key

## Pitfalls (all hit in one real migration, Aug 2026)

- **Env var is `PASSWORD_HASH`, not `PASSWORD`** — wrong name = deliberate
  crash at boot.
- **`$` in the bcrypt hash must be `$$`-escaped** in compose env values or
  compose interpolation blanks part of the hash.
- **`WG_DEFAULT_ADDRESS=10.66.66.x`** — literal `x` template, NOT CIDR.
  (`/24` produces `Address = 10.66.66.0/24/24` → wg-quick error.)
- **No `sysctls:` with `network_mode: host`** — runc rejects them; set
  ip_forward via sysctl.d on the host instead.
- **Stale volume config** — `config/wg0.conf` + `wg0.json` are loaded over env
  changes; wipe them to force regeneration.
- **AdGuard boot race** — if AdGuard binds the tunnel IP, set its unit
  `After=docker.service` and keep `Restart=on-failure` (wg0 appears when the
  container starts; AdGuard retries until the IP exists).
- **wg-easy is IPv4-only** (no NAT6). Clients get `AllowedIPs 0.0.0.0/0`;
  phone IPv6 goes direct (leak, but functional). Tell the user.
