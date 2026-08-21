# Self-Hosted VPN Playbook

A complete, battle-tested playbook for standing up a personal WireGuard VPN exit
node on a Linux VPS, with phone-wide DNS ad-blocking, a self-service client
dashboard, and autonomous health monitoring. Written for both humans and AI
agents (tested with Hermes Agent on Ubuntu 24.04, Docker co-resident).

**What you get:**

- WireGuard tunnel — your phone's traffic egresses from your VPS IP
- AdGuard Home — DNS-level ad/tracker blocking for every app, auto-updating lists
- wg-easy dashboard (optional) — add/remove VPN devices from a web UI, no terminal
- Profile generator script — one command to mint a new device profile + QR code
- Health watchdog + AI autofix crons — silent when healthy, self-healing when broken

## Architecture

```
iPhone/Android (WireGuard app)
      │  UDP 51820 (encrypted)
      ▼
┌─────────────────────────────────────────────┐
│                    VPS                       │
│  wg-easy (Docker, host netns)                │
│    └─ wg0 interface — 10.66.66.1/24          │
│        ├─ DNS queries → AdGuard Home :53     │
│        │     (filters ads, upstream DoH)     │
│        └─ other traffic → MASQUERADE → eth0  │
│  nft rules (wg-nft-rules.service)            │
│  Health watchdog cron → AI autofix cron      │
└─────────────────────────────────────────────┘
```

## Prerequisites

- Any Linux VPS with a public IPv4 (1GB RAM, Ubuntu 22.04/24.04 tested)
- Docker + Docker Compose v2 (only if you want the wg-easy dashboard)
- Domain not required — raw IP is fine
- Client apps: [WireGuard for iOS](https://apps.apple.com/us/app/wireguard/id1441195209) /
  [WireGuard for Android](https://play.google.com/store/apps/details?id=com.wireguard.android)

## Docs (read in order)

1. [docs/01-wireguard-vpn.md](docs/01-wireguard-vpn.md) — core VPN: keys, config, NAT,
   Docker coexistence, iPhone onboarding, end-to-end verification without a phone
2. [docs/02-wg-easy-dashboard.md](docs/02-wg-easy-dashboard.md) — optional self-service
   dashboard: compose stack, migration from raw wg-quick, migration pitfalls
3. [docs/03-adguard-home.md](docs/03-adguard-home.md) — ad/tracker blocking at the DNS
   level, filter lists, auto-updates, pointing the tunnel at it
4. [docs/04-health-monitoring.md](docs/04-health-monitoring.md) — zero-token health
   watchdog cron + AI autofix cron that repairs the stack when flags appear

## Scripts

| Script | Purpose |
|---|---|
| `scripts/add-wg-profile.py` | Mint a new device profile + QR via the wg-easy API (one command) |
| `scripts/vpn-health-check.py` | Silent-when-healthy watchdog; prints `FLAG:` lines when broken |
| `scripts/verify-tunnel.sh` | Full netns end-to-end test: handshake, ICMP, egress IP, DNS |
| `docker-compose.wg-easy.yml` | wg-easy template (edit placeholders before use) |

## Quick start (30 minutes)

1. Read `docs/01-wireguard-vpn.md` and build the core tunnel; verify with
   `scripts/verify-tunnel.sh` BEFORE touching a phone
2. Add `docs/03-adguard-home.md`; point client DNS at the tunnel IP
3. (Optional) `docs/02-wg-easy-dashboard.md` for the self-service UI
4. Set up `docs/04-health-monitoring.md` crons so the stack self-heals

## License

MIT — see [LICENSE](LICENSE). Use it, fork it, teach your agents with it.
