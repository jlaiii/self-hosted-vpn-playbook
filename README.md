# Self-Hosted VPN Playbook

A complete, battle-tested playbook for standing up a personal WireGuard VPN
exit node on a Linux VPS — with phone-wide DNS ad-blocking, a self-service
device dashboard, a stats dashboard, a zero-token health watchdog, and an
AI autofix pattern. **Zero-logging by default**: no DNS query history, no
connection logs, no per-client statistics (see Zero-logging policy below).
Written for humans **and AI agents**: every step is scripted, parameterized,
and documented with the pitfalls that actually break things in production.

## Stack

| Component | What it does |
|---|---|
| WireGuard (via [wg-easy](https://github.com/wg-easy/wg-easy)) | Kernel-speed VPN tunnel, web UI to add/remove devices and show QR codes |
| AdGuard Home *(optional)* | DNS ad/tracker blocking for every device on the tunnel (~450k rules, auto-updating) |
| Stats dashboard (Flask) | CPU/RAM/disk/network, live VPS public IP (ip.me check), VPN devices with tunnel + real-world IPs, containers, on-demand Ookla speed tests — tunnel-only, mobile-first, **zero log features**. Reboot button + PWA shell included |
| `vpn-health-check.py` | Watchdog **v3**: 16 checks (15 on hosts without the exit-provider sandbox) — services, firewall rules, MSS clamp, ad-blocking, endpoint sanity, rejected-handshake detection, live egress test, on-cadence Ookla speed test, plus SYSTEM checks (RAM/CPU/disk/failed units). Tiered: silent when healthy (zero tokens), scripted auto-fix on flags, `FLAG:` lines when broken |
| `add-wg-profile.py` | Mint device profiles (QR + .conf) from the CLI — an AI agent can hand a profile to a user in one command |
| `setup-vpn.sh` | **One-command installer** for the entire stack on a fresh VPS |

## Quick start (one command)

```bash
sudo VPS_IP=203.0.113.10 UI_PASSWORD='PickAStrongPassword' \
  bash scripts/setup-vpn.sh --with-adguard --with-speedtest
```

Requirements: a fresh Ubuntu/Debian VPS with a public IP, UDP allowed, root
access. The script installs Docker, starts wg-easy, installs the firewall +
MSS-clamp rules (persisted via systemd), deploys the stats dashboard, installs
the watchdog cron, creates the `healthcheck` peer, and runs a full verification
pass before printing the summary.

Options:
- `--with-adguard` — AdGuard Home on the tunnel IP (DNS ad-blocking)
- `--with-speedtest` — Ookla CLI for the dashboard's speed-test tab
- Env: `WG_SUBNET=10.66.66.0/24`, `DNS_IP`, `WG_PORT=51820`, `UI_PORT=51821`,
  `DASH_PORT=8088`, `MSS_VALUE=1240`, `INSTALL_DIR=/opt/vpn-stack`

After it finishes: open `http://<DNS_IP>:<UI_PORT>` **while connected to the
VPN** (everything is tunnel-only by design — nothing is exposed publicly).

## Manual build (read the docs)

1. [docs/01-wireguard-vpn.md](docs/01-wireguard-vpn.md) — tunnel core, NAT,
   Docker's FORWARD-policy trap, iPhone onboarding, verification
2. [docs/02-wg-easy-dashboard.md](docs/02-wg-easy-dashboard.md) — self-service
   dashboard, migration, wg-easy v14 API quirks
3. [docs/03-adguard-home.md](docs/03-adguard-home.md) — DNS ad-blocking setup
4. [docs/04-health-monitoring.md](docs/04-health-monitoring.md) — the watchdog
   and cron wiring (Hermes cron jobs and plain-cron equivalents)

## Health monitoring (the important part)

`scripts/vpn-health-check.py` is the watchdog. **Healthy tick = no output,
exit 0** — wire it into any scheduler and it costs nothing:

```cron
*/5 * * * * root INCIDENTS_LOG=/opt/vpn-stack/dashboard/data/vpn-incidents.jsonl \
  WD_CONFIG_FILE=/opt/vpn-stack/dashboard/data/watchdog-config.json \
  python3 /usr/local/bin/vpn-health-check.py
```

Its checks (all env-parameterized; 16 on hosts with the exit-provider
sandbox, 15 without — every box-specific path skips cleanly when its state
file is absent):

1. wg-easy container running + healthy
2. wg0 up, UDP port listening
3. NAT MASQUERADE rule present
4. FORWARD accept rules present (both directions)
5. UI port public-block rule present (dashboard not exposed)
6. **MSS clamp rules present** — without them, sites that send full-size TLS
   records (DuckDuckGo on Azure is the canonical case) stall while Google works
7. AdGuard answering on the tunnel IP + ad blocking still effective
8. Rules unit enabled (survives reboot)
9. Dashboard unit active + HTTP 200
10. **Peer endpoint sanity** — a real device showing a private/test endpoint
    means a stale rig is holding its tunnel slot ("connected but no internet")
11. **Active egress test** — spins a throwaway WireGuard client (the dedicated
    `healthcheck` peer) in a netns: real handshake, ICMP, HTTPS egress with the
    expected public IP. Catches forwarding/NAT/routing breakage that presence
    checks miss.
12. **On-cadence speed test** — Ookla CLI every `SPEEDTEST_EVERY_S` (default
    30 min — a full test saturates the uplink ~20 s, so it never runs each
    5-min tick). Flags on down/up/ping thresholds only.
13. SYSTEM: memory pressure (RAM % and/or swap) — no scripted fix, AI tier
14. SYSTEM: sustained CPU load (5-min avg vs cores × factor) — AI tier
15. SYSTEM: root disk % — Tier 1 vacuums journal + apt cache first
16. SYSTEM: failed systemd units — Tier 1 restarts them, AI investigates
    persisting failures

System checks (13-16) run FIRST each tick so the egress/speed tests don't
skew the load reading.

Plus a **rejected-handshake detector**: a 15s capture on the WG port flags
public IPs sending repeated handshake-inits (length 148) that match no live
peer — the "device has an outdated/foreign profile" failure where WireGuard
silently ignores the client. The alert names the IP and the fix.

### AI autofix (Hermes)

On Hermes hosts, pair the watchdog with an autofix job:

- `vpn-watchdog` — `no_agent: true`, `every 5m`, script = the health check.
  Silent = nothing delivered. Flags = alert + it wakes the AI.
- `vpn-autofix` — prompt-based, `every 2h` fallback sweep, `context_from`
  the watchdog. **The watchdog also wakes it event-driven** on flags
  (`hermes cron run vpn-autofix`, 30-min cooldown file), so tokens are spent
  only when something is actually broken. The autofix knows the fix for every
  flag type and reports the unfixable ones (e.g. outdated device profiles)
  with exact user instructions.

Full prompts and wiring: [docs/04-health-monitoring.md](docs/04-health-monitoring.md).

## Zero-logging policy (default)

The stack ships with a strict no-history posture:

| Layer | Logging state |
|---|---|
| WireGuard kernel module | Never logs traffic — only live rx/tx counters (nothing to disable) |
| AdGuard Home | `querylog.enabled: false` + `file_enabled: false`, `statistics.enabled: false` — no DNS history, no counters, no `querylog.json` |
| wg-easy | `logging: driver: none` — the container writes no log at all (`docker logs` is empty by design) |
| Stats dashboard | No Logs tab, no `/api/logs*` endpoints, no toggle — the logging feature is removed, not hidden |

`setup-vpn.sh` pins all of this automatically, including a post-migration
enforcement step (AGH's first-start config migration can flip the flags
back ON). On manual installs, patch the migrated yaml by hand (docs/03).

Logins are unaffected: the wg-easy UI still requires its password (it
hard-requires `PASSWORD_HASH`) and AdGuard keeps its admin login.

If you ever re-enable DNS logging: set querylog `enabled: true` and restart
AGH (its file writer only initializes when enabled at startup). Disabling
again requires `querylog_clear`, REMOVING `querylog.json` (a truncated file
breaks AGH's file-writer init), then writing `enabled: false` into the yaml
and restarting.

The dashboard's VPN tab shows what IS live — and only live: the server's
public IP (checked via ip.me, cached 15 min) plus each device's tunnel IP
(`10.66.66.x`) and its real-world source IP. Transient display only; never
appended to any history file.

## Pitfalls (all discovered the hard way — all handled)

- **Docker sets FORWARD policy to DROP** — tunnel forwarding dies silently
- **`iptables-legacy` vs `iptables-nft`** — wg-easy's container uses legacy
  tables; on nft-based hosts its rules are inert and must be re-added with
  the host's nft `iptables`
- **wg-easy v14**: env var is `PASSWORD_HASH` (bcrypt), `WG_DEFAULT_ADDRESS`
  wants `10.x.x.x` (with literal `x`), and a stale volume `wg0.conf` survives
  env changes — delete it to regenerate
- **MTU chain**: provider eth0 MTU 1400 + wg0 MTU 1320 + client MTU 1400
  without MSS clamping = big sites stall (DDG), small sites work (Google)
- **Ookla CLI crashes without `HOME`** — systemd units need `Environment=HOME`
- **Same client key on two endpoints** — handshakes bounce, the real device
  gets "connected but no internet" (the watchdog's peer-endpoint-sanity check
  catches it)
- **systemd + netns tests**: never reuse a real device's key for tests; the
  `healthcheck` peer exists for exactly this
- **`tcpdump -i any` misses veth traffic on some kernels** — capture on the
  public interface
- **wg-easy with `logging: driver: none` produces no `docker logs` output** —
  an empty log is the zero-logging design, not a crash; verify via the UI
  (`curl :51821` → 200) and `docker ps` health instead

## Repo layout

```
scripts/
  setup-vpn.sh         one-command installer (fresh VPS)
  vpn-health-check.py  watchdog v3 — silent when healthy, zero tokens
  add-wg-profile.py    mint device profiles (QR + .conf) via the wg-easy API
  reboot_system.py     reboot helper for the dashboard's Server button
  verify-tunnel.sh     netns end-to-end tunnel test
dashboard/
  app.py + templates/  tunnel-only stats dashboard (Flask + psutil)
  static/              PWA shell (manifest, service worker, icons)
docker-compose.wg-easy.yml   template for manual builds
docs/                  01 tunnel · 02 wg-easy · 03 AdGuard · 04 monitoring
```

> **Portability note (keeps this repo honest):** the dashboard in this repo
> is the portable subset of the production dashboard it was curated from.
> Box-specific extras — VPN exit-provider switching (Direct/WARP/Mullvad
> sandbox), DeepSeek spend tracking, and the Hermes auto-updater cards — are
> deliberately NOT included. They only make sense on the original host and
> would break a fresh install (the exit-provider module is a hard import in
> the full version). When syncing newer changes in, re-curate with the same
> rule: keep everything a standalone VPS can use, drop what is host-bound.

## License

MIT — see LICENSE.
