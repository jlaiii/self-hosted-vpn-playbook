# 04 — Health Monitoring (zero tokens + AI autofix)

Two cron jobs keep the VPN stack healthy with **zero LLM tokens on the
watchdog** and an AI that only wakes up to fix things when flagged.

## Architecture

```
watchdog (no_agent, every 5m)          autofix (LLM agent, every 2h fallback)
  runs vpn-health-check.py (v3)          receives watchdog output (context_from)
  checks: container, wg0, 51820,         if FLAG: lines present → diagnose + fix
  nft rules, AdGuard DNS, blocking       if clean → stay silent
  healthy → prints nothing (silent)      reports only when it fixed something
  broken → FLAG: lines
    ├─ Tier 1 (token-free): scripted fixes (restart units, re-apply nft
    │    rules, restart wg-easy, journal/apt cleanup on disk pressure,
    │    restart failed systemd units), then re-check; clean → detailed
    │    "auto-fixed" notice, exit 0 — no LLM tokens spent
    ├─ flags that survive → INCIDENTS_LOG + /tmp/vpn-last-flags.txt
    │    (bridge file the woken AI reads FIRST) + event-driven wake
    └─ delivered to the user (alert)
```

The watchdog is pure script execution — no model, no tokens. System checks
(RAM/CPU/disk/failed units) run FIRST each tick so the egress and speed tests
don't skew the load reading; a full Ookla test only runs on a cadence
(`SPEEDTEST_EVERY_S`, default 1800s = 30 min — it saturates the uplink ~20 s,
so it never runs every 5-min tick). Every flagged event is ALSO appended to
`INCIDENTS_LOG` (JSONL, capped) so the dashboard's Watchdog tab can show what
was found and what was done about it.

## The health-check script

`scripts/vpn-health-check.py` — parameterized via env vars (defaults match this
playbook): `WG_SUBNET=10.66.66.0/24`, `WG_IF=wg0`, `WG_PORT=51820`,
`UI_PORT=51821`, `DNS_IP=10.66.66.1`, `CONTAINER=wg-easy`, `ADGUARD_UNIT=adguardhome`,
`INCIDENTS_LOG=<dashboard data dir>/vpn-incidents.jsonl`,
`WD_CONFIG_FILE=<dashboard data dir>/watchdog-config.json` (the dashboard's
Watchdog tab is the source of truth for the SYSTEM thresholds when it has
saved values), `ADD_WG_PROFILE_CMD` (tier-1 healthcheck-client recreate —
portable installs set `bash /usr/local/bin/add-wg-profile.py healthcheck`).

Checks (each failure prints a `FLAG:` line):

1. wg-easy container running + healthy ("starting" warmup is not a flag)
2. wg0 interface up, port 51820/udp listening
3. nft rules present: MASQUERADE, 2x FORWARD accept, UI-port public block,
   2x MSS clamp (eth0 MTU 1400 + wg0 MTU 1320 require clamped MSS 1240 —
   without it, big sites like DDG stall on TLS while small sites work)
4. AdGuard unit active + answering on the tunnel IP
5. Ad blocking still effective (test domain resolves to 0.0.0.0)
6. `wg-nft-rules.service` enabled (survives reboot)
7. Dashboard unit active + HTTP 200 on the tunnel IP
8. **Peer endpoint sanity** — any real device peer showing a private/test
   endpoint means a stale test rig or dead client is holding its tunnel slot
   (this is the failure where a phone shows "connected" but has no internet).
   The dedicated healthcheck peer is exempt (it legitimately uses the test IP).
9. **Active egress test** — every run spins a throwaway WireGuard client in a
   netns using the dedicated `healthcheck` peer's key and proves real traffic:
   handshake → ICMP to 1.1.1.1 → HTTPS egress with the expected public IP.
   Catches forwarding/NAT/routing breakage that presence checks miss.
10. **Rejected-handshake detector** — captures inbound UDP on the WG port for
    15s and flags public sources sending repeated handshake-inits (length 148)
    that don't match any recently-handshaken peer. This is the "device has an
    outdated/foreign profile" failure: WireGuard silently ignores them, so the
    device shows "connected" but has no internet.
11. **On-cadence speed test** — Ookla every `SPEEDTEST_EVERY_S` (default 30
    min), flags when down/up/ping breach thresholds (defaults 50 Mbps / 30
    Mbps / 100 ms). Slow flags have NO scripted fix — they go to the AI tier.
12. SYSTEM: memory pressure — RAM % ≥ `RAM_PCT_MAX` (90) and/or swap ≥ 50%.
    No scripted fix — the AI investigates top consumers.
13. SYSTEM: sustained CPU load — 5-min loadavg ≥ cores × `LOAD_FACTOR` (2.0).
    No scripted fix — the AI investigates top processes.
14. SYSTEM: root disk — % ≥ `DISK_PCT_MAX` (85, warn) / `DISK_CRIT_PCT` (95).
    Tier 1: `journalctl --vacuum-size=200M && apt-get clean` (safe, no-op when
    already small); still over → AI tier.
15. SYSTEM: failed systemd units — Tier 1 restarts them; still failed → the AI
    reads their logs and reports the cause.

(The production host this playbook was curated from additionally runs a
16th check — exit-provider sandbox sanity. It skips itself cleanly when
`EXIT_STATE` doesn't exist, so plain playbook installs run the 15 checks
above; the script never hard-depends on box-specific files.)

## Event-driven AI wake (tokens only when broken)

When the watchdog finds flags it also wakes the autofix agent immediately:
`hermes cron run vpn-autofix` with a 30-minute cooldown state file
(`/tmp/vpn-autofix-trigger.ts`). The autofix job also runs a silent fallback
sweep every 2h in case the trigger path ever fails. Healthy ticks cost zero
tokens; the AI only spends tokens when something is actually wrong.

Testing hook: `CAPTURE_FILE=<file>` feeds saved tcpdump output to the
rejected-handshake detector instead of a live capture; `ALLOW_PRIVATE_PROBE=1`
disables the private-IP skip for drills. Note: `-i any` does not see veth
traffic on some kernels — the probe captures on eth0 (where real clients
arrive). Note: Python's `ipaddress` classifies TEST-NET ranges
(203.0.113.0/24 etc.) as private — don't use them as drill IPs.

Setup requirement: create the healthcheck peer once —
`bash /usr/local/bin/add-wg-profile.py healthcheck` (its key lives in the
wg-easy volume; the script reads it from wg0.json). The `setup-vpn.sh`
installer creates it automatically.

The `scripts/setup-vpn.sh` installer wires all of the above automatically,
including a plain-cron watchdog entry (no Hermes required):

```cron
*/5 * * * * root WG_EASY_CONFIG=/opt/vpn-stack/config/wg0.json DASH_URL=http://10.66.66.1:8088/ INCIDENTS_LOG=/opt/vpn-stack/dashboard/data/vpn-incidents.jsonl WD_CONFIG_FILE=/opt/vpn-stack/dashboard/data/watchdog-config.json "ADD_WG_PROFILE_CMD=bash /usr/local/bin/add-wg-profile.py healthcheck" python3 /usr/local/bin/vpn-health-check.py
```

For Hermes hosts, instead use the two cron jobs described below (the watchdog
also wakes the autofix event-driven on flags).

Exit 0 when clean (silent — nothing delivered). Non-zero + FLAG lines when
broken (delivered as the alert).

## Cron job recipes (Hermes Agent)

```
# 1. Watchdog — no tokens, script-only
cronjob(action='create', name='vpn-watchdog', schedule='every 5m',
        no_agent=True, script='vpn-health-check.py', deliver='origin')

# 2. Autofix — cheap model, only acts on flags (2h silent fallback sweep;
#    the watchdog normally wakes it event-driven within seconds of a flag)
cronjob(action='create', name='vpn-autofix', schedule='every 2h',
        context_from=['<watchdog_job_id>'], deliver='origin',
        model={'model': '<cheap-model>', 'provider': '<provider>'},
        enabled_toolsets=['terminal', 'file'],
        prompt='''You are the VPN autofix agent for a WireGuard (wg-easy) +
AdGuard Home stack. READ /tmp/vpn-last-flags.txt FIRST if it exists (it is
the watchdog's flag bridge and is authoritative over any injected context).
Rules:
1. If there are NO "FLAG:" lines: the stack is healthy. Do nothing.
   Reply with exactly nothing.
2. If there ARE "FLAG:" lines: diagnose and fix each issue. You may:
   - restart containers (docker restart wg-easy) or units (systemctl restart adguardhome)
   - re-add missing nft rules (see wg-nft-rules.service for the exact commands)
   - restart the wg-nft-rules unit if rules vanished
   - vacuum the journal / clean apt cache on SYSTEM: root disk flags
   - restart failed systemd units named in SYSTEM flags (read their logs first)
   - wipe stale wg-easy volume configs only as a last resort (container in crash loop)
   - NEVER modify the adguardhome blocklist config or the docker-compose env
   - NEVER reboot the host
3. After fixing, re-run the health check (/usr/local/bin/vpn-health-check.py
   on installer hosts, ~/.hermes/scripts/vpn-health-check.py on Hermes hosts)
   and confirm it prints nothing.
4. Report concisely: what was flagged, what you did, and the verification
   result. If you could not fix something, say exactly what remains broken.''')
```

## Why the AI wakes up

`context_from` injects the watchdog's most recent completed output into the
autofix prompt. Healthy ticks print nothing, so the autofix sees an empty
report and stays silent (zero-token rounds). Broken ticks carry `FLAG:` lines
with precise failure descriptions, so the autofix has a concrete work list
instead of guessing.

## Pitfalls

- **Keep the watchdog `no_agent`** — an LLM watchdog at 5-minute cadence burns
  tokens 24/7 for nothing. Script-only is free and faster.
- **The health check must be silent when healthy** — otherwise the user gets
  pings every 5 minutes forever.
- **Don't let the autofix spam "all good" reports** — instruct it to reply with
  nothing when there are no flags.
- **Give the autofix narrow scope** (restart services, restore rules) — broad
  autonomy invites config drift. Explicitly forbid touching blocklists and
  compose env values.
- **Check both the watchdog AND the autofix periodically** — a watchdog that
  never prints is ambiguous (healthy OR broken script). Verify manually once
  a week: run the script, then break something on purpose and watch the flag.
