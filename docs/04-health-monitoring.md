# 04 — Health Monitoring (zero tokens + AI autofix)

Two cron jobs keep the VPN stack healthy with **zero LLM tokens on the
watchdog** and an AI that only wakes up to fix things when flagged.

## Architecture

```
watchdog (no_agent, every 5m)          autofix (LLM agent, every 30m)
  runs vpn-health-check.py               receives watchdog output (context_from)
  checks: container, wg0, 51820,         if FLAG: lines present → diagnose + fix
  nft rules, AdGuard DNS, blocking       if clean → stay silent
  healthy → prints nothing (silent)      reports only when it fixed something
  broken → prints FLAG: lines
  └─ delivered to the user (alert)
```

The watchdog is pure script execution — no model, no tokens. The autofix job
uses the cheapest available model and only spends tokens when something is
actually broken.

## The health-check script

`scripts/vpn-health-check.py` — parameterized via env vars (defaults match this
playbook): `WG_SUBNET=10.66.66.0/24`, `WG_IF=wg0`, `WG_PORT=51820`,
`UI_PORT=51821`, `DNS_IP=10.66.66.1`, `CONTAINER=wg-easy`, `ADGUARD_UNIT=adguardhome`.

Checks (each failure prints a `FLAG:` line):

1. wg-easy container running + healthy ("starting" warmup is not a flag)
2. wg0 interface up, port 51820/udp listening
3. nft rules present: MASQUERADE, 2x FORWARD accept, UI-port public block
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
   handshake → ICMP to 1.1.1.1 → HTTPS egress with the server's public IP.
   Catches forwarding/NAT/routing breakage that presence checks miss.

Setup requirement: create the healthcheck peer once —
`bash /root/wg-easy/add-wg-profile.sh healthcheck` (its key lives in the
wg-easy volume; the script reads it from wg0.json).

Exit 0 when clean (silent — nothing delivered). Non-zero + FLAG lines when
broken (delivered as the alert).

## Cron job recipes (Hermes Agent)

```
# 1. Watchdog — no tokens, script-only
cronjob(action='create', name='vpn-watchdog', schedule='every 5m',
        no_agent=True, script='vpn-health-check.py', deliver='origin')

# 2. Autofix — cheap model, only acts on flags
cronjob(action='create', name='vpn-autofix', schedule='every 30m',
        context_from=['<watchdog_job_id>'], deliver='origin',
        model={'model': '<cheap-model>', 'provider': '<provider>'},
        enabled_toolsets=['terminal', 'file'],
        prompt='''You are the VPN autofix agent for a WireGuard (wg-easy) +
AdGuard Home stack. The latest watchdog output is injected above.
Rules:
1. If there are NO "FLAG:" lines: the stack is healthy. Do nothing.
   Reply with exactly nothing.
2. If there ARE "FLAG:" lines: diagnose and fix each issue. You may:
   - restart containers (docker restart wg-easy) or units (systemctl restart adguardhome)
   - re-add missing nft rules (see wg-nft-rules.service for the exact commands)
   - restart the wg-nft-rules unit if rules vanished
   - wipe stale wg-easy volume configs only as a last resort (container in crash loop)
   - NEVER modify the adguardhome blocklist config or the docker-compose env
3. After fixing, re-run scripts/vpn-health-check.py (at ~/.hermes/scripts/) and
   confirm it prints nothing.
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
