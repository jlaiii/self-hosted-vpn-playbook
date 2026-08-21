#!/usr/bin/env python3
"""VPN stack health watchdog (wg-easy + AdGuard Home).

Prints NOTHING and exits 0 when healthy (no_agent cron => silent tick).
Prints "FLAG:" lines and exits non-zero when broken (cron delivers the
output as an alert, and the AI autofix job parses the FLAG lines).

Checks:
  1. wg-easy container running + healthy
  2. wg0 interface up, UDP <WG_PORT> listening
  3. nft rules present: MASQUERADE, 2x FORWARD accept, UI-port public block
  4. AdGuard Home unit active + answering on the tunnel IP
  5. Ad blocking still effective (test domain -> 0.0.0.0)
  6. wg-nft-rules unit enabled (survives reboot)

Env overrides (defaults match the self-hosted-vpn-playbook):
  CONTAINER=wg-easy  WG_IF=wg0  WG_PORT=51820  UI_PORT=51821
  WG_SUBNET=10.66.66.0/24  DNS_IP=10.66.66.1  ADGUARD_UNIT=adguardhome
  RULES_UNIT=wg-nft-rules  BLOCK_TEST_DOMAIN=doubleclick.net
"""
import os
import subprocess
import sys

CONTAINER = os.environ.get("CONTAINER", "wg-easy")
WG_IF = os.environ.get("WG_IF", "wg0")
WG_PORT = os.environ.get("WG_PORT", "51820")
UI_PORT = os.environ.get("UI_PORT", "51821")
WG_SUBNET = os.environ.get("WG_SUBNET", "10.66.66.0/24")
DNS_IP = os.environ.get("DNS_IP", "10.66.66.1")
ADGUARD_UNIT = os.environ.get("ADGUARD_UNIT", "adguardhome")
RULES_UNIT = os.environ.get("RULES_UNIT", "wg-nft-rules")
BLOCK_TEST = os.environ.get("BLOCK_TEST_DOMAIN", "doubleclick.net")

flags = []


def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)


def flag(msg):
    flags.append(msg)


# 1. container
r = sh(f"docker inspect -f '{{{{.State.Status}}}} {{{{if .State.Health}}}}{{{{.State.Health.Status}}}}{{{{end}}}}' {CONTAINER} 2>/dev/null")
if r.returncode != 0 or not r.stdout.strip():
    flag(f"wg-easy container '{CONTAINER}' not present or inspect failed")
else:
    parts = r.stdout.strip().split()
    if parts[0] != "running":
        flag(f"wg-easy container not running (state: {r.stdout.strip() or '?'})")
    elif len(parts) > 1 and parts[1] not in ("healthy", ""):
        flag(f"wg-easy container unhealthy ({parts[1]})")

# 2. interface + listener
r = sh(f"wg show {WG_IF}")
if r.returncode != 0 or "interface:" not in r.stdout:
    flag(f"WireGuard interface {WG_IF} is down")
else:
    if f"listening port: {WG_PORT}" not in r.stdout:
        flag(f"WireGuard not listening on UDP {WG_PORT}")

# 3. nft rules
rules = [
    (f"iptables -t nat -C POSTROUTING -s {WG_SUBNET} -o eth0 -j MASQUERADE",
     "NAT MASQUERADE rule missing"),
    (f"iptables -C FORWARD -i {WG_IF} -o eth0 -j ACCEPT",
     "FORWARD wg0->eth0 ACCEPT rule missing"),
    (f"iptables -C FORWARD -i eth0 -o {WG_IF} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
     "FORWARD eth0->wg0 ESTABLISHED rule missing"),
    (f"iptables -C INPUT -i eth0 -p tcp --dport {UI_PORT} -j DROP",
     f"UI port {UI_PORT} public-block rule missing (dashboard exposed!)"),
]
for cmd, desc in rules:
    if sh(cmd).returncode != 0:
        flag(desc)

# 4. AdGuard unit + DNS answering
r = sh(f"systemctl is-active {ADGUARD_UNIT}")
if r.stdout.strip() != "active":
    flag(f"AdGuard unit '{ADGUARD_UNIT}' not active ({r.stdout.strip() or 'unknown'})")
else:
    r = sh(f"dig +short +time=3 @{DNS_IP} example.com")
    if r.returncode != 0 or not any(part.replace(".", "").isdigit() for part in r.stdout.split()):
        flag(f"AdGuard not answering DNS on {DNS_IP}:53")

# 5. ad blocking effective
r = sh(f"dig +short +time=3 @{DNS_IP} {BLOCK_TEST}")
if r.returncode != 0 or "0.0.0.0" not in r.stdout:
    flag(f"ad blocking degraded: {BLOCK_TEST} is not blocked (got: {r.stdout.strip() or 'no answer'})")

# 6. rules unit enabled
r = sh(f"systemctl is-enabled {RULES_UNIT}")
if r.stdout.strip() != "enabled":
    flag(f"unit '{RULES_UNIT}' not enabled (firewall rules would vanish on reboot)")

if flags:
    print(f"VPN HEALTH CHECK FAILED — {len(flags)} issue(s)")
    for f in flags:
        print(f"FLAG: {f}")
    sys.exit(1)
# healthy: print nothing
sys.exit(0)
