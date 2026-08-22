#!/usr/bin/env python3
"""Advanced VPN stack health watchdog (wg-easy + AdGuard Home + dashboard).

Prints NOTHING and exits 0 when healthy (no_agent cron => silent tick).
Prints "FLAG:" lines and exits non-zero when broken.

Checks:
  1. wg-easy container running + healthy
  2. wg0 interface up, UDP <WG_PORT> listening
  3. nft rules present: MASQUERADE, 2x FORWARD accept, UI-port public block
  4. AdGuard unit active + answering on the tunnel IP
  5. Ad blocking still effective (test domain -> 0.0.0.0)
  6. wg-nft-rules unit enabled (survives reboot)
  7. Dashboard unit active + HTTP 200
  8. Peer endpoint sanity — a real device must never show a private/test
     endpoint (catches stale test rigs stealing a device's tunnel slot)
  9. ACTIVE EGRESS TEST — spins a throwaway WireGuard client (dedicated
     "healthcheck" peer, its own key) in a netns and proves real traffic:
     handshake -> ICMP to 1.1.1.1 -> HTTPS egress with the server's public
     IP. Catches forwarding/NAT/routing failures that presence checks miss.

Env overrides (defaults match the self-hosted-vpn-playbook):
  CONTAINER=wg-easy  WG_IF=wg0  WG_PORT=51820  UI_PORT=51821
  WG_SUBNET=10.66.66.0/24  DNS_IP=10.66.66.1  ADGUARD_UNIT=adguardhome
  RULES_UNIT=wg-nft-rules  DASH_UNIT=vps-dashboard  DASH_URL=http://<DNS_IP>:8088/
  BLOCK_TEST_DOMAIN=doubleclick.net  WG_EASY_CONFIG=/root/wg-easy/config/wg0.json
  HEALTHCHECK_CLIENT=healthcheck  EXPECTED_EGRESS_IP=<server public IP>
"""
import ipaddress
import json
import os
import subprocess
import sys
import time

CONTAINER = os.environ.get("CONTAINER", "wg-easy")
WG_IF = os.environ.get("WG_IF", "wg0")
WG_PORT = os.environ.get("WG_PORT", "51820")
UI_PORT = os.environ.get("UI_PORT", "51821")
WG_SUBNET = os.environ.get("WG_SUBNET", "10.66.66.0/24")
DNS_IP = os.environ.get("DNS_IP", "10.66.66.1")
ADGUARD_UNIT = os.environ.get("ADGUARD_UNIT", "adguardhome")
RULES_UNIT = os.environ.get("RULES_UNIT", "wg-nft-rules")
DASH_UNIT = os.environ.get("DASH_UNIT", "vps-dashboard")
DASH_URL = os.environ.get("DASH_URL", f"http://{DNS_IP}:8088/")
BLOCK_TEST = os.environ.get("BLOCK_TEST_DOMAIN", "doubleclick.net")
WG_EASY_CONFIG = os.environ.get("WG_EASY_CONFIG", "/root/wg-easy/config/wg0.json")
HEALTHCHECK_CLIENT = os.environ.get("HEALTHCHECK_CLIENT", "healthcheck")
TEST_NS = "vpn-health-ns"
TEST_HOST_IP = "10.88.88.1"
TEST_CLIENT_IP = "10.88.88.2"
LOCK = "/tmp/vpn-health-check.lock"
EXCLUDE_NETS = os.environ.get("EXCLUDE_NETS", "10.88.88.0/24").split(",")
AUTOFIX_JOB = os.environ.get("AUTOFIX_JOB", "vpn-autofix")
AUTOFIX_COOLDOWN_S = int(os.environ.get("AUTOFIX_COOLDOWN_S", "1800"))
AUTOFIX_TRIGGER_TS = "/tmp/vpn-autofix-trigger.ts"

flags = []


def sh(cmd, timeout=30):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)


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
    elif len(parts) > 1 and parts[1] == "unhealthy":
        flag(f"wg-easy container unhealthy ({parts[1]})")
    # "starting" is the normal post-restart warmup — not a flag

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
    (f"iptables -t mangle -C FORWARD -i {WG_IF} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240",
     "MSS clamp wg0->eth0 missing (big sites will stall: MTU black hole)"),
    (f"iptables -t mangle -C FORWARD -o {WG_IF} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1240",
     "MSS clamp eth0->wg0 missing (big sites will stall: MTU black hole)"),
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
    if r.returncode != 0 or not any(p.replace(".", "").isdigit() for p in r.stdout.split()):
        flag(f"AdGuard not answering DNS on {DNS_IP}:53")

# 5. ad blocking effective
r = sh(f"dig +short +time=3 @{DNS_IP} {BLOCK_TEST}")
if r.returncode != 0 or "0.0.0.0" not in r.stdout:
    flag(f"ad blocking degraded: {BLOCK_TEST} is not blocked (got: {r.stdout.strip() or 'no answer'})")

# 6. rules unit enabled
r = sh(f"systemctl is-enabled {RULES_UNIT}")
if r.stdout.strip() != "enabled":
    flag(f"unit '{RULES_UNIT}' not enabled (firewall rules would vanish on reboot)")

# 7. dashboard unit active + responding
r = sh(f"systemctl is-active {DASH_UNIT}")
if r.stdout.strip() != "active":
    flag(f"dashboard unit '{DASH_UNIT}' not active ({r.stdout.strip() or 'unknown'})")
else:
    r = sh(f"curl -s -o /dev/null -w '%{{http_code}}' -m 5 {DASH_URL}")
    if r.stdout.strip() != "200":
        flag(f"dashboard not responding at {DASH_URL} (HTTP {r.stdout.strip() or 'timeout'})")

# 8. peer endpoint sanity (RFC1918/link-local/loopback endpoints = impostor)
#    The healthcheck peer legitimately uses the test veth IP — exempt it.
hc_pubkey = None
try:
    cfg8 = json.load(open(WG_EASY_CONFIG))
    hc8 = next((c for c in cfg8.get("clients", {}).values()
                if c.get("name") == HEALTHCHECK_CLIENT), None)
    hc_pubkey = hc8["publicKey"] if hc8 else None
except Exception:
    pass
r = sh(f"wg show {WG_IF} dump")
for line in r.stdout.strip().splitlines()[1:]:
    parts = line.split("\t")
    if len(parts) < 8 or not parts[2]:
        continue
    if parts[0] == hc_pubkey:
        continue
    ep = parts[2]
    ip = ep.split(":")[0]
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        continue
    if a.is_private or a.is_loopback or a.is_link_local:
        flag(f"peer {parts[0][:10]}… has private/test endpoint {ep} — "
             "a test rig or stale client is holding the tunnel slot")

# 10. rejected-handshake detector: a device knocking with keys the server
#     doesn't recognize (outdated/foreign profile) gets silently ignored by
#     WireGuard — the "connected but no internet" failure. Capture inbound
#     handshake-init packets (UDP length 148) and flag sources that are not
#     the endpoint of any recently-handshaken peer.
def rejected_handshake_probe():
    if os.environ.get("SKIP_HANDSHAKE_PROBE"):
        return
    if sh("which tcpdump").returncode != 0:
        flag("tcpdump missing — rejected-handshake detection unavailable")
        return
    # public clients arrive via eth0 (veth/test traffic is excluded anyway);
    # note: -i any does NOT see veth traffic on some kernels
    capture_file = os.environ.get("CAPTURE_FILE")  # test hook: feed saved output
    if capture_file:
        r = subprocess.run(["cat", capture_file], capture_output=True, text=True)
    else:
        r = sh(f"timeout 15 tcpdump -i eth0 -nn -l udp port {WG_PORT} -c 40 2>/dev/null",
               timeout=20)
    sources = {}
    for line in r.stdout.splitlines():
        # "HH:MM:SS.mmm IP 1.2.3.4.1234 > 5.6.7.8.51820: UDP, length 148"
        if "> " not in line or "length 148" not in line:
            continue
        try:
            src = line.split(" IP ", 1)[1].split(" > ", 1)[0]
            ip = src.rsplit(".", 1)[0]
            a = ipaddress.ip_address(ip)
        except (IndexError, ValueError):
            continue
        if a.is_loopback or a.is_link_local:
            continue
        if any(a in ipaddress.ip_network(n) for n in EXCLUDE_NETS):
            continue
        if a.is_private and not os.environ.get("ALLOW_PRIVATE_PROBE"):
            continue  # local test rigs; public-internet devices only
        sources[ip] = sources.get(ip, 0) + 1
    # which peers handshook recently, from where
    live_endpoints = set()
    try:
        r2 = sh(f"wg show {WG_IF} dump", timeout=10)
        now = time.time()
        for line in r2.stdout.strip().splitlines()[1:]:
            p = line.split("\t")
            if len(p) >= 8 and p[2] and p[4] and int(p[4]) > now - 120:
                live_endpoints.add(p[2].rsplit(":", 1)[0])
    except Exception:
        pass
    for ip, count in sources.items():
        if count >= 3 and ip not in live_endpoints:
            flag(f"rejected handshakes from {ip} ({count} attempts in 15s) — "
                 "that device has an outdated/foreign profile; the server "
                 "ignores it. Fix: delete and re-import the profile on the device.")


# 9. active egress test (dedicated healthcheck peer, real traffic)
def egress_test():
    try:
        cfg = json.load(open(WG_EASY_CONFIG))
        cl = next((c for c in cfg.get("clients", {}).values()
                   if c.get("name") == HEALTHCHECK_CLIENT), None)
        srv_pub = cfg.get("server", {}).get("publicKey")
        if not cl or not srv_pub:
            flag(f"healthcheck client '{HEALTHCHECK_CLIENT}' missing from wg-easy "
                 "(create one so the egress test can run)")
            return
        cl_key, cl_addr = cl["privateKey"], cl["address"]
    except Exception as e:
        flag(f"cannot read wg-easy config for egress test: {str(e)[:80]}")
        return

    # expected egress IP: container WG_HOST env, else explicit env override
    expected = os.environ.get("EXPECTED_EGRESS_IP")
    if not expected:
        r = sh(f"docker inspect {CONTAINER} --format "
               "'{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null")
        for line in r.stdout.splitlines():
            if line.startswith("WG_HOST="):
                expected = line.split("=", 1)[1].strip()
                break

    sh(f"ip netns del {TEST_NS} 2>/dev/null; ip link del vh0 2>/dev/null; "
       f"ip netns add {TEST_NS}; ip link add vh0 type veth peer name vh1; "
       f"ip link set vh1 netns {TEST_NS}; ip addr add {TEST_HOST_IP}/24 dev vh0; "
       f"ip link set vh0 up")
    r = sh(f"""ip netns exec {TEST_NS} bash -c '
ip link set lo up
ip addr add {TEST_CLIENT_IP}/24 dev vh1
ip link set vh1 up
ip link add wg0 type wireguard
wg set wg0 private-key /dev/stdin <<< "{cl_key}"
wg set wg0 peer {srv_pub} preshared-key /dev/stdin <<< "{cl['preSharedKey']}"
wg set wg0 peer {srv_pub} endpoint {TEST_HOST_IP}:{WG_PORT} allowed-ips 0.0.0.0/0 persistent-keepalive 25
ip addr add {cl_addr}/24 dev wg0
ip link set wg0 up
ip route add default dev wg0'""", timeout=20)
    if r.returncode != 0:
        flag(f"egress test: netns client setup failed: {r.stderr.strip()[:100]}")
        return
    time.sleep(1.5)
    try:
        r = sh(f"ip netns exec {TEST_NS} ping -c 2 -W 3 1.1.1.1", timeout=15)
        if r.returncode != 0 or "0% packet loss" not in r.stdout:
            flag("egress test: ICMP through tunnel FAILED — forwarding/NAT broken")
        if expected:
            r = sh(f"ip netns exec {TEST_NS} curl -s -m 10 "
                   "https://1.1.1.1/cdn-cgi/trace", timeout=15)
            if f"ip={expected}" not in r.stdout:
                flag(f"egress test: wrong egress IP (expected {expected}, "
                     f"got {r.stdout.strip()[:60] or 'no answer'})")
    finally:
        sh(f"ip netns del {TEST_NS} 2>/dev/null; ip link del vh0 2>/dev/null")


if os.path.exists(LOCK) and time.time() - os.path.getmtime(LOCK) < 90:
    pass  # another instance mid-run; skip the egress test this tick
else:
    try:
        open(LOCK, "w").close()
        egress_test()
    finally:
        try:
            os.remove(LOCK)
        except OSError:
            pass

rejected_handshake_probe()


def wake_autofix():
    """Event-driven AI wake: only pays tokens when something is broken."""
    try:
        last = 0.0
        if os.path.exists(AUTOFIX_TRIGGER_TS):
            try:
                last = float(open(AUTOFIX_TRIGGER_TS).read().strip() or 0)
            except ValueError:
                last = 0.0
        if time.time() - last < AUTOFIX_COOLDOWN_S:
            return False
        with open(AUTOFIX_TRIGGER_TS, "w") as f:
            f.write(str(time.time()))
        r = sh(f"hermes cron run {AUTOFIX_JOB}", timeout=30)
        return r.returncode == 0
    except Exception:
        return False


if flags:
    print(f"VPN HEALTH CHECK FAILED — {len(flags)} issue(s)")
    for f in flags:
        print(f"FLAG: {f}")
    if wake_autofix():
        print("(autofix agent woken)")
    sys.exit(1)
sys.exit(0)
