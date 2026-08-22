#!/usr/bin/env python3
"""Advanced VPN stack health watchdog v2 (wg-easy + AdGuard Home + dashboard).

Tiered self-healing design:
  Tier 0 (every tick, token-free): 11 health checks. Healthy => silent, exit 0.
  Tier 1 (on flags, token-free): scripted fixes — restart units, re-add nft
        rules, restart wg-easy for stale endpoints. Re-check; if clean,
        deliver a one-line "auto-fixed" notice. No LLM tokens spent.
  Tier 2 (on flags surviving Tier 1): write /tmp/vpn-last-flags.txt and wake
        the AI autofix agent (hermes cron run vpn-autofix, 30m cooldown).
        The flags file fixes the context race: the AI previously woke with
        the PREVIOUS (silent) tick as context and did nothing.

Checks:
  1. wg-easy container running + healthy
  2. wg0 interface up, UDP <WG_PORT> listening
  3. nft rules present: MASQUERADE, 2x FORWARD accept, UI-port public block,
     2x MSS clamp
  4. AdGuard unit active + answering on the tunnel IP
  5. Ad blocking still effective (test domain -> 0.0.0.0)
  6. wg-nft-rules unit enabled (survives reboot)
  7. Dashboard unit active + HTTP 200
  8. Peer endpoint sanity — a real device must never show a private/test
     endpoint (catches stale test rigs stealing a device's tunnel slot)
  9. ACTIVE EGRESS TEST — throwaway WireGuard client (dedicated "healthcheck"
     peer, its own key) in a netns: handshake -> ICMP -> HTTPS egress IP
 10. Rejected-handshake detector — inbound length-148 inits from public IPs
     that don't match any live peer = device with an outdated profile.
     The SERVER'S OWN public IP and flows to private destinations are
     skipped (wg-easy rekeying against the stale netns endpoint of the
     healthcheck peer is self-inflicted, not a broken device).

Env overrides (defaults match the self-hosted-vpn-playbook):
  CONTAINER=wg-easy  WG_IF=wg0  WG_PORT=51820  UI_PORT=51821
  WG_SUBNET=10.66.66.0/24  DNS_IP=10.66.66.1  ADGUARD_UNIT=adguardhome
  RULES_UNIT=wg-nft-rules  DASH_UNIT=vps-dashboard  DASH_URL=http://<DNS_IP>:8088/
  BLOCK_TEST_DOMAIN=doubleclick.net  WG_EASY_CONFIG=/root/wg-easy/config/wg0.json
  HEALTHCHECK_CLIENT=healthcheck  EXPECTED_EGRESS_IP=<server public IP>
  FLAGS_FILE=/tmp/vpn-last-flags.txt  SCRIPTED_FIX=0 (disable Tier 1)
  SKIP_HANDSHAKE_PROBE=1  ALLOW_PRIVATE_PROBE=1  CAPTURE_FILE=<saved tcpdump>
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
AUTOFIX_TRIGGER_TS = os.environ.get("AUTOFIX_TRIGGER_TS", "/tmp/vpn-autofix-trigger.ts")
FLAGS_FILE = os.environ.get("FLAGS_FILE", "/tmp/vpn-last-flags.txt")
SCRIPTED_FIX = os.environ.get("SCRIPTED_FIX", "1") == "1"

_server_public_ip = None


def sh(cmd, timeout=30):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True,
                          timeout=timeout)


def server_public_ip():
    """Server's own public IP, from EXPECTED_EGRESS_IP or the container's
    WG_HOST env. Used by the egress test (expected egress) and the
    rejected-handshake probe (skip self-inflicted inits)."""
    global _server_public_ip
    if _server_public_ip is not None:
        return _server_public_ip
    ip = (os.environ.get("EXPECTED_EGRESS_IP") or "").strip()
    if not ip:
        try:
            r = sh(f"docker inspect {CONTAINER} --format "
                   "'{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null")
            for line in r.stdout.splitlines():
                if line.startswith("WG_HOST="):
                    ip = line.split("=", 1)[1].strip()
                    break
        except Exception:
            pass
    _server_public_ip = ip or None
    return _server_public_ip


def check_container(flags):
    r = sh(f"docker inspect -f '{{{{.State.Status}}}} {{{{if .State.Health}}}}{{{{.State.Health.Status}}}}{{{{end}}}}' {CONTAINER} 2>/dev/null")
    if r.returncode != 0 or not r.stdout.strip():
        flags.append(f"wg-easy container '{CONTAINER}' not present or inspect failed")
        return
    parts = r.stdout.strip().split()
    if parts[0] != "running":
        flags.append(f"wg-easy container not running (state: {r.stdout.strip() or '?'})")
    elif len(parts) > 1 and parts[1] == "unhealthy":
        flags.append(f"wg-easy container unhealthy ({parts[1]})")


def check_interface(flags):
    r = sh(f"wg show {WG_IF}")
    if r.returncode != 0 or "interface:" not in r.stdout:
        flags.append(f"WireGuard interface {WG_IF} is down")
    elif f"listening port: {WG_PORT}" not in r.stdout:
        flags.append(f"WireGuard not listening on UDP {WG_PORT}")


def check_nft_rules(flags):
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
            flags.append(desc)


def check_adguard(flags):
    r = sh(f"systemctl is-active {ADGUARD_UNIT}")
    if r.stdout.strip() != "active":
        flags.append(f"AdGuard unit '{ADGUARD_UNIT}' not active ({r.stdout.strip() or 'unknown'})")
        return
    r = sh(f"dig +short +time=3 @{DNS_IP} example.com")
    if r.returncode != 0 or not any(p.replace(".", "").isdigit() for p in r.stdout.split()):
        flags.append(f"AdGuard not answering DNS on {DNS_IP}:53")


def check_adblock(flags):
    r = sh(f"dig +short +time=3 @{DNS_IP} {BLOCK_TEST}")
    if r.returncode != 0 or "0.0.0.0" not in r.stdout:
        flags.append(f"ad blocking degraded: {BLOCK_TEST} is not blocked (got: {r.stdout.strip() or 'no answer'})")


def check_rules_unit(flags):
    r = sh(f"systemctl is-enabled {RULES_UNIT}")
    if r.stdout.strip() != "enabled":
        flags.append(f"unit '{RULES_UNIT}' not enabled (firewall rules would vanish on reboot)")


def check_dashboard(flags):
    r = sh(f"systemctl is-active {DASH_UNIT}")
    if r.stdout.strip() != "active":
        flags.append(f"dashboard unit '{DASH_UNIT}' not active ({r.stdout.strip() or 'unknown'})")
        return
    r = sh(f"curl -s -o /dev/null -w '%{{http_code}}' -m 5 {DASH_URL}")
    if r.stdout.strip() != "200":
        flags.append(f"dashboard not responding at {DASH_URL} (HTTP {r.stdout.strip() or 'timeout'})")


def check_peer_endpoints(flags):
    ep_exclude = os.environ.get("EP_EXCLUDE_NETS", "10.88.88.0/24,10.99.99.0/24").split(",")
    hc_pubkey = None
    try:
        cfg = json.load(open(WG_EASY_CONFIG))
        hc = next((c for c in cfg.get("clients", {}).values()
                   if c.get("name") == HEALTHCHECK_CLIENT), None)
        hc_pubkey = hc["publicKey"] if hc else None
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
        if any(a in ipaddress.ip_network(n) for n in ep_exclude):
            continue
        if a.is_private or a.is_loopback or a.is_link_local:
            flags.append(f"peer {parts[0][:10]}… has private/test endpoint {ep} — "
                         "a test rig or stale client is holding the tunnel slot")


def egress_test(flags):
    try:
        cfg = json.load(open(WG_EASY_CONFIG))
        cl = next((c for c in cfg.get("clients", {}).values()
                   if c.get("name") == HEALTHCHECK_CLIENT), None)
        srv_pub = cfg.get("server", {}).get("publicKey")
        if not cl or not srv_pub:
            flags.append(f"healthcheck client '{HEALTHCHECK_CLIENT}' missing from wg-easy "
                         "(create one so the egress test can run)")
            return
        cl_key, cl_addr = cl["privateKey"], cl["address"]
    except Exception as e:
        flags.append(f"cannot read wg-easy config for egress test: {str(e)[:80]}")
        return

    expected = server_public_ip()

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
        flags.append(f"egress test: netns client setup failed: {r.stderr.strip()[:100]}")
        return
    time.sleep(1.5)
    try:
        r = sh(f"ip netns exec {TEST_NS} ping -c 2 -W 3 1.1.1.1", timeout=15)
        if r.returncode != 0 or "0% packet loss" not in r.stdout:
            flags.append("egress test: ICMP through tunnel FAILED — forwarding/NAT broken")
        if expected:
            r = sh(f"ip netns exec {TEST_NS} curl -s -m 10 "
                   "https://1.1.1.1/cdn-cgi/trace", timeout=15)
            if f"ip={expected}" not in r.stdout:
                flags.append(f"egress test: wrong egress IP (expected {expected}, "
                             f"got {r.stdout.strip()[:60] or 'no answer'})")
    finally:
        sh(f"ip netns del {TEST_NS} 2>/dev/null; ip link del vh0 2>/dev/null")


def rejected_handshake_probe(flags):
    """Inbound length-148 inits from public IPs that don't match any recently
    handshaken peer = device with an outdated/foreign profile. Skip the
    server's OWN public IP (wg-easy rekeying against stale netns endpoints is
    self-inflicted) and flows whose destination is private (server chatting
    with a dead test rig)."""
    if os.environ.get("SKIP_HANDSHAKE_PROBE"):
        return
    if sh("which tcpdump").returncode != 0:
        flags.append("tcpdump missing — rejected-handshake detection unavailable")
        return
    capture_file = os.environ.get("CAPTURE_FILE")
    if capture_file:
        r = subprocess.run(["cat", capture_file], capture_output=True, text=True)
    else:
        r = sh(f"timeout 15 tcpdump -i eth0 -nn -l udp port {WG_PORT} -c 40 2>/dev/null",
               timeout=20)
    self_ip = server_public_ip()
    sources = {}
    for line in r.stdout.splitlines():
        if "> " not in line or "length 148" not in line:
            continue
        try:
            src = line.split(" IP ", 1)[1].split(" > ", 1)[0]
            dst = line.split(" > ", 1)[1].split(":", 1)[0]
            src_ip = src.rsplit(".", 1)[0]
            dst_ip = dst.rsplit(".", 1)[0]
            sa = ipaddress.ip_address(src_ip)
            da = ipaddress.ip_address(dst_ip)
        except (IndexError, ValueError):
            continue
        if self_ip and sa == ipaddress.ip_address(self_ip):
            continue  # self-inflicted: server's own inits (rekey to stale peer)
        if da.is_private or da.is_loopback or da.is_link_local:
            continue  # server talking to a dead test rig — not a foreign device
        if sa.is_loopback or sa.is_link_local:
            continue
        if any(sa in ipaddress.ip_network(n) for n in EXCLUDE_NETS):
            continue
        if sa.is_private and not os.environ.get("ALLOW_PRIVATE_PROBE"):
            continue
        sources[src_ip] = sources.get(src_ip, 0) + 1
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
            flags.append(f"rejected handshakes from {ip} ({count} attempts in 15s) — "
                         "that device has an outdated/foreign profile; the server "
                         "ignores it. Fix: delete and re-import the profile on the device.")


def run_checks():
    flags = []
    check_container(flags)
    check_interface(flags)
    check_nft_rules(flags)
    check_adguard(flags)
    check_adblock(flags)
    check_rules_unit(flags)
    check_dashboard(flags)
    check_peer_endpoints(flags)
    if os.path.exists(LOCK) and time.time() - os.path.getmtime(LOCK) < 90:
        pass  # another instance mid-run; skip the egress test this tick
    else:
        try:
            open(LOCK, "w").close()
            egress_test(flags)
        finally:
            try:
                os.remove(LOCK)
            except OSError:
                pass
    rejected_handshake_probe(flags)
    return flags


# ---- Tier 1: scripted fixes (token-free) ---------------------------------
# flag-substring -> (action, cooldown_sleep, description)
SCRIPTED_ACTIONS = [
    ("container not running", "docker restart wg-easy", 10, "restarted wg-easy container"),
    ("container unhealthy", "docker restart wg-easy", 10, "restarted wg-easy container"),
    ("NAT MASQUERADE rule missing", "systemctl restart wg-nft-rules", 2, "restarted wg-nft-rules"),
    ("FORWARD wg0->eth0 ACCEPT rule missing", "systemctl restart wg-nft-rules", 2, "restarted wg-nft-rules"),
    ("FORWARD eth0->wg0 ESTABLISHED rule missing", "systemctl restart wg-nft-rules", 2, "restarted wg-nft-rules"),
    ("UI port", "systemctl restart wg-nft-rules", 2, "restarted wg-nft-rules"),
    ("MSS clamp", "systemctl restart wg-nft-rules", 2, "restarted wg-nft-rules"),
    ("AdGuard unit", "systemctl restart adguardhome", 5, "restarted adguardhome"),
    ("not answering DNS", "systemctl restart adguardhome", 5, "restarted adguardhome"),
    ("ad blocking degraded", "systemctl restart adguardhome", 5, "restarted adguardhome"),
    ("not enabled (firewall rules would vanish", "systemctl enable wg-nft-rules", 1, "enabled wg-nft-rules"),
    ("dashboard", "systemctl restart vps-dashboard", 3, "restarted vps-dashboard"),
    ("private/test endpoint", "docker restart wg-easy", 10, "restarted wg-easy (clear stale peer endpoint)"),
    ("egress test", "systemctl restart wg-nft-rules", 2, "restarted wg-nft-rules (forwarding/NAT)"),
    ("healthcheck client", "bash /root/wg-easy/add-wg-profile.sh healthcheck", 5, "recreated healthcheck client"),
]
# NOT script-fixed (no action): rejected handshakes (device-side), tcpdump
# missing, unknown flags.


def apply_scripted_fixes(flags):
    """Returns list of human-readable action descriptions actually executed.
    Dedupes identical commands."""
    done = {}
    descriptions = []
    for f in flags:
        for sub, cmd, sleep_s, desc in SCRIPTED_ACTIONS:
            if sub in f:
                if cmd not in done:
                    done[cmd] = True
                    r = sh(cmd, timeout=60)
                    if r.returncode == 0:
                        descriptions.append(desc)
                    else:
                        descriptions.append(f"{desc} FAILED ({r.stderr.strip()[:80]})")
                    time.sleep(sleep_s)
                break
    return descriptions


def write_flags_file(status, flags):
    try:
        with open(FLAGS_FILE, "w") as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {status}\n")
            for x in flags:
                f.write(f"FLAG: {x}\n")
    except Exception:
        pass


def wake_autofix():
    """Event-driven AI wake: only pays tokens when flags survive Tier 1."""
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


def main():
    flags = run_checks()
    if not flags:
        if os.path.exists(FLAGS_FILE):
            try:
                os.remove(FLAGS_FILE)
            except OSError:
                pass
        sys.exit(0)

    # Tier 1: scripted fixes, then re-verify
    write_flags_file("UNFIXED", flags)
    if SCRIPTED_FIX:
        fixed = apply_scripted_fixes(flags)
        flags2 = run_checks()
        if not flags2:
            write_flags_file("FIXED-BY-SCRIPTED-TIER", flags)
            print(f"VPN AUTO-FIXED (scripted): {'; '.join(fixed) or 'checks self-healed'} "
                  f"— all {len(flags)} issue(s) cleared. No AI needed.")
            sys.exit(0)
        flags = flags2
    write_flags_file("UNFIXED", flags)

    # Tier 2: wake the AI
    print(f"VPN HEALTH CHECK FAILED — {len(flags)} issue(s)")
    for f in flags:
        print(f"FLAG: {f}")
    if wake_autofix():
        print("(autofix agent woken)")
    sys.exit(1)


if __name__ == "__main__":
    main()
