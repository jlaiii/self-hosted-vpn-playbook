#!/usr/bin/env python3
"""Advanced VPN + SYSTEM health watchdog v3 (wg-easy + AdGuard + dashboard +
host health: RAM/CPU load/disk/failed units).

Tiered self-healing design:
  Tier 0 (every tick, token-free): 16 health checks. Healthy => silent, exit 0.
  Tier 1 (on flags, token-free): scripted fixes — restart units, re-add nft
        rules, restart wg-easy for stale endpoints, vacuum journal + clean
        apt cache on disk pressure, restart failed systemd units. Re-check;
        if clean, deliver a detailed "auto-fixed" notice. No LLM tokens spent.
  Tier 2 (on flags surviving Tier 1): write /tmp/vpn-last-flags.txt and wake
        the AI autofix agent (hermes cron run vpn-autofix, 30m cooldown).
        The flags file fixes the context race: the AI previously woke with
        the PREVIOUS (silent) tick as context and did nothing.
        SYSTEM flags with NO safe scripted fix (memory pressure, sustained
        CPU load) go straight to Tier 2 so the AI investigates and reports.

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
 11. SPEED TEST — Ookla CLI on a cadence (SPEEDTEST_EVERY_S, default 1800s =
     30 min: a full test saturates the uplink ~20 s, so it does NOT run every
     tick). Flags only when down/up/ping breach thresholds (DOWN_MIN_MBPS,
     UP_MIN_MBPS, PING_MAX_MS) or the test fails. Slow flags have NO scripted
     fix (Tier 1) — they go straight to Tier 2 so the AI investigates the
     uplink and reports.
 12. SYSTEM: memory pressure — RAM% >= RAM_PCT_MAX (90) and/or swap pressure.
     No scripted fix — Tier 2 AI investigates top consumers.
 13. SYSTEM: sustained CPU load — loadavg 5m >= cores * LOAD_FACTOR (2.0).
     No scripted fix — Tier 2 AI investigates top processes.
 14. SYSTEM: root disk — % >= DISK_PCT_MAX (85, warn) / DISK_CRIT_PCT (95,
     critical). Tier 1: vacuum journal + apt-get clean (safe, no-op when
     already small); still over -> Tier 2.
 15. SYSTEM: failed systemd units — Tier 1 restarts them; still failed -> AI
     reads their logs and reports the cause.

NOTE: system checks (12-15) run FIRST each tick so the egress/speed tests
don't skew the load reading.

Env overrides (defaults match the self-hosted-vpn-playbook):
  CONTAINER=wg-easy  WG_IF=wg0  WG_PORT=51820  UI_PORT=51821
  WG_SUBNET=10.66.66.0/24  DNS_IP=10.66.66.1  ADGUARD_UNIT=adguardhome
  RULES_UNIT=wg-nft-rules  DASH_UNIT=vps-dashboard  DASH_URL=http://<DNS_IP>:8088/
  BLOCK_TEST_DOMAIN=doubleclick.net  WG_EASY_CONFIG=/root/wg-easy/config/wg0.json
  HEALTHCHECK_CLIENT=healthcheck  EXPECTED_EGRESS_IP=<server public IP>
  FLAGS_FILE=/tmp/vpn-last-flags.txt  SCRIPTED_FIX=0 (disable Tier 1)
  INCIDENTS_LOG=/root/vps-dash/data/vpn-incidents.jsonl (detailed flag history)
  ADD_WG_PROFILE_CMD=<cmd> (tier-1 healthcheck-client recreate; portable
  installs set this to 'bash /usr/local/bin/add-wg-profile.py healthcheck')
  SKIP_HANDSHAKE_PROBE=1  ALLOW_PRIVATE_PROBE=1  CAPTURE_FILE=<saved tcpdump>
  SPEEDTEST_BIN=/usr/local/bin/speedtest  SPEEDTEST_EVERY_S=1800
  SPEEDTEST_LAST_TS=/tmp/vpn-speedtest-last.ts  DOWN_MIN_MBPS=50
  UP_MIN_MBPS=30  PING_MAX_MS=100
  SYSTEM_CHECKS=0 (disable host-health checks)  RAM_PCT_MAX=90
  SWAP_PCT_MAX=50  LOAD_FACTOR=2.0  DISK_PCT_MAX=85  DISK_CRIT_PCT=95
"""
import ipaddress
import json
import os
import re
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
EXIT_STATE = os.environ.get("EXIT_STATE", "/root/vps-dash/data/exit-state.json")
EXIT_MANAGER = os.environ.get("EXIT_MANAGER",
                              "/root/vps-dash/exit_manager.py")
AUTOFIX_COOLDOWN_S = int(os.environ.get("AUTOFIX_COOLDOWN_S", "1800"))
AUTOFIX_TRIGGER_TS = os.environ.get("AUTOFIX_TRIGGER_TS", "/tmp/vpn-autofix-trigger.ts")
FLAGS_FILE = os.environ.get("FLAGS_FILE", "/tmp/vpn-last-flags.txt")
INCIDENTS_LOG = os.environ.get("INCIDENTS_LOG",
                               "/root/vps-dash/data/vpn-incidents.jsonl")
SCRIPTED_FIX = os.environ.get("SCRIPTED_FIX", "1") == "1"
SPEEDTEST_BIN = os.environ.get("SPEEDTEST_BIN", "/usr/local/bin/speedtest")
SPEEDTEST_EVERY_S = int(os.environ.get("SPEEDTEST_EVERY_S", "1800"))
SPEEDTEST_LAST_TS = os.environ.get("SPEEDTEST_LAST_TS",
                                   "/tmp/vpn-speedtest-last.ts")
SPEEDTEST_RESULT_FILE = os.environ.get("SPEEDTEST_RESULT_FILE",
                                       "/tmp/vpn-speedtest-last.json")
DOWN_MIN_MBPS = float(os.environ.get("DOWN_MIN_MBPS", "50"))
UP_MIN_MBPS = float(os.environ.get("UP_MIN_MBPS", "30"))
PING_MAX_MS = float(os.environ.get("PING_MAX_MS", "100"))
# ---- system health thresholds (host checks 12-15) ------------------------
# Dashboard-tunable: data/watchdog-config.json (written by the VPS dashboard
# Watchdog tab) overrides env, env overrides the defaults. The dashboard is
# the source of truth when it has saved values.
SYSTEM_CHECKS = os.environ.get("SYSTEM_CHECKS", "1") == "1"
RAM_PCT_MAX = float(os.environ.get("RAM_PCT_MAX", "90"))
SWAP_PCT_MAX = float(os.environ.get("SWAP_PCT_MAX", "50"))
LOAD_FACTOR = float(os.environ.get("LOAD_FACTOR", "2.0"))
DISK_PCT_MAX = float(os.environ.get("DISK_PCT_MAX", "85"))
DISK_CRIT_PCT = float(os.environ.get("DISK_CRIT_PCT", "95"))
try:
    _wd_cfg = json.load(open(
        os.environ.get("WD_CONFIG_FILE", "/root/vps-dash/data/watchdog-config.json")))
    _wd_map = {"ram_pct_max": "RAM_PCT_MAX", "swap_pct_max": "SWAP_PCT_MAX",
               "load_factor": "LOAD_FACTOR", "disk_pct_warn": "DISK_PCT_MAX",
               "disk_pct_crit": "DISK_CRIT_PCT"}
    for _k, _v in _wd_cfg.items():
        if _k in _wd_map and isinstance(_v, (int, float)) and _v > 0:
            globals()[_wd_map[_k]] = float(_v)
except Exception:
    pass

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
        # exit sandbox (xeth) static path rules
        (f"iptables -t nat -C POSTROUTING -s 10.90.0.0/30 -o eth0 -j MASQUERADE",
         "NAT xeth sandbox MASQUERADE rule missing"),
        (f"iptables -C FORWARD -i {WG_IF} -o xeth0 -j ACCEPT",
         "FORWARD wg0->xeth0 ACCEPT rule missing"),
        (f"iptables -C FORWARD -i xeth0 -o {WG_IF} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
         "FORWARD xeth0->wg0 ESTABLISHED rule missing"),
        (f"iptables -C FORWARD -i xeth0 -o eth0 -j ACCEPT",
         "FORWARD xeth0->eth0 ACCEPT rule missing"),
        (f"iptables -C FORWARD -i eth0 -o xeth0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
         "FORWARD eth0->xeth0 ESTABLISHED rule missing"),
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

    vps_ip = server_public_ip()
    expected = vps_ip
    # Exit provider active? Then the healthcheck peer must egress via the
    # sandbox tunnel (its exit IP), not the VPS IP.
    sticky = None
    profile = None
    try:
        st = json.load(open(EXIT_STATE))
        profile = st.get("profile", "direct")
        if profile != "direct" and st.get("exit_ip"):
            expected = st["exit_ip"]
        sticky = st.get("sticky")
    except Exception:
        pass

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
                got_ip = None
                for line in r.stdout.strip().splitlines():
                    if line.startswith("ip="):
                        got_ip = line.split("=", 1)[1]
                        break
                # Protection ON: a live tunnel whose egress IP rotated (provider
                # NAT pool on reconnect) is not a fault — adopt the new IP as
                # the expected one. Real failures = no answer or VPS IP (leak).
                if (sticky and sticky == profile and got_ip
                        and got_ip != vps_ip):
                    try:
                        st = json.load(open(EXIT_STATE))
                        st["exit_ip"] = got_ip
                        tmp = EXIT_STATE + ".tmp"
                        with open(tmp, "w") as f:
                            json.dump(st, f)
                        os.replace(tmp, EXIT_STATE)
                    except Exception:
                        pass
                else:
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


def check_speedtest(flags):
    """Ookla speed test on a cadence; flags only when slow or failing.

    A full test saturates the uplink for ~20 s, so it runs at most every
    SPEEDTEST_EVERY_S (default 30 min) — the timestamp file persists across
    ticks/restarts. Slow/failed results have no scripted fix: they pass
    straight to Tier 2 so the AI investigates the host uplink and reports.
    """
    if os.path.exists(SPEEDTEST_LAST_TS):
        try:
            last = float(open(SPEEDTEST_LAST_TS).read().strip() or 0)
            if time.time() - last < SPEEDTEST_EVERY_S:
                return  # not due yet — keep output stable
        except ValueError:
            pass
    os.environ.setdefault("HOME", "/root")  # Ookla binary crashes without HOME
    rc, err, raw = -1, "", None
    try:
        r = subprocess.run(
            [SPEEDTEST_BIN, "--format=json", "--accept-license",
             "--accept-gdpr"],
            capture_output=True, text=True, timeout=90)
        rc, err, raw = r.returncode, (r.stderr or "")[:100], r.stdout
    except Exception as e:
        err = str(e)[:100]
    try:
        with open(SPEEDTEST_LAST_TS, "w") as f:
            f.write(str(time.time()))
    except OSError:
        pass
    if rc != 0:
        flags.append(f"SPEEDTEST failed to run (exit {rc}: "
                     f"{err.strip() or 'timeout'}) — host uplink test unavailable")
        return
    try:
        d = json.loads(raw or "{}")
        down = round(d["download"]["bandwidth"] * 8 / 1e6, 2)
        up = round(d["upload"]["bandwidth"] * 8 / 1e6, 2)
        ping = round(d["ping"]["latency"], 2)
    except Exception as e:
        flags.append(f"SPEEDTEST result parse failed: {str(e)[:80]}")
        return
    srv = d.get("server", {})
    try:  # persist the last result for the dashboard Watchdog tab
        with open(SPEEDTEST_RESULT_FILE, "w") as f:
            json.dump({"ts": time.time(), "down": down, "up": up, "ping": ping,
                       "server": f"{srv.get('name')} ({srv.get('location')})"},
                      f)
    except OSError:
        pass
    slow = []
    if down < DOWN_MIN_MBPS:
        slow.append(f"down {down} Mbps < {DOWN_MIN_MBPS}")
    if up < UP_MIN_MBPS:
        slow.append(f"up {up} Mbps < {UP_MIN_MBPS}")
    if ping > PING_MAX_MS:
        slow.append(f"ping {ping} ms > {PING_MAX_MS}")
    if slow:
        flags.append(f"SPEEDTEST slow: {'; '.join(slow)} — host uplink degraded "
                     f"(server: {srv.get('name')} ({srv.get('location')}))")


def _exit_rule_present():
    """True when BOTH sandbox steering rules are installed (pref 99 pins
    VPN-subnet->VPN-subnet to main so host replies to clients never enter
    the sandbox; pref 100 steers VPN-subnet internet egress into the
    sandbox table). NO `not to` clauses — they invert the whole rule on
    this kernel and blackhole host traffic."""
    out = sh("ip rule show").stdout
    return ("from 10.66.66.0/24 to 10.66.66.0/24 lookup main" in out
            and "from 10.66.66.0/24 lookup 100" in out)


def check_exit_provider(flags):
    """Exit-provider sanity: a tunnel profile must actually have its tunnel
    up and the host rule in place (otherwise devices are fail-closed offline
    or leaking direct); direct mode must not have a stale host rule.
    Settle window: skips tunnel-DOWN verdicts within 90s of a switch so a
    watchdog run right after a user's dashboard click can't fight it."""
    try:
        st = json.load(open(EXIT_STATE))
    except Exception:
        return
    profile = st.get("profile", "direct")
    sticky = st.get("sticky")
    if profile == "direct":
        if _exit_rule_present():
            flags.append("exit provider: stale host rule while profile is direct — "
                         "VPN devices may be blackholed")
        return
    if profile not in ("warp", "mullvad"):
        return
    if time.time() - float(st.get("last_switch_ts", 0) or 0) < 90:
        return  # settling; let the user's switch finish without interference
    iface = "warp-exitns" if profile == "warp" else "mullvad-exitns"
    r = sh(f"ip netns exec exitns ip link show {iface}")
    if r.returncode != 0:
        if sticky == profile:
            flags.append(f"exit provider {profile}: tunnel {iface} is DOWN — "
                         "VPN devices fail-closed (protection ON: retrying "
                         "tunnel, NOT reverting to direct)")
        else:
            flags.append(f"exit provider {profile}: tunnel {iface} is DOWN — "
                         "VPN devices are fail-closed offline; reverting to direct")
        return
    if not _exit_rule_present():
        flags.append(f"exit provider {profile}: host rule missing — devices leaking direct!")
    # handshake freshness (tunnel up but dead peer = silent blackhole)
    r = sh(f"ip netns exec exitns wg show {iface} latest-handshakes", timeout=10)
    if r.returncode == 0 and r.stdout.strip():
        now = time.time()
        for line in r.stdout.strip().splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and parts[2].isdigit():
                if now - float(parts[2]) > 180:
                    age = int(now - float(parts[2]))
                    if sticky == profile:
                        flags.append(f"exit provider {profile}: tunnel handshake stale "
                                     f"({age}s) — protection ON: retrying tunnel, "
                                     f"NOT reverting to direct")
                    else:
                        flags.append(f"exit provider {profile}: tunnel handshake stale "
                                     f"({age}s) — reverting to direct")


def run_checks():
    flags = []
    # SYSTEM checks first — the egress/speed tests load the box and would
    # skew the load-average reading.
    if SYSTEM_CHECKS:
        check_memory(flags)
        check_cpu_load(flags)
        check_disk(flags)
        check_failed_units(flags)
    check_container(flags)
    check_interface(flags)
    check_nft_rules(flags)
    check_adguard(flags)
    check_adblock(flags)
    check_rules_unit(flags)
    check_dashboard(flags)
    check_exit_provider(flags)
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
    check_speedtest(flags)
    rejected_handshake_probe(flags)
    return flags


def _meminfo():
    """(total_b, used_b, used_pct, swap_total, swap_used, swap_pct) from
    /proc/meminfo — stdlib-only so the cron script has no psutil dep."""
    try:
        d = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                d[k] = int(v.strip().split()[0]) * 1024  # kB -> bytes
        total = d.get("MemTotal", 0)
        avail = d.get("MemAvailable", d.get("MemFree", 0))
        used = max(total - avail, 0)
        pct = used / total * 100 if total else 0.0
        st = d.get("SwapTotal", 0)
        su = max(st - d.get("SwapFree", st), 0)
        spct = su / st * 100 if st else 0.0
        return total, used, pct, st, su, spct
    except Exception:
        return 0, 0, 0.0, 0, 0, 0.0


def _disk_usage(path="/"):
    """(total_b, used_b, used_pct) via statvfs (excludes reserved root space,
    matching df's 'Avail' semantics)."""
    try:
        s = os.statvfs(path)
        total = s.f_blocks * s.f_frsize
        free = s.f_bavail * s.f_frsize
        used = max(total - free, 0)
        return total, used, used / total * 100 if total else 0.0
    except OSError:
        return 0, 0, 0.0


def check_memory(flags):
    total, used, pct, st, su, spct = _meminfo()
    gb = 2 ** 30
    if pct >= RAM_PCT_MAX:
        detail = (f"RAM {pct:.1f}% used ({used/gb:.1f}G / {total/gb:.1f}G)")
        if st and spct >= SWAP_PCT_MAX:
            detail += f" · swap {spct:.1f}% used — memory pressure"
        flags.append(f"SYSTEM: memory pressure — {detail}. No scripted fix — "
                     "the AI agent investigates top consumers and reports.")


def check_cpu_load(flags):
    try:
        l1, l5, l15 = os.getloadavg()
    except OSError:
        return
    cores = os.cpu_count() or 1
    if l5 >= cores * LOAD_FACTOR:
        flags.append(f"SYSTEM: sustained high CPU load — loadavg "
                     f"{l1:.2f}/{l5:.2f}/{l15:.2f} on {cores} core(s). "
                     "No scripted fix — the AI agent investigates top "
                     "processes and reports.")


def check_disk(flags):
    total, used, pct = _disk_usage("/")
    gb = 2 ** 30
    if pct >= DISK_CRIT_PCT:
        flags.append(f"SYSTEM: root disk CRITICAL — {pct:.1f}% full "
                     f"({used/gb:.1f}G / {total/gb:.1f}G)")
    elif pct >= DISK_PCT_MAX:
        flags.append(f"SYSTEM: root disk {pct:.1f}% full "
                     f"({used/gb:.1f}G / {total/gb:.1f}G)")


def check_failed_units(flags):
    r = sh("systemctl --failed --no-legend --no-pager")
    units = [ln.split()[0] for ln in r.stdout.splitlines() if ln.strip()]
    if units:
        shown = ", ".join(units[:5]) + ("…" if len(units) > 5 else "")
        flags.append(f"SYSTEM: failed systemd unit(s): {shown}")


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
    ("healthcheck client", os.environ.get("ADD_WG_PROFILE_CMD", "bash /root/wg-easy/add-wg-profile.sh healthcheck"), 5, "recreated healthcheck client"),
    ("xeth", "systemctl restart wg-nft-rules", 2, "restarted wg-nft-rules (exit sandbox path)"),
    ("exit provider", f"test -x {EXIT_MANAGER} && python3 {EXIT_MANAGER} revert-if-down || true", 8,
     "exit provider verified (revert to direct only if tunnel down AND protection off)"),
    # system health: disk pressure -> safe cleanups (no-op when already small)
    ("SYSTEM: root disk", "journalctl --vacuum-size=200M && apt-get clean", 5,
     "vacuumed journal + cleaned apt cache (disk pressure)"),
]
# NOT script-fixed (no action): rejected handshakes (device-side), tcpdump
# missing, memory pressure, sustained CPU load, unknown flags — they go
# straight to Tier 2 so the AI investigates and reports.


def apply_scripted_fixes(flags):
    """Returns list of human-readable action descriptions actually executed.
    Dedupes identical commands. Handles the dynamic failed-unit restart
    (unit names live in the flag text, so they can't be static entries)."""
    done = {}
    descriptions = []
    # dynamic fix: restart failed systemd units named in the flag
    for f in list(flags):
        if f.startswith("SYSTEM: failed systemd unit"):
            for unit in re.findall(r"[a-zA-Z0-9@_.\-]+\.(?:service|socket|"
                                   r"timer|path|target)", f):
                if unit in done:
                    continue
                done[unit] = True
                r = sh(f"systemctl restart {unit}", timeout=60)
                descriptions.append(
                    f"restarted failed unit {unit}" if r.returncode == 0
                    else f"restart of {unit} FAILED ({r.stderr.strip()[:60]})")
                time.sleep(2)
            flags = [x for x in flags if not x.startswith(
                "SYSTEM: failed systemd unit")]
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


def log_incident(status, flags, actions):
    """Append a detailed incident record (JSONL) for the dashboard's Watchdog
    tab. Every flagged event is recorded with WHAT was found (full flag text)
    and what was done about it, so the UI shows detail instead of a bare
    'auto-fixed' line. Capped at ~200 lines (oldest pruned)."""
    try:
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "status": status, "flags": list(flags), "actions": list(actions)}
        with open(INCIDENTS_LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
        if os.path.getsize(INCIDENTS_LOG) > 200_000:
            with open(INCIDENTS_LOG) as f:
                lines = f.readlines()
            with open(INCIDENTS_LOG, "w") as f:
                f.writelines(lines[-200:])
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
    tier1_actions = []
    if SCRIPTED_FIX:
        tier1_actions = apply_scripted_fixes(flags)
        flags2 = run_checks()
        if not flags2:
            write_flags_file("FIXED-BY-SCRIPTED-TIER", flags)
            log_incident("FIXED-BY-SCRIPTED-TIER", flags, tier1_actions)
            print(f"VPN AUTO-FIXED (scripted): {len(flags)} issue(s) found and cleared")
            for f in flags:
                print(f"  - {f}")
            print(f"Actions: {'; '.join(tier1_actions) or 'checks self-healed'}")
            print("Re-check: all checks passing.")
            sys.exit(0)
        flags = flags2
    log_incident("UNFIXED", flags, tier1_actions)
    write_flags_file("UNFIXED", flags)

    # Tier 2: wake the AI
    print(f"VPN HEALTH CHECK FAILED — {len(flags)} issue(s)")
    for f in flags:
        print(f"FLAG: {f}")
    if tier1_actions:
        print(f"Scripted fixes attempted: {'; '.join(tier1_actions)}")
    if wake_autofix():
        print("(autofix agent woken)")
    sys.exit(1)


if __name__ == "__main__":
    main()
