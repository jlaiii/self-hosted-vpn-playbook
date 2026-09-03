#!/usr/bin/env python3
"""VPS Dashboard — tunnel-only Flask app (10.66.66.1:8088).

Tabs: Overview (CPU/RAM/disk/network live), VPN (peers/AdGuard/wg-easy links),
Services (containers + units), Speed Test (on-demand Ookla + history),
System (OS, fail2ban, top processes).

Data: sampler thread refreshes host stats every 2s; docker/wg data fetched
per request; speedtest runs in a background thread with a single-run lock.
"""
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

import psutil
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

BIND_HOST = os.environ.get("VPS_DASH_BIND", "10.66.66.1")
BIND_PORT = int(os.environ.get("VPS_DASH_PORT", "8088"))
SPEEDTEST_BIN = os.environ.get("SPEEDTEST_BIN", "/usr/local/bin/speedtest")
DATA_DIR = os.environ.get("VPS_DASH_DATA_DIR", "/root/vps-dash/data")
HISTORY_FILE = os.path.join(DATA_DIR, "speedtests.json")
WG_EASY_CONFIG = os.environ.get(
    "VPS_DASH_WG_EASY_CONFIG", "/root/wg-easy/config/wg0.json")
WG_CONF_FILE = os.environ.get("VPS_DASH_WG_CONF_FILE",
                              "/root/wg-easy/config/wg0.conf")

# ---------------------------------------------------------------- sampler ---
CACHE = {}
_cache_lock = threading.Lock()
_net_last = None
SNAPSHOT_FILE = os.path.join(DATA_DIR, "stats-cache.json")
SLOW_EVERY_S = 15  # containers/units/wg/f2b refresh cadence
_slow_last = {"ts": 0.0, "data": {"containers": [], "units": [],
                                  "wg": {"up": False, "peers": []}, "f2b": "n/a"}}
_slow_lock = threading.Lock()


def _load_persisted():
    """Warm the cache from disk so the first request is instant after restart."""
    try:
        with open(SNAPSHOT_FILE) as f:
            snap = json.load(f)
            if snap.get("ts"):
                return snap
    except Exception:
        pass
    return {}


CACHE.update(_load_persisted())


def _bytes_rate():
    global _net_last
    now = time.time()
    io = psutil.net_io_counters()
    if _net_last is None:
        _net_last = (now, io)
        return 0, 0
    t0, io0 = _net_last
    dt = max(now - t0, 0.5)
    _net_last = (now, io)
    rx = (io.bytes_recv - io0.bytes_recv) / dt
    tx = (io.bytes_sent - io0.bytes_sent) / dt
    return rx, tx


def _sample():
    rx_rate, tx_rate = _bytes_rate()
    vm = psutil.virtual_memory()
    sw = psutil.swap_memory()
    cpu = psutil.cpu_percent(interval=0.3)
    per_cpu = psutil.cpu_percent(interval=None, percpu=True)
    load = os.getloadavg()
    disks = []
    for p in psutil.disk_partitions(all=False):
        if p.fstype and "loop" not in p.device:
            try:
                u = psutil.disk_usage(p.mountpoint)
                disks.append({
                    "mount": p.mountpoint, "device": p.device,
                    "fstype": p.fstype, "total": u.total, "used": u.used,
                    "percent": u.percent,
                })
            except OSError:
                pass
    boot = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M")
    return {
        "ts": time.time(),
        "cpu": cpu,
        "per_cpu": per_cpu,
        "cores": psutil.cpu_count(logical=True),
        "cpu_model": _cpu_model(),
        "load": load,
        "mem_total": vm.total, "mem_used": vm.used,
        "mem_avail": vm.available, "mem_percent": vm.percent,
        "swap_total": sw.total, "swap_used": sw.used, "swap_percent": sw.percent,
        "disks": disks,
        "net_rx_rate": rx_rate, "net_tx_rate": tx_rate,
        "net_rx_total": psutil.net_io_counters().bytes_recv,
        "net_tx_total": psutil.net_io_counters().bytes_sent,
        "boot": boot,
        "procs": _top_procs(),
    }


def _cpu_model():
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


def _top_procs():
    procs = []
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            info = p.info
            if info["name"]:
                procs.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    procs.sort(key=lambda x: x["cpu_percent"] or 0, reverse=True)
    out = []
    for p in procs[:8]:
        out.append({
            "pid": p["pid"], "name": p["name"],
            "cpu": round(p["cpu_percent"] or 0, 1),
            "mem": round(p["memory_percent"] or 0, 1),
        })
    return out


def _os_info():
    uname = os.uname()
    return {"os": f"{uname.sysname} {uname.release}", "kernel": uname.release}


_SERVER_IP = {"v": "", "ts": 0}


def _server_ip():
    """VPS public IPv4, live-checked via ip.me, cached 15 min."""
    if time.time() - _SERVER_IP["ts"] < 900 and _SERVER_IP["v"]:
        return _SERVER_IP["v"]
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "6", "https://ip.me"],
            capture_output=True, text=True, timeout=10)
        ip = r.stdout.strip()
        if r.returncode == 0 and ip and "." in ip:
            _SERVER_IP.update(v=ip, ts=time.time())
            return ip
    except Exception:
        pass
    if _SERVER_IP["v"]:
        return _SERVER_IP["v"]
    return os.environ.get("WG_HOST", "")  # ip.me provides the live IP; env is the final fallback


def _slow_data():
    return {
        "containers": docker_containers(),
        "units": key_units(),
        "wg": wg_peers(),
        "f2b": f2b_bans(),
        "docker_inv": docker_inventory(),
        "reboot": reboot_status(),
        "watchdog": watchdog_status(),
        "server_ip": _server_ip(),
    }


def refresh(force_slow=False):
    """Compute a full snapshot and swap it into CACHE + disk (atomic)."""
    snap = _sample()
    snap.update(_os_info())
    with _slow_lock:
        if force_slow or time.time() - _slow_last["ts"] >= SLOW_EVERY_S:
            try:
                _slow_last["data"] = _slow_data()
                _slow_last["ts"] = time.time()
            except Exception:
                pass
        snap.update(_slow_last["data"])
    snap["speedtest_running"] = speedtest_running()
    with _cache_lock:
        CACHE.clear()
        CACHE.update(snap)
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = SNAPSHOT_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(snap, f)
        os.replace(tmp, SNAPSHOT_FILE)
    except Exception:
        pass
    return snap


def sampler_loop():
    while True:
        try:
            refresh()
        except Exception:
            pass
        try:
            _sample_metrics()
        except Exception:
            pass
        # per-peer bandwidth history (5-min cadence inside the sampler)
        try:
            _sample_peer_traffic()
        except Exception:
            pass
        time.sleep(5)

# ------------------------------------------------------------- containers ---
def docker_containers():
    try:
        r = subprocess.run(
            ["docker", "stats", "--no-stream", "--format", "json"],
            capture_output=True, text=True, timeout=15,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []
    out = []
    for line in r.stdout.strip().splitlines():
        try:
            d = json.loads(line)
            name = d.get("Name", "?")
            mem_used, mem_total = d.get("MemUsage", "/").split("/", 1)
            out.append({
                "name": name,
                "cpu": d.get("CPUPerc", "0%").strip().rstrip("%"),
                "mem": d.get("MemPerc", "0%").strip().rstrip("%"),
                "mem_used": mem_used.strip(), "mem_total": mem_total.strip(),
                "net": d.get("NetIO", ""),
                "pids": d.get("PIDs", "?"),
            })
        except Exception:
            continue
    out.sort(key=lambda c: c["name"].lower())
    return out


def key_units():
    units = ["adguardhome", "wg-nft-rules", "docker", "minecraft",
             "webjail", "fail2ban"]
    res = []
    for u in units:
        try:
            active = subprocess.run(
                ["systemctl", "is-active", u], capture_output=True, text=True,
                timeout=5).stdout.strip()
        except Exception:
            active = "unknown"
        res.append({"unit": u, "active": active})
    return res


# --------------------------------------------------------------------- vpn ---
def wg_peers():
    peers = []
    names = {}
    try:
        cfg = json.load(open(WG_EASY_CONFIG))
        names = {c["publicKey"]: c["name"] for c in cfg.get("clients", {}).values()}
    except Exception:
        pass
    try:
        r = subprocess.run(["wg", "show", "wg0", "dump"],
                           capture_output=True, text=True, timeout=10)
    except Exception:
        return {"up": False, "peers": []}
    now = time.time()
    for line in r.stdout.strip().splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) < 8:   # interface line has 4 fields; peers have 8
            continue
        pub = parts[0]
        endpoint = parts[2] or "—"
        allowed = parts[3]
        tun_ip = allowed.split(",")[0].split("/")[0] if allowed else "—"
        dev_ip = "—"
        if endpoint and endpoint != "—":
            if endpoint.startswith("["):
                dev_ip = endpoint.split("]")[0].lstrip("[")
            else:
                dev_ip = endpoint.rsplit(":", 1)[0]
        hs = parts[4]
        if hs == "0":
            hs_txt = "never"
            connected = False
        else:
            age = now - int(hs)
            if age < 60:
                hs_txt = f"{int(age)}s ago"
            elif age < 3600:
                hs_txt = f"{int(age // 60)}m ago"
            elif age < 86400:
                hs_txt = f"{int(age // 3600)}h ago"
            else:
                hs_txt = f"{int(age // 86400)}d ago"
            connected = age < 180
        peers.append({
            "name": names.get(pub, pub[:10] + "…"),
            "endpoint": endpoint,
            "ip": tun_ip,
            "device_ip": dev_ip,
            "handshake": hs_txt,
            "connected": connected,
            "rx": int(parts[5]), "tx": int(parts[6]),
        })
    return {"up": True, "peers": peers}


def f2b_bans():
    try:
        r = subprocess.run(["fail2ban-client", "status", "sshd"],
                           capture_output=True, text=True, timeout=8)
        for line in r.stdout.splitlines():
            if "Currently banned" in line:
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return "n/a"


# ------------------------------------------------------------------ docker ---
_DOCKER_INV_CACHE = {"ts": 0.0, "data": None}
DOCKER_INV_EVERY_S = 30  # full inventory (ps -a + images + volumes + df)


def _docker_json(args):
    """Run docker <args> with JSON output; return list of parsed objects."""
    try:
        r = subprocess.run(["docker"] + args, capture_output=True, text=True,
                           timeout=25)
        if r.returncode != 0:
            return None
        return [json.loads(line) for line in r.stdout.splitlines() if line.strip()]
    except Exception:
        return None


def docker_inventory():
    """Full Docker inventory: all containers, images, volumes, networks,
    compose projects, and disk usage. Cached 30 s (local daemon, cheap).
    """
    now = time.time()
    if _DOCKER_INV_CACHE["data"] and now - _DOCKER_INV_CACHE["ts"] < DOCKER_INV_EVERY_S:
        return _DOCKER_INV_CACHE["data"]
    inv = {"containers": [], "images": [], "volumes": [], "networks": [],
           "projects": [], "df": [], "error": None}

    ps = _docker_json(["ps", "-a", "--format", "json"])
    if ps is None:
        inv["error"] = "docker daemon unreachable"
    else:
        projects = {}
        for c in ps:
            labels = {}
            for kv in (c.get("Labels") or "").split(","):
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    labels[k] = v
            proj = labels.get("com.docker.compose.project")
            svc = labels.get("com.docker.compose.service")
            running = c.get("State") == "running"
            inv["containers"].append({
                "id": c.get("ID", "")[:12],
                "name": c.get("Names", "").lstrip("/"),
                "image": c.get("Image", ""),
                "state": c.get("State", "?"),
                "status": c.get("Status", ""),
                "ports": c.get("Ports", ""),
                "created": c.get("RunningFor", ""),
                "running": running,
            })
            if proj and svc:
                p = projects.setdefault(proj, {"services": {}, "total": 0, "up": 0})
                p["total"] += 1
                p["up"] += 1 if running else 0
                p["services"][svc] = p["services"].get(svc, 0) + 1
        inv["projects"] = [
            {"project": name, "services": ", ".join(
                f"{s}" + (f"×{n}" if n > 1 else "") for s, n in sorted(p["services"].items())),
             "total": p["total"], "up": p["up"]}
            for name, p in sorted(projects.items())]

    inv["images"] = [{
        "repo": i.get("Repository", ""), "tag": i.get("Tag", ""),
        "size": i.get("Size", ""), "created": i.get("CreatedSince", ""),
        "containers": i.get("Containers", "0"),
        "id": i.get("ID", "")[:12],
    } for i in (_docker_json(["images", "--format", "json"]) or [])]

    inv["volumes"] = [{
        "name": v.get("Name", ""), "driver": v.get("Driver", ""),
        "mountpoint": v.get("Mountpoint", ""),
    } for v in (_docker_json(["volume", "ls", "--format", "json"]) or [])]

    inv["networks"] = [{
        "name": n.get("Name", ""), "driver": n.get("Driver", ""),
        "scope": n.get("Scope", ""), "internal": n.get("Internal") == "true",
    } for n in (_docker_json(["network", "ls", "--format", "json"]) or [])]

    for line in (_docker_json(["system", "df", "--format", "json"]) or []):
        inv["df"].append({
            "type": line.get("Type", ""), "total": line.get("TotalCount", ""),
            "active": line.get("Active", ""), "size": line.get("Size", ""),
            "reclaimable": line.get("Reclaimable", ""),
        })

    _DOCKER_INV_CACHE.update(ts=now, data=inv)
    return inv


# ------------------------------------------------------------ maintenance ---
# OS reboot (10-min cooldown between requests, persisted across restarts)
REBOOT_COOLDOWN_S = 600
REBOOT_SCRIPT = os.environ.get("VPS_DASH_REBOOT_SCRIPT",
                               "/root/vps-dash/reboot_system.py")
REBOOT_STATE_FILE = os.path.join(DATA_DIR, "reboot-state.json")
_reboot_lock = threading.Lock()
_reboot_pending = False


def _load_reboot_state():
    try:
        with open(REBOOT_STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_reboot_state(st):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        tmp = REBOOT_STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(st, f)
        os.replace(tmp, REBOOT_STATE_FILE)
    except Exception:
        pass


def _schedule_reboot(reason, delay=5):
    """Fire the reboot script detached; record the request for cooldown."""
    global _reboot_pending
    _reboot_pending = True
    st = _load_reboot_state()
    st["last_request"] = time.time()
    _save_reboot_state(st)
    try:
        subprocess.Popen(
            [sys.executable, REBOOT_SCRIPT, "--delay", str(delay),
             "--reason", reason],
            start_new_session=True)
    except Exception:
        _reboot_pending = False


def reboot_status():
    st = _load_reboot_state()
    last = st.get("last_request", 0)
    return {
        "pending": _reboot_pending,
        "last_request": int(last),
        "cooldown_until": int(last + REBOOT_COOLDOWN_S),
    }


# Hermes self-update (check read-only; run does git pull + dep reinstall,
# then reboots the OS via the reboot script)
_UPDATE_LOCK = threading.Lock()
# --------------------------------------------------------------- watchdog ---
WATCHDOG_SCRIPT = os.environ.get("VPS_DASH_WATCHDOG_SCRIPT",
                                 "/root/.hermes/scripts/vpn-health-check.py")
WATCHDOG_OUT_DIR = os.environ.get("VPS_DASH_WATCHDOG_OUT_DIR",
                                  "/root/.hermes/cron/output/6ce95323d108")
AUTOFIX_OUT_DIR = os.environ.get("VPS_DASH_AUTOFIX_OUT_DIR",
                                 "/root/.hermes/cron/output/42e7b3d2b0cd")
WD_FLAGS_FILE = "/tmp/vpn-last-flags.txt"
# incidents file lives beside the dashboard's own data dir (watchdog cron
# writes the same path via INCIDENTS_LOG env) — portable across installs
WD_INCIDENTS_FILE = os.environ.get("WD_INCIDENTS_FILE",
                                   os.path.join(DATA_DIR, "vpn-incidents.jsonl"))
WD_SPEEDTEST_FILE = "/tmp/vpn-speedtest-last.json"
_wd_lock = threading.Lock()
_wd_running = False
_wd_result = None  # {ts, exit_code, output, duration}


def _read_dir_reports(d, limit, keep_output=True):
    """Newest-first runs from a cron output dir: [{ts, status, report, output}].

    Agent-job files (vpn-autofix) embed the full prompt + context before the
    actual result; only the '## Response' section is user-facing, so it is
    extracted separately (report=) and the raw file text (output=) is kept for
    the no_agent watchdog runs only.
    """
    out = []
    try:
        names = sorted(os.listdir(d), reverse=True)
    except Exception:
        return out
    for n in names[:limit]:
        if not n.endswith(".md"):
            continue
        try:
            text = open(os.path.join(d, n)).read()
            status = "unknown"
            report = ""
            if "\n## Response\n" in text:
                # Agent job: the Response section is authoritative — the
                # '**Status:**' lines belong to injected watchdog context.
                report = text.split("\n## Response\n", 1)[1].strip()
                if report.startswith("[SILENT]"):
                    status = "silent"
                else:
                    status = "responded"
            elif "\n## Error\n" in text:
                status = "error"
            else:
                for line in text.splitlines():
                    if line.startswith("**Status:**"):
                        status = line.split("**Status:**", 1)[1].strip()
                        break
            silent = "silent" in status.lower()
            if silent:
                report = ""
            out.append({
                "ts": n[:19].replace("_", " "),
                "status": status,
                "silent": silent,
                "report": report[:1500],
                "output": text[:1500] if (keep_output and not silent) else "",
            })
        except Exception:
            continue
    return out


def _read_incidents(limit=20):
    """Detailed flag incidents from vpn-health-check.py's JSONL log,
    newest first: [{ts, status, flags: [...], actions: [...]}]."""
    out = []
    try:
        with open(WD_INCIDENTS_FILE) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return out
    return out[-limit:][::-1]


def watchdog_status():
    st = {"healthy": True, "flags": [], "running": _wd_running,
          "last_result": _wd_result, "last_speedtest": None, "last_check": None,
          "incidents": [], "flags_ts": None}
    try:
        lines = open(WD_FLAGS_FILE).read().splitlines()
        st["flags"] = [l[6:] for l in lines if l.startswith("FLAG:")]
        st["healthy"] = not st["flags"]
        st["flags_ts"] = time.strftime("%Y-%m-%d %H:%M:%S UTC",
                                       time.gmtime(os.path.getmtime(WD_FLAGS_FILE)))
    except Exception:
        pass
    st["incidents"] = _read_incidents(8)
    try:
        st["last_speedtest"] = json.load(open(WD_SPEEDTEST_FILE))
    except Exception:
        pass
    hist = _read_dir_reports(WATCHDOG_OUT_DIR, 3, keep_output=False)
    if hist:
        st["last_check"] = hist[0]["ts"]
    return st


def _run_watchdog_check():
    global _wd_running, _wd_result
    t0 = time.time()
    try:
        r = subprocess.run(["python3", WATCHDOG_SCRIPT],
                           capture_output=True, text=True, timeout=150)
        _wd_result = {"ts": int(time.time()), "exit_code": r.returncode,
                      "output": (r.stdout + r.stderr).strip()[-4000:],
                      "duration": round(time.time() - t0, 1)}
    except Exception as e:
        _wd_result = {"ts": int(time.time()), "exit_code": -1,
                      "output": str(e)[:300],
                      "duration": round(time.time() - t0, 1)}
    _wd_running = False


@app.route("/api/watchdog/history")
def api_watchdog_history():
    return jsonify({
        "checks": _read_dir_reports(WATCHDOG_OUT_DIR, 30),
        "autofix": _read_dir_reports(AUTOFIX_OUT_DIR, 8),
        "incidents": _read_incidents(30),
    })


@app.route("/api/watchdog/run", methods=["POST"])
def api_watchdog_run():
    global _wd_running
    with _wd_lock:
        if _wd_running:
            return jsonify({"error": "A check is already running.",
                            "status": "running"}), 409
        _wd_running = True
        _wd_result = None
    threading.Thread(target=_run_watchdog_check, daemon=True).start()
    log_action("watchdog", "manual health check run (Run Check Now)")
    return jsonify({"status": "started"})


# ---------------------------------------------------------------- history ---
# Logs tab: 1-min resource history (90d tiered retention), admin action audit
# trail, system events (boots/updates/packages), security & access events.
METRICS_FILE = os.path.join(DATA_DIR, "metrics.jsonl")
ACTIONS_FILE = os.path.join(DATA_DIR, "admin-actions.jsonl")
METRICS_EVERY_S = 60
_metrics_last = {"ts": 0.0}
_hist_cache = {"ts": 0.0, "system": None, "security": None}
HIST_CACHE_TTL_S = 60


def _sample_metrics():
    """Append one compact resource sample per minute (from the sampler loop).
    Fields: t (epoch), cpu %, mem %, disk % (root), rx/tx Mbps."""
    now = time.time()
    if now - _metrics_last["ts"] < METRICS_EVERY_S:
        return
    _metrics_last["ts"] = now
    try:
        vm = psutil.virtual_memory()
        disk_pct = 0.0
        try:
            disk_pct = psutil.disk_usage("/").percent
        except OSError:
            pass
        rx, tx = _bytes_rate()
        row = {
            "t": int(now),
            "cpu": round(psutil.cpu_percent(interval=0.25), 1),
            "mem": round(vm.percent, 1),
            "disk": round(disk_pct, 1),
            "rx": round(rx * 8 / 1e6, 2),
            "tx": round(tx * 8 / 1e6, 2),
        }
        with open(METRICS_FILE, "a") as f:
            f.write(json.dumps(row) + "\n")
        _prune_metrics()
    except Exception:
        pass


def _prune_metrics():
    """90-day retention, tiered: 1-min samples < 7d, every 5th (5-min) to 30d,
    every 15th (15-min) to 90d. Rewrites only when the file grows past ~25k
    rows (~2.5 MB)."""
    try:
        if os.path.getsize(METRICS_FILE) < 2_500_000:
            return
        with open(METRICS_FILE) as f:
            lines = f.readlines()
        now = time.time()
        keep, c7, c30 = [], 0, 0
        for ln in lines:
            try:
                t = json.loads(ln)["t"]
            except Exception:
                continue
            age = now - t
            if age < 7 * 86400:
                keep.append(ln)
            elif age < 30 * 86400:
                c7 += 1
                if c7 % 5 == 0:
                    keep.append(ln)
            else:
                c30 += 1
                if c30 % 15 == 0:
                    keep.append(ln)
        with open(METRICS_FILE, "w") as f:
            f.writelines(keep[-20000:])
    except Exception:
        pass


def log_action(action, detail, origin="dashboard"):
    """Append a state-changing admin action to the audit trail (JSONL).
    Called by mutating API endpoints; capped at 2000 lines."""
    try:
        with open(ACTIONS_FILE, "a") as f:
            f.write(json.dumps({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "action": action, "detail": detail, "origin": origin}) + "\n")
        if os.path.getsize(ACTIONS_FILE) > 300_000:
            with open(ACTIONS_FILE) as f:
                lines = f.readlines()
            with open(ACTIONS_FILE, "w") as f:
                f.writelines(lines[-2000:])
    except Exception:
        pass


def _client_name(client_id):
    try:
        cfg = json.load(open(WG_EASY_CONFIG))
        for k, c in cfg.get("clients", {}).items():
            if k == client_id or c.get("id") == client_id:
                return c.get("name") or k
    except Exception:
        pass
    return client_id


def _ts_epoch(s):
    s = (s or "").strip()
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S UTC",
                "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(
                tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _boots():
    try:
        r = subprocess.run(["journalctl", "--list-boots", "--no-pager"],
                           capture_output=True, text=True, timeout=15)
    except Exception:
        return []
    boots = []
    for line in r.stdout.splitlines()[1:]:
        p = line.split()
        if len(p) < 7:
            continue
        start = " ".join(p[2:6])
        end = " ".join(p[6:10]) if len(p) >= 10 else ""
        dur = None
        try:
            t0 = datetime.strptime(start, "%a %Y-%m-%d %H:%M:%S %Z")
            if end:
                t1 = datetime.strptime(end, "%a %Y-%m-%d %H:%M:%S %Z")
                dur = int(t1.timestamp() - t0.timestamp())
        except ValueError:
            pass
        boots.append({"id": p[0], "start": start, "end": end, "duration": dur})
    return boots


def _apt_history(days):
    out = []
    try:
        cur = None
        with open("/var/log/apt/history.log") as f:
            for raw in f:
                line = raw.strip()
                if line.startswith("Start-Date:"):
                    cur = {"ts": line.split(":", 1)[1].strip(),
                           "cmd": "", "pkgs": []}
                elif line.startswith("Commandline:") and cur:
                    cur["cmd"] = line.split(":", 1)[1].strip()
                elif (line.startswith("Upgrade:") or line.startswith("Install:")
                      or line.startswith("Remove:")) and cur:
                    # apt names are `pkg:arch (old, new)` — versions inside the
                    # parens contain commas, so split on commas is wrong.
                    for name in re.findall(
                            r"([a-zA-Z0-9][a-zA-Z0-9.+-]*):(?:amd64|arm64|all|"
                            r"i386|riscv64|ppc64el|s390x|noarch)\b", line):
                        if name and name not in cur["pkgs"]:
                            cur["pkgs"].append(name)
                elif line.startswith("End-Date:") and cur:
                    out.append(cur)
                    cur = None
    except OSError:
        return []
    res = []
    for e in out:
        try:
            t = datetime.strptime(e["ts"], "%Y-%m-%d  %H:%M:%S")
            if time.time() - t.replace(tzinfo=timezone.utc).timestamp() \
                    <= days * 86400:
                res.append(e)
        except ValueError:
            continue
    return res[-30:]


def _exit_log_events(days):
    """VPN exit switches from exit-manager.log (CLI/cron/boot/dashboard origin)."""
    try:
        lines = open(os.path.join(DATA_DIR, "exit-manager.log")).readlines()
    except OSError:
        return []
    out = []
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        try:
            ts_part, rest = line.split(" ", 1)
        except ValueError:
            continue
        t = _ts_epoch(ts_part)
        if t is None or time.time() - t > days * 86400:
            continue
        caller = ""
        if "(caller:" in rest:
            rest2, caller = rest.split("(caller:", 1)
            caller = caller.rstrip(")").strip()
            rest = rest2.strip()
        if rest.startswith("switch: "):
            detail = rest.replace("switch: ", "")
            origin = _caller_label(caller)
            out.append({"t": t, "category": "vpn", "action": "exit switch",
                        "detail": detail, "origin": origin})
        elif rest.startswith("switch FAILED"):
            out.append({"t": t, "category": "vpn", "action": "exit switch (failed)",
                        "detail": rest, "origin": _caller_label(caller)})
        elif rest.startswith("sticky "):
            out.append({"t": t, "category": "vpn", "action": "protection (sticky)",
                        "detail": rest, "origin": _caller_label(caller)})
        elif rest.startswith("manual switch"):
            out.append({"t": t, "category": "vpn", "action": "exit switch",
                        "detail": rest, "origin": _caller_label(caller)})
    return out


def _caller_label(caller):
    if not caller:
        return "CLI"
    if caller.startswith("/sbin/init") or caller.startswith("systemd"):
        return "boot restore"
    if "vpn-health-check" in caller:
        return "watchdog"
    if "hermes" in caller:
        return "cron/agent"
    if "blocked-scripts" in caller:
        return "test/agent"
    return "CLI"


def _incident_events(days):
    try:
        lines = open(WD_INCIDENTS_FILE).readlines()
    except OSError:
        return []
    out = []
    for raw in lines:
        try:
            d = json.loads(raw)
        except ValueError:
            continue
        t = _ts_epoch(d.get("ts", ""))
        if t is None or time.time() - t > days * 86400:
            continue
        status = d.get("status", "")
        detail = "; ".join(d.get("flags", []))[:300] or "(no detail)"
        out.append({"t": t, "category": "watchdog",
                    "action": "vpn flagged" if status == "UNFIXED"
                    else "vpn auto-fixed",
                    "detail": detail, "origin": "vpn-health-check.py"})
    return out


@app.route("/api/history/metrics")
def api_history_metrics():
    rng = request.args.get("range", "24h")
    hours = {"24h": 24, "7d": 168, "30d": 720, "90d": 2160}.get(rng, 24)
    now = time.time()
    rows = []
    try:
        with open(METRICS_FILE) as f:
            for line in f:
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                if now - d.get("t", 0) <= hours * 3600:
                    rows.append(d)
    except OSError:
        pass
    step = max(1, len(rows) // 240)
    pts = rows[::step] if step > 1 else rows
    if pts and rows and pts[-1] is not rows[-1]:
        pts.append(rows[-1])
    return jsonify({"range": rng, "count": len(rows), "points": pts,
                    "since": rows[0]["t"] if rows else None,
                    "retention_days": 90})


@app.route("/api/history/system")
def api_history_system():
    if _hist_cache["system"] and \
            time.time() - _hist_cache["ts"] < HIST_CACHE_TTL_S:
        return jsonify(_hist_cache["system"])
    days = int(request.args.get("days", 30))
    updates = []
    try:
        for line in open(os.path.join(DATA_DIR, "auto-update.log")):
            try:
                d = json.loads(line)
                t = _ts_epoch(d.get("ts", ""))
                if t is not None and time.time() - t <= days * 86400:
                    d["t"] = t
                    updates.append(d)
            except Exception:
                continue
    except OSError:
        pass
    data = {"boots": _boots(), "updates": updates[-60:],
            "packages": _apt_history(days)}
    _hist_cache.update(ts=time.time(), system=data)
    return jsonify(data)


@app.route("/api/history/security")
def api_history_security():
    if _hist_cache["security"] and \
            time.time() - _hist_cache["ts"] < HIST_CACHE_TTL_S:
        return jsonify(_hist_cache["security"])
    days = int(request.args.get("days", 7))
    since = f"{days} days ago"
    logins, bans = [], []
    try:
        r = subprocess.run(
            ["journalctl", "--since", since, "-u", "ssh", "-u", "sshd",
             "--no-pager", "-o", "short-iso"],
            capture_output=True, text=True, timeout=25)
        pat_acc = re.compile(
            r"Accepted (publickey|password) for(?: invalid user)? (\S+) "
            r"from (\S+) port")
        pat_fail = re.compile(
            r"Failed password for(?: invalid user)? (\S+) from (\S+) port")
        pat_inv = re.compile(r"Invalid user (\S+) from (\S+) port")
        for raw in r.stdout.splitlines():
            try:
                ts_part = raw.split(" ", 1)[0]
                t = _ts_epoch(ts_part)
                if t is None:
                    continue
                m = pat_acc.search(raw)
                if m:
                    logins.append({"t": t, "kind": "accepted",
                                   "user": m.group(2), "ip": m.group(3)})
                    continue
                m = pat_inv.search(raw)
                if m:
                    logins.append({"t": t, "kind": "invalid",
                                   "user": m.group(1), "ip": m.group(2)})
                    continue
                m = pat_fail.search(raw)
                if m:
                    logins.append({"t": t, "kind": "failed",
                                   "user": m.group(1), "ip": m.group(2)})
            except Exception:
                continue
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["journalctl", "--since", since, "-u", "fail2ban", "--no-pager",
             "-o", "short-iso"],
            capture_output=True, text=True, timeout=25)
        for raw in r.stdout.splitlines():
            if " Ban " not in raw and " Unban " not in raw:
                continue
            m = re.search(r"\b(?:Ban|Unban)\s+(\S+)", raw)
            if not m:
                continue
            ts_part = raw.split(" ", 1)[0]
            t = _ts_epoch(ts_part)
            if t is None:
                continue
            bans.append({"t": t, "ip": m.group(1),
                         "kind": "ban" if " Ban " in raw else "unban"})
    except Exception:
        pass
    # fail2ban logs bans to its own file (NOT journald on this host)
    try:
        pat_ban = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})[^:]*: "
                             r"NOTICE\s+\[\S+\]\s+(Ban|Unban)\s+(\S+)")
        with open("/var/log/fail2ban.log") as f:
            for raw in f:
                m = pat_ban.search(raw)
                if not m:
                    continue
                t = _ts_epoch(m.group(1))
                if t is None or time.time() - t > days * 86400:
                    continue
                bans.append({"t": t, "ip": m.group(3),
                             "kind": m.group(2).lower()})
    except OSError:
        pass
    logins.sort(key=lambda x: x["t"], reverse=True)
    bans.sort(key=lambda x: x["t"], reverse=True)
    failed = [x for x in logins if x["kind"] == "failed"]
    data = {
        "days": days,
        "summary": {
            "accepted": sum(1 for x in logins if x["kind"] == "accepted"),
            "failed": len(failed),
            "invalid": sum(1 for x in logins if x["kind"] == "invalid"),
            "failed_ips": len({x["ip"] for x in failed}),
            "bans": len(bans),
            "banned_now": f2b_bans(),
        },
        "logins": logins[:150],
        "bans": bans[:100],
    }
    _hist_cache.update(ts=time.time(), security=data)
    return jsonify(data)


@app.route("/api/history/actions")
def api_history_actions():
    days = int(request.args.get("days", 30))
    events = []
    try:
        for line in open(ACTIONS_FILE):
            try:
                d = json.loads(line)
                t = _ts_epoch(d.get("ts", ""))
                if t is not None and time.time() - t <= days * 86400:
                    d["t"] = t
                    d["category"] = "admin"
                    events.append(d)
            except Exception:
                continue
    except OSError:
        pass
    events += _exit_log_events(days)
    events += _incident_events(days)
    events.sort(key=lambda x: x.get("t", 0), reverse=True)
    return jsonify({"events": events[:300]})


# ----------------------------------------------------------- notifications ---
NOTIF_STATE_FILE = os.path.join(DATA_DIR, "notif-state.json")
NOTIF_KINDS = {"incident": "flag", "ban": "security", "unban": "security",
               "action": "activity"}
NOTIF_LABELS = {"incident": "Watchdog flag", "ban": "IP banned",
                "unban": "IP unbanned", "action": "Admin action"}


def _notif_state_read():
    try:
        return json.load(open(NOTIF_STATE_FILE)).get("last_viewed", 0) or 0
    except Exception:
        return 0


def _notif_state_write(ts):
    try:
        with open(NOTIF_STATE_FILE, "w") as f:
            f.write(json.dumps({"last_viewed": ts}) + "\n")
    except OSError:
        pass


def _notifications(limit=30):
    """Merged alert feed: watchdog incidents + fail2ban bans + admin actions,
    newest first. Each item: {t, kind, title, detail, icon}."""
    items = []
    try:
        for line in open(WD_INCIDENTS_FILE):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            t = _ts_epoch(d.get("ts", "")) or 0
            if not t:
                continue
            flags = d.get("flags") or []
            items.append({
                "t": t, "kind": "incident",
                "title": "Watchdog: " + (d.get("status") or "flagged"),
                "detail": flags[0][:160] if flags else (d.get("status") or ""),
                "count": len(flags),
            })
    except OSError:
        pass
    try:
        for line in open(ACTIONS_FILE):
            try:
                d = json.loads(line)
            except ValueError:
                continue
            t = _ts_epoch(d.get("ts", "")) or 0
            if not t:
                continue
            items.append({"t": t, "kind": "action",
                          "title": d.get("action") or "action",
                          "detail": (d.get("detail") or "")[:160]})
    except OSError:
        pass
    # bans from fail2ban.log (last 3 days, cap 10) — cheap tail read
    try:
        pat = re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})[^:]*: "
                         r"NOTICE\s+\[\S+\]\s+(Ban|Unban)\s+(\S+)")
        now = time.time()
        with open("/var/log/fail2ban.log") as f:
            for raw in f:
                m = pat.search(raw)
                if not m:
                    continue
                t = _ts_epoch(m.group(1))
                if t is None or now - t > 3 * 86400:
                    continue
                act = m.group(2).lower()
                items.append({"t": t, "kind": act,
                              "title": "IP " + act + " — " + m.group(3),
                              "detail": "fail2ban sshd jail"})
    except OSError:
        pass
    items.sort(key=lambda x: x["t"], reverse=True)
    return items[:limit]


@app.route("/api/notifications")
def api_notifications():
    items = _notifications(30)
    last = _notif_state_read()
    unread = sum(1 for it in items if it["t"] > last)
    return jsonify({"items": items, "unread": unread,
                    "last_viewed": last})


@app.route("/api/notifications/view", methods=["POST"])
def api_notifications_view():
    _notif_state_write(int(time.time()))
    return jsonify({"ok": True, "unread": 0})


# ------------------------------------------------------------------ exports ---
def _csv_response(filename, rows, header=None):
    """Render rows (list of lists) as an attachment CSV."""
    import csv as _csv
    import io as _io
    buf = _io.StringIO()
    w = _csv.writer(buf)
    if header:
        w.writerow(header)
    w.writerows(rows)
    resp = app.make_response("\ufeff" + buf.getvalue())  # BOM for Excel
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return resp


def _json_response(filename, data):
    resp = app.make_response(json.dumps(data, indent=2))
    resp.headers["Content-Type"] = "application/json; charset=utf-8"
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return resp


def _fmt_ts_local(t):
    try:
        return datetime.fromtimestamp(t, timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


@app.route("/api/export/actions")
def api_export_actions():
    days = int(request.args.get("days", 30))
    rows = []
    try:
        for line in open(ACTIONS_FILE):
            try:
                d = json.loads(line)
            except ValueError:
                continue
            t = _ts_epoch(d.get("ts", "")) or 0
            if t and time.time() - t <= days * 86400:
                rows.append([_fmt_ts_local(t), d.get("action", ""),
                             d.get("detail", ""), d.get("origin", "")])
            elif not t:
                rows.append([d.get("ts", ""), d.get("action", ""),
                             d.get("detail", ""), d.get("origin", "")])
    except OSError:
        pass
    rows.sort(reverse=True)
    if request.args.get("fmt") == "json":
        return _json_response(f"admin-actions-{days}d.json", rows)
    return _csv_response(f"admin-actions-{days}d.csv", rows,
                         ["time_utc", "action", "detail", "origin"])


@app.route("/api/export/security")
def api_export_security():
    days = int(request.args.get("days", 7))
    sec = api_history_security().get_json()
    rows = []
    for b in sec.get("bans", []):
        rows.append([_fmt_ts_local(b["t"]), b.get("kind", ""), b.get("ip", "")])
    for l in sec.get("logins", []):
        rows.append([_fmt_ts_local(l["t"]), l.get("kind", ""),
                     l.get("user", ""), l.get("ip", "")])
    rows.sort(reverse=True)
    if request.args.get("fmt") == "json":
        return _json_response(f"security-{days}d.json", rows)
    return _csv_response(f"security-{days}d.csv", rows,
                         ["time_utc", "event", "user_or_ip", "ip"])


@app.route("/api/export/speedtests")
def api_export_speedtests():
    hist = load_history()
    rows = []
    for h in hist:
        if h.get("error"):
            rows.append([h.get("ts", ""), "error", "", "", "", "", h["error"]])
        else:
            rows.append([h.get("ts", ""), h.get("ping", ""), h.get("jitter", ""),
                         h.get("loss", ""), h.get("down_mbps", ""),
                         h.get("up_mbps", ""), h.get("server", "")])
    rows.sort(reverse=True)
    if request.args.get("fmt") == "json":
        return _json_response("speedtests.json", rows)
    return _csv_response("speedtests.csv", rows,
                         ["time_utc", "ping_ms", "jitter_ms", "loss_pct",
                          "down_mbps", "up_mbps", "server"])


@app.route("/api/export/metrics")
def api_export_metrics():
    rng = request.args.get("range", "24h") or "24h"
    rows = []
    try:
        for line in open(METRICS_FILE):
            try:
                d = json.loads(line)
            except ValueError:
                continue
            t = d.get("t", 0)
            if rng == "24h" and time.time() - t > 86400:
                continue
            if rng == "7d" and time.time() - t > 7 * 86400:
                continue
            rows.append([_fmt_ts_local(t), d.get("cpu", ""), d.get("mem", ""),
                         d.get("disk", ""), d.get("rx", ""), d.get("tx", "")])
    except OSError:
        pass
    rows.sort()
    if request.args.get("fmt") == "json":
        return _json_response(f"metrics-{rng}.json", rows)
    return _csv_response(f"metrics-{rng}.csv", rows,
                         ["time_utc", "cpu_pct", "mem_pct", "disk_pct",
                          "rx_mbps", "tx_mbps"])


# ------------------------------------------------------ health summary -----
@app.route("/api/health")
def api_health():
    """Header traffic light: combines watchdog flags, disk pressure, fail2ban
    activity, pending Hermes update and scheduled reboot into one level."""
    flags = []
    try:
        lines = open(WD_FLAGS_FILE).read().splitlines()
        flags = [l[6:] for l in lines if l.startswith("FLAG:")]
    except Exception:
        pass
    disk = 0.0
    try:
        disk = psutil.disk_usage("/").percent
    except Exception:
        pass
    banned = 0
    try:
        banned = int(_f2b_status().get("banned_now") or 0)
    except Exception:
        pass
    rb = False
    try:
        rb = bool(_reboot_pending)
    except Exception:
        pass
    upd = False  # Hermes auto-updater is box-specific; not part of portable stack
    level = "ok"
    issues = []
    if flags:
        level = "bad"
        issues.append(f"{len(flags)} watchdog flag(s)")
    if disk >= 95:
        level = "bad"
        issues.append(f"disk {disk:.0f}%")
    if rb:
        level = "bad"
        issues.append("reboot scheduled")
    if level == "ok" and (disk >= 85 or banned or upd):
        level = "warn"
        if disk >= 85:
            issues.append(f"disk {disk:.0f}%")
        if banned:
            issues.append(f"{banned} banned IP")
        if upd:
            issues.append("update pending")
    return jsonify({"level": level, "issues": issues, "flags": len(flags),
                    "disk_pct": round(disk, 1), "banned": banned,
                    "reboot_pending": rb, "update_pending": upd})


# -------------------------------------------------- per-peer traffic --------
PEER_TRAFFIC_FILE = os.path.join(DATA_DIR, "peer-traffic.jsonl")
PEER_TRAFFIC_EVERY_S = 300
_peer_traffic_last = {"ts": 0.0}


def _sample_peer_traffic():
    """Append cumulative wg rx/tx counters per peer every 5 min (sampler)."""
    now = time.time()
    if now - _peer_traffic_last["ts"] < PEER_TRAFFIC_EVERY_S:
        return
    _peer_traffic_last["ts"] = now
    try:
        wg = wg_peers()
    except Exception:
        return
    if not wg.get("up"):
        return
    row = {"t": int(now), "peers": [
        {"name": p.get("name", "?"), "rx": p.get("rx", 0), "tx": p.get("tx", 0)}
        for p in wg.get("peers", [])]}
    try:
        with open(PEER_TRAFFIC_FILE, "a") as f:
            f.write(json.dumps(row) + "\n")
        # prune to ~31 days
        lines = open(PEER_TRAFFIC_FILE).readlines()
        if len(lines) > 9000:
            with open(PEER_TRAFFIC_FILE, "w") as f:
                f.writelines(lines[-9000:])
    except OSError:
        pass


@app.route("/api/peers/traffic")
def api_peers_traffic():
    """Per-device bandwidth from 5-min counter deltas: total rx/tx per peer
    over the window + per-day series (for sparklines)."""
    days = int(request.args.get("days", 7))
    samples = []
    try:
        for line in open(PEER_TRAFFIC_FILE):
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if time.time() - d.get("t", 0) <= days * 86400:
                samples.append(d)
    except OSError:
        pass
    peers, prev = {}, {}
    for s in samples:  # chronological
        for p in s.get("peers", []):
            key = p.get("name") or "?"
            rx, tx = p.get("rx", 0) or 0, p.get("tx", 0) or 0
            pr = prev.get(key)
            if pr is not None:
                drx, dtx = rx - pr[0], tx - pr[1]
                if 0 <= drx < 2 ** 40 and 0 <= dtx < 2 ** 40:
                    e = peers.setdefault(key, {"name": key, "rx": 0, "tx": 0,
                                               "days": {}})
                    e["rx"] += drx
                    e["tx"] += dtx
                    day = datetime.fromtimestamp(s["t"], tz=timezone.utc) \
                        .strftime("%Y-%m-%d")
                    e["days"][day] = e["days"].get(day, 0) + drx + dtx
            prev[key] = (rx, tx)
    out = [{"name": k, "rx": e["rx"], "tx": e["tx"],
            "total": e["rx"] + e["tx"], "days": e["days"]}
           for k, e in peers.items()]
    out.sort(key=lambda x: x["total"], reverse=True)
    return jsonify({"days": days, "peers": out[:15],
                    "samples": len(samples)})


def _f2b_parse():
    """Parse bantime/findtime/maxretry from jail.local ([DEFAULT] + [sshd])."""
    vals = {"bantime": None, "findtime": None, "maxretry": None}
    section = None
    try:
        with open(F2B_JAIL) as f:
            for raw in f:
                line = raw.strip()
                if line.startswith("[") and line.endswith("]"):
                    section = line[1:-1].strip()
                    continue
                if section not in ("DEFAULT", "sshd"):
                    continue
                if "=" not in line or line.startswith("#"):
                    continue
                k, v = [x.strip() for x in line.split("=", 1)]
                if k in vals and v and vals[k] is None:
                    vals[k] = v
    except OSError:
        pass
    return vals


def _f2b_write(bantime, findtime, maxretry):
    """Rewrite the six keys (3 per section) in jail.local. Returns error str
    or None on success. Requires all 6 keys present (bantime/findtime/maxretry
    in both [DEFAULT] and [sshd]) — a layout drift fails loudly instead of
    silently producing a partial config."""
    try:
        with open(F2B_JAIL) as f:
            lines = f.readlines()
    except OSError as e:
        return f"cannot read {F2B_JAIL}: {e}"
    vals = {"bantime": str(bantime), "findtime": str(findtime),
            "maxretry": str(maxretry)}
    section = None
    found = {"bantime": 0, "findtime": 0, "maxretry": 0}
    out = []
    for raw in lines:
        line = raw.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            out.append(raw)
            continue
        if section in ("DEFAULT", "sshd") and "=" in line \
                and not line.startswith("#"):
            k = line.split("=", 1)[0].strip()
            if k in vals:
                out.append(f"{k} = {vals[k]}\n")
                found[k] += 1
                continue
        out.append(raw)
    if any(found[k] < 2 for k in vals):
        return (f"unexpected jail.local layout — found {found}, "
                "need bantime/findtime/maxretry in both [DEFAULT] and [sshd]")
    try:
        with open(F2B_JAIL, "w") as f:
            f.writelines(out)
    except OSError as e:
        return f"cannot write {F2B_JAIL}: {e}"
    return None


def _f2b_banned_ips():
    try:
        r = subprocess.run(["fail2ban-client", "status", "sshd"],
                           capture_output=True, text=True, timeout=8)
        for line in r.stdout.splitlines():
            if "Banned IP list:" in line:
                return [t for t in line.split(":", 1)[1].split()
                        if re.match(r"^\d+\.\d+\.\d+\.\d+$", t)]
    except Exception:
        pass
    return []


def _f2b_status():
    st = {"active": False, "banned_now": "n/a", "total_banned": "n/a"}
    try:
        r = subprocess.run(["fail2ban-client", "status", "sshd"],
                           capture_output=True, text=True, timeout=8)
        st["active"] = "Jail list" in r.stdout or "Status for the jail" in r.stdout
        for line in r.stdout.splitlines():
            if "Currently banned" in line:
                st["banned_now"] = line.split(":", 1)[1].strip()
            elif "Total banned" in line:
                st["total_banned"] = line.split(":", 1)[1].strip()
    except Exception:
        pass
    return st


@app.route("/api/fail2ban/unban", methods=["POST"])
def api_f2b_unban():
    """Unban a single IP from the sshd jail (quick-action + panel button)."""
    body = request.get_json(silent=True) or {}
    ip = (body.get("ip") or "").strip()
    parts = ip.split(".")
    if not (len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)):
        return jsonify({"error": "not a valid IPv4 address"}), 400
    r = subprocess.run(["fail2ban-client", "set", "sshd", "unbanip", ip],
                       capture_output=True, text=True, timeout=8)
    if r.returncode != 0:
        return jsonify({"error": f"fail2ban refused: "
                                 f"{(r.stderr or r.stdout).strip()[:200]}"}), 500
    # confirm it actually left the banned list
    if ip in _f2b_banned_ips():
        return jsonify({"error": "IP still in the banned list after unban — "
                                 "check the jail state"}), 500
    log_action("fail2ban", f"unbanned {ip} (manual)")
    return jsonify({"ok": True, "ip": ip, "status": _f2b_status()})


# ------------------------------------------------------ watchdog thresholds ---
WD_CONFIG_FILE = os.path.join(DATA_DIR, "watchdog-config.json")
WD_CONFIG_DEFAULTS = {
    "ram_pct_max": 90.0, "swap_pct_max": 50.0, "load_factor": 2.0,
    "disk_pct_warn": 85.0, "disk_pct_crit": 95.0,
}


def _wd_config_read():
    cfg = dict(WD_CONFIG_DEFAULTS)
    try:
        with open(WD_CONFIG_FILE) as f:
            cfg.update({k: float(v) for k, v in json.load(f).items()
                        if k in WD_CONFIG_DEFAULTS})
    except Exception:
        pass
    return cfg


@app.route("/api/watchdog/config")
def api_wd_config():
    return jsonify({"config": _wd_config_read(), "defaults": WD_CONFIG_DEFAULTS,
                    "file": "data/watchdog-config.json"})


@app.route("/api/watchdog/config", methods=["POST"])
def api_wd_config_save():
    body = request.get_json(silent=True) or {}
    cfg = {}
    bounds = {
        "ram_pct_max": (20.0, 99.0), "swap_pct_max": (5.0, 99.0),
        "load_factor": (0.5, 16.0), "disk_pct_warn": (40.0, 99.0),
        "disk_pct_crit": (50.0, 99.0),
    }
    for k, (lo, hi) in bounds.items():
        try:
            v = float(body.get(k))
        except (TypeError, ValueError):
            return jsonify({"error": f"{k} must be a number"}), 400
        if not lo <= v <= hi:
            return jsonify({"error": f"{k} must be {lo:g}–{hi:g}"}), 400
        cfg[k] = v
    if cfg["disk_pct_crit"] <= cfg["disk_pct_warn"]:
        return jsonify({"error": "critical disk % must be above the warning %"}), 400
    try:
        with open(WD_CONFIG_FILE, "w") as f:
            f.write(json.dumps(cfg, indent=2) + "\n")
    except OSError as e:
        return jsonify({"error": f"cannot write config: {e}"}), 500
    log_action("watchdog", "thresholds updated: " + " · ".join(
        f"{k} {v:g}" for k, v in cfg.items()))
    return jsonify({"ok": True, "config": cfg,
                    "note": "Takes effect on the next scheduled check (≤5 min)."})


@app.route("/api/fail2ban/config")
def api_f2b_config():
    v = _f2b_parse()
    live = {}
    for k in ("bantime", "findtime", "maxretry"):
        try:
            r = subprocess.run(["fail2ban-client", "get", "sshd", k],
                               capture_output=True, text=True, timeout=8)
            live[k] = r.stdout.strip()
        except Exception:
            live[k] = None
    return jsonify({"config": v, "live": live, "status": _f2b_status(),
                    "presets": F2B_PRESETS})


@app.route("/api/fail2ban/config", methods=["POST"])
def api_f2b_config_save():
    body = request.get_json(silent=True) or {}
    try:
        bantime = int(body.get("bantime"))
        findtime = int(body.get("findtime"))
        maxretry = int(body.get("maxretry"))
    except (TypeError, ValueError):
        return jsonify({"error": "bantime, findtime and maxretry must be numbers"}), 400
    if bantime != -1 and not 60 <= bantime <= 31536000:
        return jsonify({"error": "ban duration must be Permanent (-1) or 60–31536000 seconds"}), 400
    if not 60 <= findtime <= 604800:
        return jsonify({"error": "counting window must be 60–604800 seconds"}), 400
    if not 1 <= maxretry <= 20:
        return jsonify({"error": "failed attempts must be 1–20"}), 400

    old = _f2b_parse()
    err = _f2b_write(bantime, findtime, maxretry)
    if err:
        return jsonify({"error": err}), 500
    r = subprocess.run(["fail2ban-client", "reload"], capture_output=True,
                       text=True, timeout=30)
    if r.returncode != 0:
        return jsonify({"error": f"fail2ban reload failed: "
                                 f"{(r.stderr or r.stdout).strip()[:200]}"}), 500
    # verify what fail2ban actually applied
    live = {}
    for k, want in (("bantime", bantime), ("findtime", findtime),
                    ("maxretry", maxretry)):
        rr = subprocess.run(["fail2ban-client", "get", "sshd", k],
                            capture_output=True, text=True, timeout=8)
        got = rr.stdout.strip()
        try:
            live[k] = int(got)
        except ValueError:
            live[k] = got
        if live[k] != want:
            return jsonify({"error": f"verification failed: {k} requested {want} "
                                     f"but fail2ban reports {got} — config file "
                                     f"was still written"}), 500
    # if the ban duration changed, re-apply currently banned IPs so the new
    # duration takes effect on them too (old bans keep their original expiry)
    rebanned = 0
    if old.get("bantime") is not None and str(bantime) != str(old["bantime"]):
        for ip in _f2b_banned_ips():
            subprocess.run(["fail2ban-client", "set", "sshd", "unbanip", ip],
                           capture_output=True, text=True, timeout=8)
            rr = subprocess.run(["fail2ban-client", "set", "sshd", "banip", ip],
                                capture_output=True, text=True, timeout=8)
            if rr.returncode == 0:
                rebanned += 1
    log_action("fail2ban", f"settings: bantime {bantime}s · findtime "
                           f"{findtime}s · maxretry {maxretry}"
                           f"{f' · {rebanned} existing ban(s) re-applied' if rebanned else ''}")
    return jsonify({"ok": True, "verified": live, "rebanned": rebanned,
                    "status": _f2b_status()})


# ------------------------------------------------------------------- routes ---
@app.after_request
def no_cache(resp):
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    return resp


@app.route("/")
def index():
    with _cache_lock:
        snap = dict(CACHE)
    preload = json.dumps(snap if snap.get("ts") else None).replace("<", "\\u003c")
    return render_template("dashboard.html", preload=preload)


# ------------------------------------------------------------------- PWA ---
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
MANIFEST = {
    "name": "VPS Dashboard",
    "short_name": "VPS Dash",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#0b1220",
    "theme_color": "#0f172a",
    "icons": [
        {"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"},
        {"src": "/icon-512.png", "sizes": "512x512", "type": "image/png",
         "purpose": "any maskable"},
    ],
}


@app.route("/manifest.json")
def pwa_manifest():
    resp = app.make_response(json.dumps(MANIFEST))
    resp.headers["Content-Type"] = "application/manifest+json"
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp


@app.route("/sw.js")
def pwa_sw():
    try:
        body = open(os.path.join(STATIC_DIR, "sw.js")).read()
    except OSError:
        return jsonify({"error": "sw.js missing"}), 404
    resp = app.make_response(body)
    resp.headers["Content-Type"] = "application/javascript"
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp


@app.route("/icon-<int:size>.png")
def pwa_icon(size):
    try:
        body = open(os.path.join(STATIC_DIR, f"icon-{size}.png"), "rb").read()
    except OSError:
        return jsonify({"error": "icon missing"}), 404
    resp = app.make_response(body)
    resp.headers["Content-Type"] = "image/png"
    resp.headers["Cache-Control"] = "public, max-age=86400"
    return resp


@app.route("/api/stats")
def api_stats():
    with _cache_lock:
        snap = dict(CACHE)
    if not snap.get("ts") or request.args.get("refresh") == "1":
        snap = refresh(force_slow=True)
    return jsonify(snap)


# ------------------------------------------------- device / logging mgmt ----
import http.cookiejar
import urllib.request as _ur

WG_EASY_URL = os.environ.get("VPS_DASH_WGEASY_URL", "http://localhost:51821")
AGH_URL = os.environ.get("VPS_DASH_AGH_URL", "http://10.66.66.1:3000")
_wge_cookies = http.cookiejar.CookieJar()
_wge_cookie_lock = threading.Lock()
_agh_cookies = http.cookiejar.CookieJar()
_agh_cookie_lock = threading.Lock()


def _read_cred(path, key="password"):
    try:
        for line in open(path):
            if line.strip().lower().startswith(key):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return ""


def _wge_pw():
    return os.environ.get("VPS_DASH_WGEASY_PASSWORD") or \
        _read_cred(os.environ.get("VPS_DASH_WG_CREDS", "/root/wg-easy/.ui-creds.txt"))


def _wge_api(method, path, json_body=None, retry=True):
    with _wge_cookie_lock:
        import urllib.request
        if not _wge_cookies:
            data = json.dumps({"password": _wge_pw()}).encode()
            req = urllib.request.Request(f"{WG_EASY_URL}/api/session", data=data,
                                         headers={"Content-Type": "application/json"},
                                         method="POST")
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_wge_cookies))
            try:
                opener.open(req, timeout=8).read()
            except Exception:
                pass
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_wge_cookies))
        body = json.dumps(json_body).encode() if json_body is not None else None
        headers = {"Content-Type": "application/json"} if body else {}
        req = urllib.request.Request(f"{WG_EASY_URL}{path}", data=body,
                                     headers=headers, method=method)
        try:
            resp = opener.open(req, timeout=15)
            code, raw = resp.status, resp.read()
        except urllib.error.HTTPError as e:
            code, raw = e.code, e.read()
            if code == 401 and retry:
                _wge_cookies.clear()
                return _wge_api(method, path, json_body, retry=False)
        except Exception:
            return {"error": "wg-easy unreachable"}, 502
    try:
        return (json.loads(raw), code) if raw else (None, code)
    except Exception:
        return (raw.decode(errors="replace"), code)


def _agh_api(method, path, json_body=None, retry=True):
    with _agh_cookie_lock:
        import urllib.request
        if not _agh_cookies:
            name = os.environ.get("VPS_DASH_AGH_USER", "jay")
            pw = os.environ.get("VPS_DASH_AGH_PASSWORD") or \
                _read_cred("/opt/AdGuardHome/.admin-creds.txt")
            data = json.dumps({"name": name, "password": pw}).encode()
            req = urllib.request.Request(f"{AGH_URL}/control/login", data=data,
                                         headers={"Content-Type": "application/json"},
                                         method="POST")
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_agh_cookies))
            try:
                opener.open(req, timeout=8).read()
            except Exception:
                pass
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(_agh_cookies))
        body = json.dumps(json_body).encode() if json_body is not None else None
        headers = {"Content-Type": "application/json"} if body else {}
        req = urllib.request.Request(f"{AGH_URL}{path}", data=body,
                                     headers=headers, method=method)
        try:
            resp = opener.open(req, timeout=15)
            code, raw = resp.status, resp.read()
        except urllib.error.HTTPError as e:
            code, raw = e.code, e.read()
            if code == 401 and retry:
                _agh_cookies.clear()
                return _agh_api(method, path, json_body, retry=False)
        except Exception:
            return {"error": "AdGuard unreachable"}, 502
    try:
        return (json.loads(raw), code) if raw else (None, code)
    except Exception:
        return (raw.decode(errors="replace"), code)


def _wg_conf_stanzas():
    stanzas = {}
    try:
        cur = None
        for line in open(WG_CONF_FILE):
            s = line.strip()
            if s == "[Peer]":
                cur = {}
            elif s.startswith("[") and s.endswith("]"):
                cur = None
            elif cur is not None and "=" in s:
                k, v = s.split("=", 1)
                cur[k.strip().lower()] = v.strip()
            if cur is not None and "publickey" in cur and "allowedips" in cur \
                    and cur not in stanzas.values():
                stanzas[cur["publickey"]] = cur
    except Exception:
        pass
    return stanzas


@app.route("/api/devices")
def api_devices():
    data, code = _wge_api("GET", "/api/wireguard/client")
    if code != 200 or not isinstance(data, list):
        return jsonify({"devices": [], "error": "wg-easy API unavailable"})
    stanzas = _wg_conf_stanzas()
    devices = []
    for c in data:
        d = {
            "id": c.get("id"),
            "name": c.get("name"),
            "address": c.get("address"),
            "enabled": c.get("enabled"),
            "handshake": c.get("latestHandshakeAt"),
            "rx": c.get("transferRx", 0),
            "tx": c.get("transferTx", 0),
            "publicKey": c.get("publicKey", ""),
            "connected": False,
        }
        if d["handshake"]:
            try:
                age = time.time() - datetime.fromisoformat(
                    d["handshake"].replace("Z", "+00:00")).timestamp()
                d["connected"] = age < 180
            except Exception:
                pass
        if c.get("publicKey") in stanzas:
            d["resettable"] = True
        devices.append(d)
    return jsonify({"devices": devices})


@app.route("/api/devices", methods=["POST"])
def api_device_create():
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()[:40]
    if not name:
        return jsonify({"error": "name required"}), 400
    data, code = _wge_api("POST", "/api/wireguard/client", {"name": name})
    if code != 200 or not isinstance(data, dict) or not data.get("success"):
        return jsonify({"error": f"create failed ({code}): {data}"}), 500
    # wg-easy returns only {"success":true} — resolve the new client from the list
    clients, _ = _wge_api("GET", "/api/wireguard/client")
    newest = None
    for c in (clients if isinstance(clients, list) else []):
        if c.get("name") == name:
            if newest is None or c.get("createdAt", "") > newest.get("createdAt", ""):
                newest = c
    if not newest:
        return jsonify({"error": "created but not found in list"}), 500
    log_action("device", f"created '{name}'")
    return jsonify({"ok": True, "id": newest.get("id"),
                    "address": newest.get("address"), "name": name})


def _device_conf(client_id):
    data, code = _wge_api("GET", f"/api/wireguard/client/{client_id}/configuration")
    if code != 200 or not isinstance(data, str):
        return None
    conf = data
    if "MTU" not in conf:
        conf = conf.replace("[Interface]", "[Interface]", 1)
        # insert MTU after the Address line
        lines = conf.splitlines()
        out, added = [], False
        for ln in lines:
            out.append(ln)
            if not added and ln.strip().startswith("Address"):
                out.append("MTU = 1280")
                added = True
        conf = "\n".join(out)
    return conf


@app.route("/api/devices/<client_id>/config")
def api_device_config(client_id):
    conf = _device_conf(client_id)
    if not conf:
        return jsonify({"error": "config fetch failed"}), 404
    return jsonify({"conf": conf})


@app.route("/api/devices/<client_id>/config/download")
def api_device_config_download(client_id):
    conf = _device_conf(client_id)
    if not conf:
        return jsonify({"error": "config fetch failed"}), 404
    name = "device"
    for c in (api_devices().get_json().get("devices") or []):
        if c["id"] == client_id:
            name = c["name"]
            break
    from flask import Response
    return Response(conf, mimetype="text/plain",
                    headers={"Content-Disposition":
                             f"attachment; filename={name}.conf"})


@app.route("/api/devices/<client_id>/qrcode")
def api_device_qrcode(client_id):
    data, code = _wge_api("GET", f"/api/wireguard/client/{client_id}/qrcode.svg")
    if code != 200 or not isinstance(data, str) or "<svg" not in data:
        return jsonify({"error": "qrcode fetch failed"}), 502
    from flask import Response
    return Response(data, mimetype="image/svg+xml")


@app.route("/api/devices/<client_id>/qrcode.png")
def api_device_qrcode_png(client_id):
    """QR as PNG — shareable to other devices (scan from gallery/AirDrop)."""
    conf = _device_conf(client_id)
    if not conf:
        return jsonify({"error": "config fetch failed"}), 404
    png = f"/tmp/qr-{client_id[:8]}.png"
    r = subprocess.run(["qrencode", "-o", png, "-t", "PNG", "-s", "12",
                        "-m", "2"], input=conf, capture_output=True, text=True,
                       timeout=15)
    if r.returncode != 0 or not os.path.exists(png):
        return jsonify({"error": "qrencode failed"}), 500
    from flask import send_file
    return send_file(png, mimetype="image/png", as_attachment=True,
                     download_name=f"vpn-{client_id[:8]}.png")


@app.route("/api/devices/<client_id>/toggle", methods=["POST"])
def api_device_toggle(client_id):
    body = request.get_json(silent=True) or {}
    enable = bool(body.get("enable"))
    action = "enable" if enable else "disable"
    data, code = _wge_api("POST", f"/api/wireguard/client/{client_id}/{action}")
    if code in (200, 201):
        log_action("device", f"{action}d '{_client_name(client_id)}'")
    return jsonify({"ok": code in (200, 201), "code": code})


@app.route("/api/devices/<client_id>/reset", methods=["POST"])
def api_device_reset(client_id):
    """Reset a device's transfer counters via syncconf remove/re-add.

    This host's wg build rejects `preshared-key` literals ("fopen" bug), so
    we reuse wg-easy's own mechanism: wg-quick strip + wg syncconf.
    """
    data, _ = _wge_api("GET", "/api/wireguard/client")
    pub = None
    for c in (data if isinstance(data, list) else []):
        if c.get("id") == client_id:
            pub = c.get("publicKey")
            break
    if not pub:
        return jsonify({"error": "device not found"}), 404
    tmp_full = "/tmp/wg-reset-full.conf"
    tmp_no = "/tmp/wg-reset-partial.conf"
    r = subprocess.run(["wg-quick", "strip", WG_CONF_FILE],
                       capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        return jsonify({"error": "wg-quick strip failed"}), 500
    full = r.stdout
    with open(tmp_full, "w") as f:
        f.write(full)
    # split into blocks ([Interface], [Peer] xN) and drop the target peer
    blocks, cur = [], []
    for ln in full.splitlines():
        s = ln.strip()
        if (s.startswith("[") and s.endswith("]")) and cur:
            blocks.append(cur)
            cur = []
        cur.append(ln)
    if cur:
        blocks.append(cur)
    keep = []
    for b in blocks:
        if b and b[0].strip() == "[Peer]" and \
                any("PublicKey" in l and pub in l for l in b):
            continue
        keep.append(b)
    partial = "\n".join("\n".join(b) for b in keep) + "\n"
    with open(tmp_no, "w") as f:
        f.write(partial)
    # 1) remove the peer (its counters vanish with it)
    r1 = subprocess.run(["wg", "syncconf", "wg0", tmp_no],
                        capture_output=True, text=True, timeout=15)
    # 2) restore the full config (peer re-added with zero counters)
    r2 = subprocess.run(["wg", "syncconf", "wg0", tmp_full],
                        capture_output=True, text=True, timeout=15)
    ok = r1.returncode == 0 and r2.returncode == 0
    if ok:
        log_action("device", f"reset counters '{_client_name(client_id)}'")
    return jsonify({"ok": ok,
                    "err": (r1.stderr + r2.stderr).strip()[:200] if not ok else ""})


@app.route("/api/devices/<client_id>", methods=["DELETE"])
def api_device_delete(client_id):
    data, code = _wge_api("DELETE", f"/api/wireguard/client/{client_id}")
    if code in (200, 204):
        log_action("device", f"deleted '{_client_name(client_id)}'")
        return jsonify({"ok": True})
    # wg-easy quirk: delete needs the wg0.json map key, not the API list id
    try:
        cfg = json.load(open(WG_EASY_CONFIG))
        for k, c in cfg.get("clients", {}).items():
            if c.get("id") == client_id:
                data, code = _wge_api("DELETE", f"/api/wireguard/client/{k}")
                if code in (200, 204):
                    log_action("device", f"deleted '{_client_name(client_id)}'")
                return jsonify({"ok": code in (200, 204)})
    except Exception:
        pass
    return jsonify({"error": "delete failed", "code": code}), 500


# ---------------------------------------------------- maintenance routes ---
@app.route("/api/reboot", methods=["POST"])
def api_reboot():
    with _reboot_lock:
        if _reboot_pending:
            return jsonify({"error": "Reboot already scheduled — it's on the way.",
                            "status": "pending"}), 409
        st = _load_reboot_state()
        wait = st.get("last_request", 0) + REBOOT_COOLDOWN_S - time.time()
        if wait > 0:
            return jsonify({"error": "cooldown", "status": "cooldown",
                            "wait": int(wait) + 1}), 429
        _schedule_reboot("dashboard button")
    log_action("reboot", "reboot scheduled (dashboard button)")
    return jsonify({"status": "rebooting", "delay_s": 5})


# ---------------------------------------------------------------- speedtest ---
_st_lock = threading.Lock()
_st_running = False
_st_result = None
_st_progress = {}
_st_started = 0.0
_st_last_finish = 0.0
_ST_COOLDOWN_S = 30


def speedtest_running():
    return _st_running


def _parse_progress(line, prog):
    """Parse an Ookla CLI progress line (from a PTY session) live.

    The CLI only emits progress when its stderr is a TTY, so the app runs it
    under `script -qec` and parses the merged session stream. Typical lines:
        Idle Latency:     0.92 ms   (jitter: 0.25ms, low: 0.73ms, high: 1.21ms)
        Download:   564.48 Mbps [=- ]  5%   - latency: 16.90 ms
        Upload:   595.25 Mbps (data used: 670.1 MB)
        Packet Loss:     0.0%
        Result URL: https://www.speedtest.net/result/c/...
    """
    s = line.strip()
    low = s.lower()
    if "idle latency:" in low:
        m = re.search(r"idle latency:\s*([\d.]+)\s*ms", low)
        if m:
            prog["ping"] = float(m.group(1))
        m = re.search(r"jitter:\s*([\d.]+)\s*ms", low)
        if m:
            prog["jitter"] = float(m.group(1))
        prog["stage"] = "Latency"
    elif low.startswith("latency"):
        m = re.search(r"latency:\s*([\d.]+)\s*ms", low)
        if m:
            prog["ping"] = float(m.group(1))
        m = re.search(r"jitter:\s*([\d.]+)\s*ms", low)
        if m:
            prog["jitter"] = float(m.group(1))
        prog["stage"] = "Latency"
    elif low.startswith("download"):
        m = re.search(r"download:\s*([\d.]+)\s*(mbit/s|mbps)", low)
        if m:
            prog["down"] = float(m.group(1))
        m = re.search(r"\]\s*(\d+)%", s)
        if m:
            prog["pct"] = int(m.group(1))
        prog["stage"] = "Download"
    elif low.startswith("upload"):
        m = re.search(r"upload:\s*([\d.]+)\s*(mbit/s|mbps)", low)
        if m:
            prog["up"] = float(m.group(1))
        m = re.search(r"\]\s*(\d+)%", s)
        if m:
            prog["pct"] = int(m.group(1))
        prog["stage"] = "Upload"
    elif low.startswith("server:"):
        m = re.search(r"Server:\s*(.+?)\s*\(id:", s)
        if m:
            prog["server"] = m.group(1).strip()
    elif "hosted by" in low:
        m = re.search(r"hosted by (.+?):\s*([\d.]+)\s*ms", low)
        if m:
            prog["server"] = m.group(1).strip()
            prog["ping"] = float(m.group(2))
        prog["stage"] = "Testing"
    elif low.startswith("packet loss"):
        m = re.search(r"packet loss:\s*([\d.]+)%", low)
        if m:
            prog["loss"] = float(m.group(1))
    elif low.startswith("result url"):
        m = re.search(r"result url:\s*(\S+)", low)
        if m:
            prog["url"] = m.group(1)
    elif "error" in low:
        prog["error"] = s
    elif "retrieving speedtest.net configuration" in low:
        prog["stage"] = "Retrieving config"
    elif "testing from" in low:
        prog["stage"] = "Connecting"
    elif "retrieving speedtest.net server list" in low:
        prog["stage"] = "Fetching servers"
    elif "selecting best server" in low:
        prog["stage"] = "Selecting server"


def _run_speedtest():
    """Crash-proof wrapper: the running flag must NEVER stay stuck."""
    global _st_running, _st_result, _st_last_finish
    try:
        _run_speedtest_inner()
    except Exception as e:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        _st_result = {"ts": ts, "error": f"speedtest crashed: {str(e)[:150]}"}
        _st_running = False
        _st_last_finish = time.time()
        try:
            refresh(force_slow=True)
        except Exception:
            pass


def _run_speedtest_inner():
    global _st_running, _st_result, _st_last_finish
    os.environ.setdefault("HOME", "/root")  # Ookla binary crashes without HOME
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    prog = _st_progress  # mutate the live dict the status endpoint reads
    # The CLI silences progress when stderr is not a TTY (systemd pipes), so
    # run it under a pseudo-terminal via `script` and parse the session feed.
    try:
        p = subprocess.Popen(
            ["script", "-qec",
             f"{SPEEDTEST_BIN} --accept-license --accept-gdpr --progress=yes",
             "/dev/null"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            errors="replace")
    except Exception as e:
        _st_result = {"ts": ts,
                      "error": f"failed to start speedtest: {str(e)[:120]}"}
        _st_running = False
        _st_last_finish = time.time()
        return

    def read_progress():
        try:
            for line in p.stdout:
                try:
                    _parse_progress(line, prog)
                except Exception:
                    pass
        except Exception:
            pass
        if not prog.get("stage") or prog["stage"] == "Starting":
            prog["stage"] = "Running"
    reader = threading.Thread(target=read_progress, daemon=True)
    reader.start()

    def progress_watchdog():
        # if the CLI emits no progress lines, at least surface a generic
        # stage so the UI isn't stuck on "Starting"
        time.sleep(8)
        if not prog.get("stage") or prog["stage"] == "Starting":
            prog["stage"] = "Running"
    threading.Thread(target=progress_watchdog, daemon=True).start()

    try:
        p.wait(timeout=150)
    except subprocess.TimeoutExpired:
        p.kill()
        try:
            p.wait(timeout=5)
        except Exception:
            pass
    reader.join(timeout=3)

    if p.returncode != 0 and not prog.get("error"):
        result = {"ts": ts, "error": f"speedtest exited {p.returncode}"}
    elif prog.get("error"):
        result = {"ts": ts, "error": prog["error"][:150]}
    elif prog.get("down") is not None and prog.get("up") is not None:
        result = {
            "ts": ts,
            "ping": round(prog["ping"], 2) if prog.get("ping") is not None else None,
            "jitter": round(prog["jitter"], 2) if prog.get("jitter") is not None else None,
            "down_mbps": round(prog["down"], 2),
            "up_mbps": round(prog["up"], 2),
            "server": prog.get("server") or "unknown",
        }
        if prog.get("loss") is not None:
            result["loss"] = prog["loss"]
        if prog.get("url"):
            result["url"] = prog["url"]
    else:
        result = {"ts": ts, "error": "speedtest produced no usable output"}
    result["elapsed"] = max(1, int(time.time() - _st_started))
    _st_result = result
    history = load_history()
    history.append(result)
    history = history[-50:]
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f)
    _st_running = False
    _st_last_finish = time.time()
    try:
        refresh(force_slow=True)  # snapshot picks up the new result
    except Exception:
        pass


def load_history():
    try:
        with open(HISTORY_FILE) as f:
            return json.load(f)
    except Exception:
        return []


@app.route("/api/speedtest", methods=["POST"])
def api_speedtest_start():
    global _st_running, _st_started
    with _st_lock:
        if _st_running:
            return jsonify({"status": "already_running"}), 409
        wait = _st_last_finish + _ST_COOLDOWN_S - time.time()
        if wait > 0:
            return jsonify({"status": "cooldown", "error": "cooldown",
                            "wait": int(wait) + 1}), 429
        _st_running = True
        _st_result = None
        _st_progress.update(stage="Starting", down=None, up=None, ping=None,
                            jitter=None, server="", pct=None, loss=None,
                            url="", error="")
        _st_started = time.time()
    threading.Thread(target=_run_speedtest, daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/api/speedtest/status")
def api_speedtest_status():
    return jsonify({
        "running": _st_running,
        "started": int(_st_started) if _st_running else 0,
        "progress": dict(_st_progress),
        "result": _st_result,
        "cooldown_until": int(_st_last_finish + _ST_COOLDOWN_S),
    })


@app.route("/api/speedtest/history")
def api_speedtest_history():
    hist = [h for h in load_history() if "error" not in h]
    if hist:
        avg = {
            "ping": round(sum(h["ping"] for h in hist) / len(hist), 2),
            "down": round(sum(h["down_mbps"] for h in hist) / len(hist), 2),
            "up": round(sum(h["up_mbps"] for h in hist) / len(hist), 2),
            "runs": len(hist),
        }
    else:
        avg = None
    return jsonify({"history": load_history()[-20:], "avg": avg})


if __name__ == "__main__":
    threading.Thread(target=sampler_loop, daemon=True).start()
    app.run(host=BIND_HOST, port=BIND_PORT, threaded=True)
