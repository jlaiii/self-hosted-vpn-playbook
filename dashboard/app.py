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
import subprocess
import threading
import time
from datetime import datetime, timezone

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


def _slow_data():
    return {
        "containers": docker_containers(),
        "units": key_units(),
        "wg": wg_peers(),
        "f2b": f2b_bans(),
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


@app.route("/api/stats")
def api_stats():
    with _cache_lock:
        snap = dict(CACHE)
    if not snap.get("ts") or request.args.get("refresh") == "1":
        snap = refresh(force_slow=True)
    return jsonify(snap)


# ----------------------------------------------------------------- speedtest ---
_st_lock = threading.Lock()
_st_running = False
_st_result = None


def speedtest_running():
    return _st_running


def _run_speedtest():
    global _st_running, _st_result
    os.environ.setdefault("HOME", "/root")  # Ookla binary crashes without HOME
    try:
        r = subprocess.run(
            [SPEEDTEST_BIN, "--format=json", "--accept-license", "--accept-gdpr"],
            capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise RuntimeError(f"speedtest exited {r.returncode}: {(r.stderr or '')[:150]}")
        d = json.loads(r.stdout)
        result = {
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "ping": round(d["ping"]["latency"], 2),
            "jitter": round(d["ping"]["jitter"], 2),
            "down_mbps": round(d["download"]["bandwidth"] * 8 / 1e6, 2),
            "up_mbps": round(d["upload"]["bandwidth"] * 8 / 1e6, 2),
            "server": f"{d['server']['name']} ({d['server']['location']})",
        }
    except Exception as e:
        result = {"ts": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                  "error": str(e)[:200]}
    _st_result = result
    history = load_history()
    history.append(result)
    history = history[-50:]
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f)
    _st_running = False
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
    global _st_running
    with _st_lock:
        if _st_running:
            return jsonify({"status": "already_running"}), 409
        _st_running = True
        _st_result = None
    threading.Thread(target=_run_speedtest, daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/api/speedtest/status")
def api_speedtest_status():
    return jsonify({"running": _st_running, "result": _st_result})


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
