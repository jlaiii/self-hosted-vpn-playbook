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
        _read_cred("/root/wg-easy/.ui-creds.txt")


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
        for line in open("/root/wg-easy/config/wg0.conf"):
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
    r = subprocess.run(["wg-quick", "strip", "/root/wg-easy/config/wg0.conf"],
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
    return jsonify({"ok": ok,
                    "err": (r1.stderr + r2.stderr).strip()[:200] if not ok else ""})


@app.route("/api/devices/<client_id>", methods=["DELETE"])
def api_device_delete(client_id):
    data, code = _wge_api("DELETE", f"/api/wireguard/client/{client_id}")
    if code in (200, 204):
        return jsonify({"ok": True})
    # wg-easy quirk: delete needs the wg0.json map key, not the API list id
    try:
        cfg = json.load(open(WG_EASY_CONFIG))
        for k, c in cfg.get("clients", {}).items():
            if c.get("id") == client_id:
                data, code = _wge_api("DELETE", f"/api/wireguard/client/{k}")
                return jsonify({"ok": code in (200, 204)})
    except Exception:
        pass
    return jsonify({"error": "delete failed", "code": code}), 500


def _log_state():
    p = os.path.join(DATA_DIR, "log-state.json")
    try:
        with open(p) as f:
            return json.load(f)
    except Exception:
        return {"agh_querylog_enabled": True}


def _set_log_state(d):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(os.path.join(DATA_DIR, "log-state.json"), "w") as f:
            json.dump(d, f)
    except Exception:
        pass


_QL_CACHE = {"mtime": 0, "rows": []}


def _ql_rows():
    """All querylog entries (newest first), parsed from the JSONL file.

    Cached in memory, invalidated by file mtime (the file is appended to).
    """
    path = os.environ.get("VPS_DASH_AGH_QLOG",
                          "/opt/AdGuardHome/data/querylog.json")
    try:
        mtime = os.path.getmtime(path)
    except Exception:
        return []
    if _QL_CACHE["mtime"] == mtime and _QL_CACHE["rows"]:
        return _QL_CACHE["rows"]
    rows = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                q = e.get("QH") or ""
                if not q:
                    continue
                res = e.get("Result") or {}
                blocked = bool(res.get("IsFiltered")) or \
                    "0.0.0.0" in str(e.get("Answer") or "")
                rows.append({"t": e.get("T", ""), "ip": e.get("IP", ""),
                             "name": q, "type": e.get("QT", ""),
                             "blocked": blocked})
    except Exception:
        pass
    rows.sort(key=lambda r: r["t"], reverse=True)
    _QL_CACHE["mtime"] = mtime
    _QL_CACHE["rows"] = rows
    return rows


def _ql_total(ip):
    """Total logged DNS queries for a client IP (from the querylog JSONL)."""
    try:
        path = os.environ.get("VPS_DASH_AGH_QLOG",
                              "/opt/AdGuardHome/data/querylog.json")
        r = subprocess.run(["grep", "-c", f'"IP":"{ip}"', path],
                           capture_output=True, text=True, timeout=20)
        return int(r.stdout.strip() or 0)
    except Exception:
        return 0


@app.route("/api/logs")
def api_logs():
    ql_enabled = _log_state().get("agh_querylog_enabled", True)
    devices, _ = _wge_api("GET", "/api/wireguard/client")
    dev_out = []
    if isinstance(devices, list):
        for c in devices:
            ip = c.get("address")
            q = {"recent": [], "count": 0, "total": 0}
            if ip:
                q["total"] = _ql_total(ip)
                qd, _ = _agh_api("GET", f"/control/querylog?search={ip}&limit=20")
                if isinstance(qd, dict) and isinstance(qd.get("data"), list):
                    q["recent"] = [{
                        "time": e.get("time", ""),
                        "name": (e.get("question") or {}).get("name", "?"),
                        "type": (e.get("question") or {}).get("type", ""),
                        "answer": (e.get("answer") or [{}])[0].get("value", ""),
                        "blocked": any("0.0.0.0" in str(a.get("value", "")) or
                                       e.get("reason") == "FilteredBlackList"
                                       for a in e.get("answer", [])),
                    } for e in qd["data"]]
                    q["count"] = len(qd["data"])
            dev_out.append({
                "name": c.get("name"), "address": ip,
                "queries": q,
                "rx": c.get("transferRx", 0), "tx": c.get("transferTx", 0),
                "handshake": c.get("latestHandshakeAt"),
            })
    return jsonify({"agh_querylog_enabled": ql_enabled, "devices": dev_out})


def _set_yaml_querylog(enabled):
    """Explicitly set querylog.enabled in AGH's yaml (source of truth at
    startup) — removes the API-persist vs restart race."""
    path = "/opt/AdGuardHome/AdGuardHome.yaml"
    try:
        lines = open(path).read().splitlines()
        in_ql = False
        out = []
        for ln in lines:
            s = ln.strip()
            if s.startswith("querylog:"):
                in_ql = True
                out.append(ln)
                continue
            if in_ql and s and not (ln.startswith(" ") or ln.startswith("\t")):
                in_ql = False
            if in_ql and s.startswith("enabled:"):
                ln = ln.split(":")[0] + ": " + ("true" if enabled else "false")
            out.append(ln)
        open(path, "w").write("\n".join(out) + "\n")
    except Exception:
        pass


@app.route("/api/logs/agh_toggle", methods=["POST"])
def api_logs_agh_toggle():
    body = request.get_json(silent=True) or {}
    enabled = bool(body.get("enabled"))
    # this AGH build: interval is in DAYS (90 max-ish); endpoint is POST-only
    _agh_api("POST", "/control/querylog_config",
             {"enabled": enabled, "interval": 90, "anonymize_client_ip": False})
    _set_yaml_querylog(enabled)
    if not enabled:
        # turning logging OFF = also DELETE everything already saved:
        # in-memory log (API), on-disk log file (must be REMOVED — a
        # truncated-but-present file breaks AGH's file writer init), cache
        _agh_api("POST", "/control/querylog_clear")
        try:
            path = os.environ.get("VPS_DASH_AGH_QLOG",
                                  "/opt/AdGuardHome/data/querylog.json")
            os.remove(path)
        except Exception:
            pass
        _QL_CACHE["mtime"] = 0
        _QL_CACHE["rows"] = []
    # AGH only (re)initializes its file writer when query logging is enabled
    # at startup — restart in both directions. ~5s DNS pause.
    try:
        time.sleep(1)  # let AGH settle after the config POST
        subprocess.run(["systemctl", "restart", "adguardhome"],
                       capture_output=True, timeout=20)
    except Exception:
        pass
    _set_log_state({"agh_querylog_enabled": enabled})
    return jsonify({"ok": True, "enabled": enabled})


@app.route("/api/logs/docker")
def api_logs_docker():
    lines = min(int(request.args.get("lines", 100)), 500)
    r = subprocess.run(["docker", "logs", "--tail", str(lines), "wg-easy"],
                       capture_output=True, text=True, timeout=15)
    return jsonify({"log": r.stdout[-20000:] + r.stderr[-2000:]})


@app.route("/api/logs/top")
def api_logs_top():
    """Top domains (with blocked counts) per device or overall."""
    ip = request.args.get("device", "")
    limit = min(int(request.args.get("limit", 90)), 200)
    counts = {}
    for r in _ql_rows():
        if ip and r["ip"] != ip:
            continue
        d = counts.setdefault(r["name"], {"count": 0, "blocked": 0})
        d["count"] += 1
        if r["blocked"]:
            d["blocked"] += 1
    top = sorted(counts.items(), key=lambda kv: -kv[1]["count"])[:limit]
    return jsonify({"top": [{"name": k, **v} for k, v in top],
                    "total_domains": len(counts)})


@app.route("/api/logs/full")
def api_logs_full():
    """Paginated full query log (everything, oldest history included)."""
    ip = request.args.get("device", "")
    page = max(int(request.args.get("page", 1)), 1)
    limit = min(int(request.args.get("limit", 100)), 500)
    rows = [r for r in _ql_rows() if (not ip or r["ip"] == ip)]
    total = len(rows)
    start = (page - 1) * limit
    pages = max(1, (total + limit - 1) // limit)
    if page > pages:
        page = pages
        start = (page - 1) * limit
    return jsonify({"rows": rows[start:start + limit], "total": total,
                    "page": page, "pages": pages, "limit": limit})


@app.route("/api/logs/export")
def api_logs_export():
    """Download the complete query log (optionally per device) as CSV."""
    import csv
    import io
    ip = request.args.get("device", "")
    rows = [r for r in _ql_rows() if (not ip or r["ip"] == ip)]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["time", "device_ip", "domain", "type", "blocked"])
    for r in rows[:200000]:
        w.writerow([r["t"], r["ip"], r["name"], r["type"],
                    "yes" if r["blocked"] else ""])
    from flask import Response
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition":
                             "attachment; filename=vpn-querylog.csv"})


@app.route("/api/logs/clear", methods=["POST"])
def api_logs_clear():
    body = request.get_json(silent=True) or {}
    scope = body.get("scope", "all")
    result = {"agh": False, "docker": False}
    if scope in ("agh", "all"):
        r, code = _agh_api("POST", "/control/querylog_clear")
        result["agh"] = code in (200, 204) or r is None
    if scope in ("docker", "all"):
        try:
            path = subprocess.run(
                ["docker", "inspect", "-f", "{{.LogPath}}", "wg-easy"],
                capture_output=True, text=True, timeout=10).stdout.strip()
            if path:
                with open(path, "w") as f:
                    f.truncate(0)
                result["docker"] = True
        except Exception:
            pass
    return jsonify({"ok": True, "result": result})


# ---------------------------------------------------------------- speedtest ---
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
