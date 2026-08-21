#!/usr/bin/env python3
"""Mint a new WireGuard client profile + QR via the wg-easy API.

Usage:
    add-wg-profile.py "My-Phone" [--allowed-ips 0.0.0.0/0] [--outdir /root/wg-easy/profiles]

Env overrides (defaults match the self-hosted-vpn-playbook deployment):
    WG_EASY_URL       http://localhost:51821
    WG_EASY_PASSWORD  (if unset, read from CREDS_FILE)
    CREDS_FILE        /root/wg-easy/.ui-creds.txt  (line: "Password: <pw>")
    WG_EASY_CONFIG    /root/wg-easy/config/wg0.json  (client keys live here)
    WG_SUBNET_MASK    24
    WG_DNS            10.66.66.1

Output: <outdir>/<name>.conf, <outdir>/<name>.png (QR), and a MEDIA: line
suitable for chat delivery. Requires qrencode for the QR.
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.request
import urllib.parse

API = os.environ.get("WG_EASY_URL", "http://localhost:51821")
CREDS_FILE = os.environ.get("CREDS_FILE", "/root/wg-easy/.ui-creds.txt")
CONFIG_JSON = os.environ.get("WG_EASY_CONFIG", "/root/wg-easy/config/wg0.json")
DNS = os.environ.get("WG_DNS", "10.66.66.1")
MASK = os.environ.get("WG_SUBNET_MASK", "24")


def http(method, path, body=None, cookie=None):
    req = urllib.request.Request(
        API.rstrip("/") + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json",
                 "User-Agent": "wg-profile-generator/1.0"},
    )
    if cookie:
        req.add_header("Cookie", cookie)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read()
            return r.status, r.headers, raw
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def get_password():
    pw = os.environ.get("WG_EASY_PASSWORD")
    if pw:
        return pw
    if os.path.exists(CREDS_FILE):
        for line in open(CREDS_FILE):
            if line.strip().startswith("Password:"):
                return line.split(":", 1)[1].strip()
    sys.exit("No password: set WG_EASY_PASSWORD or create " + CREDS_FILE)


def get_cookie():
    pw = get_password()
    status, headers, _ = http("POST", "/api/session", body={"password": pw})
    if status != 200:
        sys.exit(f"wg-easy login failed (HTTP {status})")
    return headers.get("Set-Cookie", "").split(";")[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("--allowed-ips", default=os.environ.get("WG_ALLOWED_IPS", "0.0.0.0/0"))
    ap.add_argument("--outdir", default=os.environ.get("OUT_DIR", "/root/wg-easy/profiles"))
    ap.add_argument("--keepalive", default=os.environ.get("WG_PERSISTENT_KEEPALIVE", "25"))
    ap.add_argument("--endpoint", default=os.environ.get("WG_HOST"))
    args = ap.parse_args()

    cookie = get_cookie()

    status, _, raw = http("POST", "/api/wireguard/client",
                          body={"name": args.name}, cookie=cookie)
    if status != 200:
        sys.exit(f"client create failed (HTTP {status}): {raw.decode()[:300]}")

    # wg-easy persists client keys in the mounted config volume. The API
    # list `id` differs from the wg0.json map key — the key is what the
    # configuration endpoint resolves by.
    cfg = json.load(open(CONFIG_JSON))
    clients = cfg.get("clients", {})
    key, client = next(((k, c) for k, c in clients.items() if c.get("name") == args.name),
                       (None, None))
    if not client:
        sys.exit("client created but not found in " + CONFIG_JSON)

    # Preferred: wg-easy's own configuration endpoint (returns the full,
    # authoritative config incl. private key, DNS, endpoint, keepalive).
    status, _, raw = http("GET",
                          f"/api/wireguard/client/{key}/configuration",
                          cookie=cookie)
    if status == 200 and b"[Interface]" in raw:
        conf = raw.decode()
    else:
        # Fallback: assemble manually (older wg-easy without the endpoint).
        srv_pub = (cfg.get("server") or {}).get("publicKey")
        if not srv_pub:
            r = subprocess.run(["wg", "show", "wg0"], capture_output=True, text=True)
            for line in r.stdout.splitlines():
                if "public key:" in line:
                    srv_pub = line.split("public key: ")[1].strip()
                    break
        if not srv_pub:
            sys.exit("could not find server public key")
        endpoint = args.endpoint or os.environ.get("WG_HOST")
        if not endpoint:
            endpoint = "<VPS_PUBLIC_IP>"  # placeholder; user must fill
        conf = (
            "[Interface]\n"
            f"PrivateKey = {client['privateKey']}\n"
            f"Address = {client['address']}/{MASK}\n"
            f"DNS = {DNS}\n\n"
            "[Peer]\n"
            f"PublicKey = {srv_pub}\n"
            f"PresharedKey = {client['preSharedKey']}\n"
            f"Endpoint = {endpoint}:{os.environ.get('WG_PORT', '51820')}\n"
            f"AllowedIPs = {args.allowed_ips}\n"
            f"PersistentKeepalive = {args.keepalive}\n"
        )

    addr = ""
    for line in conf.splitlines():
        if line.startswith("Address"):
            addr = line.split("=", 1)[1].strip()
            break

    os.makedirs(args.outdir, exist_ok=True)
    safe = "".join(c if c.isalnum() or c in " -_" else "_" for c in args.name)
    conf_path = os.path.join(args.outdir, safe + ".conf")
    qr_path = os.path.join(args.outdir, safe + ".png")
    with open(conf_path, "w") as f:
        f.write(conf)
    os.chmod(conf_path, 0o600)
    r = subprocess.run(["qrencode", "-t", "PNG", "-o", qr_path, "-s", "10", "-m", "4"],
                       input=conf.encode(), capture_output=True)
    if r.returncode != 0:
        sys.exit("qrencode failed: " + r.stderr.decode())

    print(f"Profile created: {args.name}")
    print(f"Address: {addr or 'unknown'}")
    print(f"ClientId (config key): {key}")
    print(f"Conf: {conf_path}")
    print(f"QR:   {qr_path}")
    print(f"MEDIA:{qr_path}")


if __name__ == "__main__":
    main()
