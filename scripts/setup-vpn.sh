#!/usr/bin/env bash
# setup-vpn.sh — one-command self-hosted VPN stack installer.
#
# Builds on a fresh Ubuntu/Debian VPS:
#   - wg-easy (WireGuard tunnel + self-service device dashboard)
#   - firewall/NAT/MSS-clamp rules (systemd-persisted)
#   - stats dashboard (Flask, tunnel-only)
#   - vpn-health-check.py watchdog (11 checks) + cron entry
#   - optional: AdGuard Home DNS ad-blocking (--with-adguard)
#   - optional: Ookla CLI for the speed-test tab (--with-speedtest)
#
# Usage:
#   sudo VPS_IP=203.0.113.10 UI_PASSWORD='StrongPass!' \
#     bash setup-vpn.sh [--with-adguard] [--with-speedtest]
#
# Env overrides: VPS_IP (REQUIRED) UI_PASSWORD (REQUIRED)
#   WG_SUBNET=10.66.66.0/24  DNS_IP=<subnet .1>  WG_PORT=51820
#   UI_PORT=51821  DASH_PORT=8088  MSS_VALUE=1240
#   INSTALL_DIR=/opt/vpn-stack  ADGUARD_SKIP=1  SPEEDTEST_SKIP=1
#
# After it finishes, devices connect via the wg-easy UI at
# http://<DNS_IP>:<UI_PORT> (reachable only through the tunnel).
set -euo pipefail

VPS_IP="${VPS_IP:-}"
UI_PASSWORD="${UI_PASSWORD:-}"
[ -n "$VPS_IP" ] || { echo "FATAL: VPS_IP is required"; exit 1; }
[ -n "$UI_PASSWORD" ] || { echo "FATAL: UI_PASSWORD is required"; exit 1; }

SUBNET_BASE="${WG_SUBNET:-10.66.66.0/24}"; SUBNET_BASE="${SUBNET_BASE%.*}"
DNS_IP="${DNS_IP:-$SUBNET_BASE.1}"
WG_PORT="${WG_PORT:-51820}"; UI_PORT="${UI_PORT:-51821}"; DASH_PORT="${DASH_PORT:-8088}"
MSS_VALUE="${MSS_VALUE:-1240}"
INSTALL_DIR="${INSTALL_DIR:-/opt/vpn-stack}"
NET_IF="$(ip route get 8.8.8.8 | awk '{print $5; exit}')"

log() { echo "[setup] $*"; }
need() { command -v "$1" >/dev/null || apt-get install -y -qq "$2" >/dev/null; }

[ "$(id -u)" -eq 0 ] || { echo "FATAL: run as root"; exit 1; }
export DEBIAN_FRONTEND=noninteractive

# ------------------------------------------------------------------ base deps
log "installing base packages"
apt-get update -qq
need docker docker.io; systemctl enable --now docker >/dev/null 2>&1 || true
need python3 python3
apt-get install -y -qq wireguard-tools qrencode tcpdump dnsutils curl apache2-utils \
    python3-flask python3-psutil >/dev/null

# ---------------------------------------------------------------- wg-easy ---
log "configuring wg-easy (wg0 on host netns, subnet $SUBNET_BASE.x, DNS $DNS_IP)"
HASH="$(htpasswd -bnBC 10 "" "$UI_PASSWORD" | tr -d ':\n')"
mkdir -p "$INSTALL_DIR/config" "$INSTALL_DIR/profiles"
cat > "$INSTALL_DIR/docker-compose.yml" <<EOF
services:
  wg-easy:
    image: ghcr.io/wg-easy/wg-easy:latest
    container_name: wg-easy
    restart: unless-stopped
    network_mode: host
    cap_add: [NET_ADMIN]
    environment:
      - WG_HOST=$VPS_IP
      - PASSWORD_HASH=\$\$${HASH:3}
      - WG_DEFAULT_ADDRESS=$SUBNET_BASE.x
      - WG_DEFAULT_DNS=$DNS_IP
      - WG_MTU=1320
    volumes:
      - $INSTALL_DIR/config:/etc/wireguard
EOF
# ^ note: compose interpolates \$; the bcrypt hash's leading $2b is escaped.

(cd "$INSTALL_DIR" && docker compose up -d >/dev/null 2>&1 || \
    { command -v docker-compose >/dev/null && docker-compose up -d; })
log "waiting for wg-easy to become healthy (up to 90s)"
for i in $(seq 1 45); do
    ST="$(docker inspect -f '{{.State.Health.Status}}' wg-easy 2>/dev/null || echo starting)"
    [ "$ST" = healthy ] && break
    sleep 2
done
docker inspect -f '{{.State.Status}}/{{.State.Health.Status}}' wg-easy | grep -q "running/healthy" \
    || { echo "FATAL: wg-easy failed to start; docker logs wg-easy:"; docker logs wg-easy | tail -20; exit 1; }
log "wg-easy healthy"

# ------------------------------------------------------- firewall + MSS -----
log "installing firewall/NAT/MSS rules (systemd-persisted)"
cat > /etc/systemd/system/wg-nft-rules.service <<EOF
[Unit]
Description=WireGuard firewall rules (self-hosted-vpn-playbook)
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'iptables -t nat -C POSTROUTING -s $SUBNET_BASE.0/24 -o $NET_IF -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s $SUBNET_BASE.0/24 -o $NET_IF -j MASQUERADE; iptables -C FORWARD -i wg0 -o $NET_IF -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wg0 -o $NET_IF -j ACCEPT; iptables -C FORWARD -i $NET_IF -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i $NET_IF -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; iptables -C INPUT -i $NET_IF -p tcp --dport $UI_PORT -j DROP 2>/dev/null || iptables -A INPUT -i $NET_IF -p tcp --dport $UI_PORT -j DROP; iptables -t mangle -C FORWARD -i wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $MSS_VALUE 2>/dev/null || iptables -t mangle -A FORWARD -i wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $MSS_VALUE; iptables -t mangle -C FORWARD -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $MSS_VALUE 2>/dev/null || iptables -t mangle -A FORWARD -o wg0 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $MSS_VALUE'

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now wg-nft-rules

# ---------------------------------------------------------- stats dashboard --
log "installing stats dashboard (http://$DNS_IP:$DASH_PORT, tunnel-only)"
mkdir -p "$INSTALL_DIR/dashboard/templates" "$INSTALL_DIR/dashboard/data"
cp "$(dirname "$0")/../dashboard/app.py" "$INSTALL_DIR/dashboard/app.py"
cp "$(dirname "$0")/../dashboard/templates/dashboard.html" "$INSTALL_DIR/dashboard/templates/dashboard.html"
cat > /etc/systemd/system/vps-dashboard.service <<EOF
[Unit]
Description=VPS stats dashboard (tunnel-only)
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR/dashboard
Environment=HOME=/root
Environment=VPS_DASH_BIND=$DNS_IP
Environment=VPS_DASH_PORT=$DASH_PORT
Environment=VPS_DASH_DATA_DIR=$INSTALL_DIR/dashboard/data
Environment=VPS_DASH_WG_EASY_CONFIG=$INSTALL_DIR/config/wg0.json
ExecStart=/usr/bin/python3 $INSTALL_DIR/dashboard/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now vps-dashboard

# ------------------------------------------------------------- watchdog ----
log "installing watchdog + profile generator"
cp "$(dirname "$0")/vpn-health-check.py" /usr/local/bin/vpn-health-check.py
cp "$(dirname "$0")/add-wg-profile.py" /usr/local/bin/add-wg-profile.py
chmod 755 /usr/local/bin/vpn-health-check.py /usr/local/bin/add-wg-profile.py
cat > /etc/cron.d/vpn-watchdog <<EOF
# vpn-watchdog: token-free health check every 5 min (silent when healthy)
*/5 * * * * root WG_EASY_CONFIG=$INSTALL_DIR/config/wg0.json DASH_URL=http://$DNS_IP:$DASH_PORT/ python3 /usr/local/bin/vpn-health-check.py
EOF
chmod 644 /etc/cron.d/vpn-watchdog

# -------------------------------------------------------- healthcheck peer --
log "creating healthcheck peer (watchdog egress-test identity)"
WAIT_SEC=3
for i in $(seq 1 20); do
    CURL_OUT="$(curl -s -m 10 -c /tmp/vpn-setup.cookies -X POST "http://localhost:$UI_PORT/api/session" \
        -H 'Content-Type: application/json' -d "{\"password\":\"$UI_PASSWORD\"}" -o /dev/null -w '%{http_code}')"
    [ "$CURL_OUT" = 200 ] && break
    sleep $WAIT_SEC
done
[ "$CURL_OUT" = 200 ] || { echo "FATAL: wg-easy session login failed"; exit 1; }
curl -s -m 10 -b /tmp/vpn-setup.cookies -X POST "http://localhost:$UI_PORT/api/wireguard/client" \
    -H 'Content-Type: application/json' -d '{"name":"healthcheck"}' -o /dev/null
sleep 2
python3 - "$INSTALL_DIR/config/wg0.json" <<'EOF'
import json, sys
cfg = json.load(open(sys.argv[1]))
hc = [c for c in cfg.get("clients", {}).values() if c.get("name") == "healthcheck"]
sys.exit(0 if hc else 1)
EOF
[ $? -eq 0 ] || { echo "FATAL: healthcheck client creation failed"; exit 1; }
log "healthcheck peer ready"

# ------------------------------------------------------- optional extras ----
if [ "${ADGUARD_SKIP:-0}" != 1 ] && [ "${1:-}" = "--with-adguard" ]; then
    log "installing AdGuard Home (DNS ad-blocking on $DNS_IP)"
    AGH_VER="v0.107.79"
    curl -sL -o /tmp/agh.tar.gz "https://github.com/AdguardTeam/AdGuardHome/releases/download/$AGH_VER/AdGuardHome_linux_amd64.tar.gz"
    tar -xzf /tmp/agh.tar.gz -C /tmp
    mkdir -p /opt/AdGuardHome
    mv /tmp/AdGuardHome/AdGuardHome /opt/AdGuardHome/
    AGH_PW="$(openssl rand -base64 12 | tr -d '/+=' | head -c 14)"
    AHASH="$(htpasswd -bnBC 10 "" "$AGH_PW" | tr -d ':\n')"
    cat > /opt/AdGuardHome/AdGuardHome.yaml <<EOF
http:
  pprof:
    port: 6060
    enabled: false
  address: $DNS_IP:3000
  session_ttl: 720h
users:
  - name: admin
    password: $AHASH
auth_attempts: 5
block_auth_min: 15
http_proxy: ""
language: ""
theme: auto
dns:
  bind_hosts:
    - $DNS_IP
  port: 53
  anonymize_client_ip: false
  ratelimit: 0
  ratelimit_subnet_len_ipv4: 24
  ratelimit_subnet_len_ipv6: 56
  refuse_any: true
  upstream_dns:
    - https://dns.quad9.net/dns-query
    - https://1.1.1.1/dns-query
  upstream_dns_file: ""
  bootstrap_dns:
    - 9.9.9.10
    - 1.1.1.1
  fallback_dns: []
  upstream_mode: load_balance
  fastest_timeout: 1s
  allowed_clients: []
  disallowed_clients: []
  blocking_mode: default
  blocked_response_ttl: 10
  querylog_enabled: true
  querylog_file_enabled: true
  querylog_interval: 2160h
  querylog_size_memory: 1000
  anonymize_client_ip: false
  cache_size: 4194304
  cache_ttl_min: 0
  cache_ttl_max: 60
  cache_optimistic: false
  bogus_nxdomain: []
  aaaa_disabled: false
  enable_dnssec: false
  edns_client_subnet:
    custom_ip: ""
    enabled: false
    use_custom: false
  max_goroutines: 300
  handle_ddr: true
  ipset: []
  ipset_file: ""
  bootstrap_prefer_ipv6: false
  upstream_timeout: 10s
  private_networks: []
  use_private_ptr_resolvers: false
  local_ptr_upstreams: []
  use_dns64: false
  dns64_prefixes: []
  serve_http3: false
  use_http3_upstreams: false
  serve_plain_dns: true
  hostsfile_enabled: true
tls:
  enabled: false
  server_name: ""
filters:
  - enabled: true
    url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
    name: AdGuard DNS filter
    id: 1
  - enabled: true
    url: https://big.oisd.nl/
    name: OISD Blocklist Big
    id: 2
whitelist_filters: []
user_rules: []
dhcp:
  enabled: false
clients:
  runtime_sources:
    whois: true
    arp: true
    rdns: true
    dhcp: true
    hosts: true
log:
  enabled: true
  file: ""
  max_backups: 0
  max_size: 100
  max_age: 3
  verbose: false
os:
  group: ""
  user: ""
  rlimit_nofile: 0
schema_version: 30
EOF
    cat > /etc/systemd/system/adguardhome.service <<EOF
[Unit]
Description=AdGuard Home DNS filter
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/AdGuardHome
ExecStart=/opt/AdGuardHome/AdGuardHome -c /opt/AdGuardHome/AdGuardHome.yaml -w /opt/AdGuardHome
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && systemctl enable --now adguardhome
    printf "AdGuard admin: http://%s:3000  password: %s\n" "$DNS_IP" "$AGH_PW" > /root/.adguard-creds.txt
    log "AdGuard installed (admin creds: /root/.adguard-creds.txt)"
fi

if [ "${SPEEDTEST_SKIP:-0}" != 1 ] && [ "${1:-}" = "--with-speedtest" ] || [ "${2:-}" = "--with-speedtest" ]; then
    log "installing Ookla speedtest CLI"
    curl -sL -o /tmp/ookla.tgz "https://install.speedtest.net/app/cli/ookla-speedtest-1.2.0-linux-x86_64.tgz"
    tar -xzf /tmp/ookla.tgz -C /tmp
    mv /tmp/speedtest /usr/local/bin/speedtest
    chmod 755 /usr/local/bin/speedtest
    /usr/local/bin/speedtest --accept-license --accept-gdpr >/dev/null 2>&1 || true
fi

# ------------------------------------------------------------------ verify --
log "running the health check (must print nothing)"
set +e
OUT="$(WG_EASY_CONFIG=$INSTALL_DIR/config/wg0.json DASH_URL=http://$DNS_IP:$DASH_PORT/ \
    python3 /usr/local/bin/vpn-health-check.py 2>&1)"
RC=$?
set -e
if [ $RC -ne 0 ]; then
    echo "FATAL: health check failed:"; echo "$OUT"; exit 1
fi
log "health check: all green"

cat <<EOF

================= VPN STACK READY =================
Tunnel:      $VPS_IP:$WG_PORT (udp)
Device UI:   http://$DNS_IP:$UI_PORT   (password: $UI_PASSWORD; tunnel-only)
Stats:       http://$DNS_IP:$DASH_PORT (tunnel-only)
Watchdog:    cron every 5 min -> /usr/local/bin/vpn-health-check.py
             (silent when healthy; prints FLAG lines + exit 1 when broken)
Add device:  /usr/local/bin/add-wg-profile.py "Name" (prints QR path)
====================================================

Next steps:
1. Create a device profile in the wg-easy UI (or add-wg-profile.py).
2. Import it in the WireGuard app (QR) and connect.
3. The watchdog covers container, tunnel, 6 firewall rules, AdGuard,
   dashboard, endpoint sanity, rejected handshakes, and a live egress test.
4. For Hermes-based hosts: create the two Hermes cron jobs per
   docs/04-health-monitoring.md (no_agent watchdog + event-woken autofix).
EOF
