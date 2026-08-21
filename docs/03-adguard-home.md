# 03 — AdGuard Home (DNS ad/tracker blocking)

DNS-level blocking for the tunnel: phone queries hit AdGuard Home (AGH) on the
tunnel IP, ad/tracker domains resolve to 0.0.0.0, everything else forwards
upstream over DoH. Blocks ads in every app, not just browsers. Proven with
v0.107.79 on Ubuntu 24.04.

## Install (latest release from GitHub)

```bash
# AdGuardHome_linux_amd64.tar.gz — tarball nests an inner AdGuardHome/ dir;
# extract, move the binary up. Binary is already executable.
mkdir -p /opt/AdGuardHome
```

## Minimal config — /opt/AdGuardHome/AdGuardHome.yaml

AGH migrates/fills missing keys on first start. The critical ones:

```yaml
http:
  address: 10.66.66.1:3000          # admin UI tunnel-only, never public
users:
  - name: admin
    password: <BCRYPT>
dns:
  bind_hosts:
    - 10.66.66.1                    # tunnel IP only — NOT 0.0.0.0 (open resolver!)
  port: 53
  upstream_dns:
    - https://dns.quad9.net/dns-query
    - https://cloudflare-dns.com/dns-query
  bootstrap_dns:
    - 9.9.9.10
    - 1.1.1.1
filtering:
  filters_update_interval: 12       # hours; keeps lists current
  filters:
    - enabled: true
      url: https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt
      name: AdGuard DNS filter
      id: 1
    - enabled: true
      url: https://big.oisd.nl/
      name: OISD Blocklist Big
      id: 2
querylog:
  enabled: true
statistics:
  enabled: true
```

systemd unit:

```ini
[Unit]
Description=AdGuard Home DNS filter
After=network-online.target docker.service
[Service]
WorkingDirectory=/opt/AdGuardHome
ExecStart=/opt/AdGuardHome/AdGuardHome -c /opt/AdGuardHome/AdGuardHome.yaml -w /opt/AdGuardHome
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
```

## Point the tunnel at it

Client profile: `DNS = 10.66.66.1` (was 1.1.1.1). Regenerate QR/conf.
In the phone app: tunnel → Edit → DNS servers → `10.66.66.1`.

## Verify

```bash
dig @10.66.66.1 example.com          # resolves real IPs
dig @10.66.66.1 doubleclick.net      # 0.0.0.0 (blocked)
dig @10.66.66.1 analytics.tiktok.com # 0.0.0.0 (blocked)
```

Filter status (after session login — see doc 02 for API auth):

```bash
curl -s -b cookies.txt http://10.66.66.1:3000/control/filtering/status
# expect rule counts + last_updated dates for both filters
```

## Pitfalls

- **Config migrator corrupts `bootstrap_dns`** — first start rewrites the yaml
  (schema bumps) and turns the bootstrap list into a LIST OF LISTS → parse
  crash ("cannot construct !!seq into string"). Fix the nesting after migration.
- **Migrator flips `safe_search.enabled` to true** — set back to false unless
  the user wants forced safe search.
- **Migrator drops non-default filters** (OISD etc.) — re-add via API:
  `POST /control/filtering/add_url {"name","url","whitelist":false}`.
- **Admin UI + DNS must bind the tunnel IP only** — binding 0.0.0.0 makes you
  an open resolver and exposes the admin panel to the internet.
- **Boot race with wg-easy** — AGH binds an IP that only exists after the
  wg-easy container starts; `After=docker.service` + `Restart=on-failure`
  self-heals within seconds.
- **Upstream via DoH** keeps your DNS queries private from the VPS provider;
  plain UDP/53 upstream does not.
