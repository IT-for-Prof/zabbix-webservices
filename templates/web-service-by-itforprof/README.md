# Web service by itforprof.com

Full-stack web-service monitoring template for Zabbix 7.0.

|                  |                                          |
| ---------------- | ---------------------------------------- |
| Vendor           | `itforprof.com`                          |
| Version          | `7.0-2.2.2`                              |
| Template group   | `Templates/Applications`                 |
| Wizard-ready     | Yes                                      |
| Execution        | Whatever monitors the host (server / proxy) |

## Overview

Replaces the legacy [`Template Website metrics (itmicus.ru)`](https://github.com/itmicus/zabbix/tree/master/Template%20Web%20Site)
and its abandoned `website_metrics.py` externalscript (built on the
unmaintained `whois==0.9` PyPI package and a `requests` monkey-patch).

Six layers, single template per host:

| # | Concern              | Mechanism                                                       |
| - | -------------------- | --------------------------------------------------------------- |
| 1 | HTTP availability    | Native Zabbix Web Scenario (`{$WEB_SERVICE.URL}`).               |
| 2 | TLS + certificate    | EXTERNAL item `web_check.py cert` → master JSON + ~13 dependents. |
| 3 | Domain WHOIS         | EXTERNAL item `web_check.py whois` (apex-deduped FS cache, 24h TTL). |
| 4 | Network diagnostics  | Native simple checks (`net.tcp.service.perf`). |
| 5 | Deep TLS scan (daily) | EXTERNAL `web_check.py tls-scan` + LLD per weak finding.         |
| 6 | HTTP/3 advertise + QUIC reachability | EXTERNAL `web_check.py http3` (Alt-Svc + aioquic handshake; silent on hosts that don't advertise h3). |

All checks run from the host's `monitored_by` (server or proxy), so request
egress matches the rest of the host's monitoring (correct for
GEO/RKN/internal-DNS scenarios).

Design rationale: [`docs/architecture.md`](../../docs/architecture.md).
Validation matrix:  [`docs/validation.md`](../../docs/validation.md).

## Requirements

- Zabbix 7.0+.
- `web_check.py` deployed to `/usr/lib/zabbix/externalscripts/` on every
  Zabbix server/proxy that monitors hosts using this template. One-liner:
  ```
  curl -fsSL https://raw.githubusercontent.com/IT-for-Prof/zabbix-webservices/main/scripts/deploy/install.sh | sudo sh
  ```
  See [`scripts/deploy/install.sh`](../../scripts/deploy/install.sh) for the
  venv layout (`/opt/web_check/venv`, Python 3.12 installed by `uv` — the host's system Python is not used; codebase floor is 3.11).
- `fping` ≥ 3.10 on the monitor node (for Layer 4 ICMP items).

## Macros (27)

Required:

| Macro | Purpose |
| ----- | ------- |
| `{$WEB_SERVICE.URL}`  | Full URL to monitor, e.g. `https://example.com/healthz`. |
| `{$WEB_SERVICE.HOST}` | Host or IP for diag simple checks. Migration script derives this from the URL hostname. |

With defaults (override per host as needed):

| Macro | Default | Purpose |
| ----- | ------- | ------- |
| `{$WEB_SERVICE.PHRASE}` | `""` | Body substring/regex (PCRE); empty = skip. |
| `{$WEB_SERVICE.PHRASE.FLAGS}` | `(?i)` | PCRE flag prefix for the phrase. Default `(?i)` = case-insensitive. Set to empty string for case-sensitive. |
| `{$WEB_SERVICE.EXPECTED_CODE}` | `200` | HTTP codes considered healthy (`200,204,301-302`). |
| `{$WEB_SERVICE.TIMEOUT}` | `15` | HTTP request timeout (s). |
| `{$WEB_SERVICE.USER_AGENT}` | `Zabbix-WebService-by-itforprof/2.0` | UA header. |
| `{$WEB_SERVICE.FOLLOW_REDIRECTS}` | `YES` | Follow 3xx. |
| `{$WEB_SERVICE.CHECK.INTERVAL}` | `1m` | Web scenario delay. |
| `{$WEB_SERVICE.CERT.CHECK.INTERVAL}` | `5m` | Cert master delay. |
| `{$WEB_SERVICE.WHOIS.CHECK.INTERVAL}` | `1h` | WHOIS master delay (mostly cache hits). |
| `{$WEB_SERVICE.WHOIS.CACHE.TTL}` | `86400` | WHOIS cache TTL (s). |
| `{$WEB_SERVICE.TLS_SCAN.CHECK.INTERVAL}` | `1d` | Deep TLS scan delay. |
| `{$WEB_SERVICE.DIAG.CHECK.INTERVAL}` | `5m` | Diag simple-check delay. |
| `{$WEB_SERVICE.SLOW.WARN}` | `5` | Avg HTTP response > N (s, 10m) → WARNING. |
| `{$WEB_SERVICE.NODATA.PERIOD}` | `10m` | Web scenario no-data trigger window. |
| `{$WEB_SERVICE.CERT.WARN_DAYS}` | `30` | Cert expiry INFO threshold. |
| `{$WEB_SERVICE.CERT.NOTICE_DAYS}` | `14` | Cert expiry WARNING threshold. |
| `{$WEB_SERVICE.CERT.CRIT_DAYS}` | `7` | Cert expiry HIGH threshold. |
| `{$WEB_SERVICE.CERT.MIN_KEY_RSA}` | `2048` | Min RSA key size (bits). |
| `{$WEB_SERVICE.CERT.MIN_KEY_ECDSA}` | `256` | Min ECDSA key size (bits). |
| `{$WEB_SERVICE.WHOIS.WARN_DAYS}` | `30` | Domain expiry WARNING threshold (days). |
| `{$WEB_SERVICE.WHOIS.NOTICE_DAYS}` | `7` | Domain expiry AVERAGE threshold (days). |
| `{$WEB_SERVICE.WHOIS.CRIT_DAYS}` | `1` | Domain expiry HIGH threshold (days). DISASTER fires on `days_to_expire < 0` (already expired). |
| `{$WEB_SERVICE.TCP.SLOW_SEC}` | `1` | `net.tcp.service.perf` WARNING threshold. |
| `{$WEB_SERVICE.HTTP3.CHECK.INTERVAL}` | `5m` | HTTP/3 master item delay. |
| `{$WEB_SERVICE.HTTP3.TIMEOUT}` | `8` | Combined HEAD + QUIC handshake timeout (s). |
| `{$WEB_SERVICE.HTTP3.SLOW_MS}` | `250` | QUIC handshake time WARNING threshold (ms). |

## Triggers (34)

By scope:

| Scope         | Count | Highest severity |
| ------------- | :---: | ---------------- |
| availability  | 1     | HIGH             |
| performance   | 1     | WARNING          |
| data-collection | 5   | AVERAGE          |
| tls (cert + handshake) | 12 | DISASTER       |
| whois         | 8     | DISASTER         |
| diag          | 4     | HIGH             |
| http3         | 3     | HIGH             |
| tls-scan (LLD item prototype) | 1 per finding | INFO (no trigger prototype) |

Cert-expiry triggers cascade DISASTER → HIGH (<7d) → WARNING (<14d) → INFO
(<30d) with `dependencies` so only the most severe fires.

For internal endpoints signed by a corporate CA, the "Cert chain untrusted"
trigger means the monitor node running `web_check.py cert` does not trust that
CA yet, or the endpoint is not serving the required intermediate certificates.
Install the corporate root/intermediate CA into the Zabbix server/proxy trust
store and keep TLS verification enabled.

WHOIS-expiry triggers are gated on `web_check.whois.provider_no_expiry` —
Hungarian (`.hu`) registries omit expiry by policy; those hosts stay silent
on the "Domain expires" series but still alert on cert expiry.

NODATA coverage:
- Web scenario: `{$WEB_SERVICE.NODATA.PERIOD}` (default 10m).
- Cert / WHOIS / TLS-scan / HTTP/3 externalscripts: 3× their own delay
  (15m / 3h / 3d / 15m). Distinct from each script's own `ok=false` envelope;
  the NODATA triggers fire when the externalscript wasn't invoked at all
  (binary missing, fork refused, etc).

HTTP/3 layer is silent by design on hosts whose servers don't advertise
`h3` in their `Alt-Svc` response header — no triggers fire on `advertised=false`.
The only HIGH-severity trigger is `HTTP/3 advertised but unreachable`,
which catches the case where the server claims h3 support but our proxy
can't actually complete the QUIC handshake (UDP/443 dropped on the path,
CDN regression, etc).

## Migrating from `Template Website metrics (itmicus.ru)`

See [`../../docs/migration-checklist.md`](../../docs/migration-checklist.md)
and [`../../scripts/migrate-from-itmicus.py`](../../scripts/migrate-from-itmicus.py)
(idempotent, `--dry-run` is the default, pass `--apply` to write).

Macro translation:

| Old                              | New                       |
| -------------------------------- | ------------------------- |
| `{$WEBSITE_METRICS_URL}`         | `{$WEB_SERVICE.URL}`      |
| `{$WEBSITE_METRICS_PHRASE}`      | `{$WEB_SERVICE.PHRASE}`   |
| `{$WEBSITE_METRICS_TIMEOUT}`     | `{$WEB_SERVICE.TIMEOUT}`  |
| `{$WEBSITE_METRICS_TIMEOUT_RECOVERY}` | (dropped — Zabbix web scenarios have step-level timeout) |
| `{$WEBSITE_METRICS_DEBUG}`       | (dropped — Zabbix has scenario-level debug controls)     |
| (derived)                        | `{$WEB_SERVICE.HOST}` ← URL hostname for Layer 4 diag.    |

## Caveats

- **Phrase is a case-insensitive regex by default.** Zabbix Web Scenarios
  treat the `required` field as PCRE. The template prepends
  `{$WEB_SERVICE.PHRASE.FLAGS}` (default `(?i)`) to the user-supplied phrase,
  so `EUROTRADE` matches both `Eurotrade` and `eurotrade` in the response body.
  Set the flags macro to empty string to opt back into case-sensitive matching,
  or to other PCRE flags (`(?s)` dotall, `(?m)` multi-line, etc.). Escape
  regex metacharacters (`. ( [ |`) in the phrase if you want literal matching.
  The migration script copies legacy phrase values verbatim.
- **Layer 4 is host-specific.** `{$WEB_SERVICE.HOST}` MUST be set on every
  host or the diag items go UNSUPPORTED. The migration script derives it
  from the URL hostname automatically.
- **`web_check.py` venv must exist on the monitor node.** The cert/WHOIS/
  TLS-scan EXTERNAL items return `error_code=missing_dependency` if the venv
  at `/opt/web_check/venv` is missing — they don't crash Zabbix, but you'll
  see the "Cert check failing" trigger fire.

## Author

**Konstantin Tyutyunnik** / Константин Тютюнник — [itforprof.com](https://itforprof.com)

## Credits

Original work. Supersedes the conceptually-similar Zabbix template
[`Template Website metrics (itmicus.ru)`](https://github.com/itmicus/zabbix/tree/master/Template%20Web%20Site)
by **itmicus** — its scope of work (HTTP availability + TLS + WHOIS expiry)
is here re-implemented from scratch on Zabbix 7.0 native primitives plus
one modern Python externalscript. **No code copied.** Macro names are
kept compatible so [`../../scripts/migrate-from-itmicus.py`](../../scripts/migrate-from-itmicus.py)
can translate host-level macros 1:1.

## License

MIT — see [`../../LICENSE`](../../LICENSE).
Copyright © 2025-2026 Konstantin Tyutyunnik / Константин Тютюнник.
