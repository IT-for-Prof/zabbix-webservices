# Web service by itforprof.com

Full-stack web-service monitoring template for Zabbix 7.0.

|                  |                                          |
| ---------------- | ---------------------------------------- |
| Vendor           | `itforprof.com`                          |
| Version          | `7.0-2.5.0`                              |
| TLS profile      | `7.0-1.2.0`                              |
| Template group   | `Templates/Applications`                 |
| Wizard-ready     | Yes                                      |
| Execution        | Whatever monitors the host (server / proxy) |

## Overview

Replaces the legacy [`Template Website metrics (itmicus.ru)`](https://github.com/itmicus/zabbix/tree/master/Template%20Web%20Site)
and its abandoned `website_metrics.py` externalscript (built on the
unmaintained `whois==0.9` PyPI package and a `requests` monkey-patch).

The original template remains the full web-service profile:

| # | Concern              | Mechanism                                                       |
| - | -------------------- | --------------------------------------------------------------- |
| 1 | HTTP availability    | Native Zabbix Web Scenario (`{$WEB_SERVICE.URL}`).               |
| 2 | TLS + certificate    | EXTERNAL item `web_check.py cert` → master JSON + ~13 dependents. |
| 3 | Domain WHOIS         | EXTERNAL item `web_check.py whois` (apex-deduped FS cache, 24h TTL). |
| 4 | Network diagnostics  | Native simple checks (`net.tcp.service.perf`). |
| 5 | Deep TLS scan (daily) | EXTERNAL `web_check.py tls-scan` + LLD per weak finding.         |
| 6 | HTTP/3 advertise + QUIC reachability | EXTERNAL `web_check.py http3` (Alt-Svc + aioquic handshake; silent on hosts that don't advertise h3). |

## Certificate-TLS profile

For TLS endpoints checked with an `https://host[:port]` URL, import [`template_web_service_by_itforprof_com_tls.yaml`](template_web_service_by_itforprof_com_tls.yaml)
and link only **Web service by itforprof.com - Certificate-TLS**. It contains the
certificate master item, certificate metadata, expiry/rotation checks, and live
TLS protocol/cipher/handshake items. The URL keeps its port, so SQL Server can
use `https://ifp-vps03.itforprof.com:1433`; HTTP, WHOIS, HTTP/3, TLS scan, and
TCP 80/443 checks are absent from this profile.

The profile watches the certificate, not the service. It has no availability
alert: a probe that cannot reach the endpoint only raises AVERAGE "Cert check
failing on 3 consecutive checks" after three failed checks. Monitor the
service's availability elsewhere (Zabbix agent, a TCP port check, or the full
template for a website) and never link this profile to a site as its only check.

The external script currently preserves a non-standard port only for `https://`
URLs. Use that scheme for SQL Server and other TLS endpoints.

The endpoint must accept a direct TLS handshake. Legacy SQL Server TDS 7.x
normally sends a PRELOGIN exchange before TLS; this endpoint was verified from
the monitoring server and negotiated TLS directly.

Profile defaults are host-overridable:

| Macro | Default |
|---|---:|
| `{$WEB_SERVICE.CERT.CHECK.INTERVAL}` | `5m` |
| `{$WEB_SERVICE.CERT.NODATA.PERIOD}` | `15m` |
| `{$WEB_SERVICE.CERT.WARN_DAYS}` | `90` |
| `{$WEB_SERVICE.CERT.NOTICE_DAYS}` | `30` |
| `{$WEB_SERVICE.CERT.CRIT_DAYS}` | `7` |
| `{$WEB_SERVICE.CERT.ROTATE_MIN_DAYS}` | `3` |
| `{$WEB_SERVICE.CERT.MIN_KEY_RSA}` / `MIN_KEY_ECDSA` | `2048` / `256` |

For `IFP-VPS03`, set `{$WEB_SERVICE.URL}` to
`https://ifp-vps03.itforprof.com:1433` and override the certificate interval
and expiry thresholds on the host as needed. Before enabling it, run
`web_check.py cert https://ifp-vps03.itforprof.com:1433` on the Zabbix
server/proxy that monitors the host. The corporate CA must be trusted on that
node for `chain_status=ok`; the agent check on the SQL host does not validate
external-script reachability.

All checks run from the host's `monitored_by` (server or proxy), so request
egress matches the rest of the host's monitoring (correct for
GEO/RKN/internal-DNS scenarios).

Design rationale: [`docs/architecture.md`](../../docs/architecture.md).
Validation matrix:  [`docs/validation.md`](../../docs/validation.md).

## Languages

Each template ships in English and Russian:

| Template | English | Russian |
|---|---|---|
| Full profile | `template_web_service_by_itforprof_com.yaml` | `template_web_service_by_itforprof_com_ru.yaml` |
| Certificate-TLS profile | `template_web_service_by_itforprof_com_tls.yaml` | `template_web_service_by_itforprof_com_tls_ru.yaml` |

Both languages share UUIDs, the technical template name, item keys, trigger
expressions, macros and tags. Only display text differs: item and trigger
names, event names, descriptions, value map labels and the visible template
name. To switch a server's language, import the other file over the existing
template with "Update existing" checked. Zabbix matches every object by UUID
and renames it in place, so history, host links and macro overrides stay. One
server holds one language at a time.

The English file is the source. `scripts/translate-templates.py` generates
`*_ru.yaml` from it and `i18n/ru.yaml`, and CI fails when a `*_ru.yaml` no
longer matches them.

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
| `{$WEB_SERVICE.HOST}` | Host or IP for diag simple checks. Set this to the URL hostname. |

With defaults (override per host as needed):

| Macro | Default | Purpose |
| ----- | ------- | ------- |
| `{$WEB_SERVICE.PHRASE}` | `""` | Body substring/regex (PCRE); empty = skip. |
| `{$WEB_SERVICE.PHRASE.FLAGS}` | `(?i)` | PCRE flag prefix for the phrase. Default `(?i)` = case-insensitive. Set to empty string for case-sensitive. |
| `{$WEB_SERVICE.EXPECTED_CODE}` | `200` | HTTP codes considered healthy (`200,204,301-302`). |
| `{$WEB_SERVICE.TIMEOUT}` | `15` | HTTP request timeout (s). |
| `{$WEB_SERVICE.USER_AGENT}` | `Zabbix-WebService-by-itforprof/2.0` | UA header. |
| `{$WEB_SERVICE.CHECK.INTERVAL}` | `1m` | Web scenario delay. |
| `{$WEB_SERVICE.CERT.CHECK.INTERVAL}` | `5m` | Cert master delay. |
| `{$WEB_SERVICE.WHOIS.CHECK.INTERVAL}` | `1h` | WHOIS master delay (mostly cache hits). |
| `{$WEB_SERVICE.WHOIS.CACHE.TTL}` | `86400` | WHOIS cache TTL (s). |
| `{$WEB_SERVICE.TLS_SCAN.CHECK.INTERVAL}` | `1d` | Deep TLS scan delay. |
| `{$WEB_SERVICE.DIAG.CHECK.INTERVAL}` | `5m` | Diag simple-check delay. |
| `{$WEB_SERVICE.SLOW.WARN}` | `10` | Avg HTTP response > N (s, 10m) → WARNING. |
| `{$WEB_SERVICE.NODATA.PERIOD}` | `10m` | Web scenario no-data trigger window. |
| `{$WEB_SERVICE.CERT.WARN_DAYS}` | `30` | Cert expiry INFO threshold. |
| `{$WEB_SERVICE.CERT.NOTICE_DAYS}` | `14` | Cert expiry WARNING threshold. |
| `{$WEB_SERVICE.CERT.CRIT_DAYS}` | `7` | Cert expiry AVERAGE threshold (last rung before HIGH "expired"). |
| `{$WEB_SERVICE.CERT.ROTATE_MIN_DAYS}` | `3` | "Rotated late" WARNING threshold: a rotation while the outgoing cert had fewer days left than this fires the alert. Reads the pre-rotation window, not the new cert. |
| `{$WEB_SERVICE.CERT.MIN_KEY_RSA}` | `2048` | Min RSA key size (bits). |
| `{$WEB_SERVICE.CERT.MIN_KEY_ECDSA}` | `256` | Min ECDSA key size (bits). |
| `{$WEB_SERVICE.WHOIS.WARN_DAYS}` | `30` | Domain expiry WARNING threshold (days). |
| `{$WEB_SERVICE.WHOIS.NOTICE_DAYS}` | `7` | Domain expiry AVERAGE threshold (days). |
| `{$WEB_SERVICE.WHOIS.CRIT_DAYS}` | `1` | Domain expiry AVERAGE threshold (days). HIGH fires on `days_to_expire < 0` (already expired). |
| `{$WEB_SERVICE.TCP.SLOW_SEC}` | `3` | `net.tcp.service.perf` WARNING threshold. |
| `{$WEB_SERVICE.HTTP3.CHECK.INTERVAL}` | `5m` | HTTP/3 master item delay. |
| `{$WEB_SERVICE.HTTP3.SLOW_MS}` | `1000` | QUIC handshake time WARNING threshold (ms). |

## Triggers (34 + 1 LLD prototype)

By scope:

| Scope         | Count | Highest severity |
| ------------- | :---: | ---------------- |
| availability  | 1     | HIGH             |
| performance   | 1     | WARNING          |
| data-collection | 6   | AVERAGE          |
| tls (cert + handshake) | 12 | HIGH           |
| whois         | 8     | HIGH             |
| diag          | 2     | AVERAGE          |
| http3         | 3     | AVERAGE          |
| tls-scan      | 1     | INFO             |
| tls-scan (LLD trigger prototype) | 1 per finding | WARNING |

Severity rule: HIGH means the service is already broken for users (site down,
cert or domain expired, hostname not covered, chain untrusted); AVERAGE means it
still works but needs action. No trigger is DISASTER. **Web service is failing**
and **TCP 443 connect failed** (AVERAGE) need two consecutive failed checks, so a
single failed poll does not open a problem.

Cert-expiry triggers cascade HIGH (expired) → AVERAGE (<7d) → WARNING (<14d)
→ INFO (<30d) with `dependencies` so only the most severe fires. Separately,
**Cert rotated** (INFO) fires on any fingerprint change, and **Cert rotated
unexpectedly** (WARNING) fires when a rotation is detected while the *outgoing*
cert was within `{$WEB_SERVICE.CERT.ROTATE_MIN_DAYS}` (default 3) days of
expiry — i.e. a dangerously late renewal. It reads `max(days_to_expire)` over
the 2h window ending 15m ago (the old cert), since on a dependent item
`last()` already reflects the freshly installed cert at the instant the
fingerprint changes. The fingerprint item discards any non-64-hex value
(`MATCHES_REGEX` / `DISCARD_VALUE`), so the error-envelope empty fingerprint
written during a cert-check outage never enters history — `change()` only ever
sees a genuine `real→real` rotation. A recovery from an outage (`""→real`) is
therefore not a rotation, while a genuinely late rotation that spanned a failed
poll (`old→""→new`) still fires, because the `""` is dropped, leaving
`old→new`.

For internal endpoints signed by a corporate CA, the "Cert chain untrusted"
trigger means the monitor node running `web_check.py cert` does not trust that
CA yet, or the endpoint is not serving the required intermediate certificates.
Install the corporate root/intermediate CA into the Zabbix server/proxy trust
store and keep TLS verification enabled.

WHOIS-expiry triggers are gated on `web_check.whois.provider_no_expiry` —
Hungarian (`.hu`) registries omit expiry by policy; those hosts stay silent
on the "Domain expires" series but still alert on cert expiry.

Certificate probe failures have two levels in both profiles. **Cert check
failing** remains INFO on the first error. Every dependent cert/TLS item drops
an `ok=false` envelope (`NOT_MATCHES_REGEX "ok":false` / `DISCARD_VALUE`) and
keeps its last real value, so the envelope's stubs (`hostname_covered=false`,
`days_to_expire=0`, `public_key_bits=0`) never reach the metadata triggers. Those
triggers have no dependency on the INFO trigger: it lost the race when both
flipped in one history-sync batch, and froze recovery for the 1h discard
heartbeat. **Cert check failing on 3 consecutive checks** is AVERAGE
on the third consecutive `ok=false` result (~10–15 minutes at the default
5-minute interval). The status item stores every poll. A successful check
clears the sustained-failure trigger immediately; missing master data clears
it after the existing no-data period, when the separate no-data trigger takes
over. The new trigger uses a freshness condition rather than a dependency so
an existing problem can recover while no-data is active.

NODATA coverage:
- Web scenario: `{$WEB_SERVICE.NODATA.PERIOD}` (default 10m).
- Cert / WHOIS / TLS-scan / HTTP/3 externalscripts: 3× their own delay
  (15m / 3h / 3d / 15m). Distinct from each script's own `ok=false` envelope;
  the NODATA triggers fire when the externalscript wasn't invoked at all
  (binary missing, fork refused, etc).

HTTP/3 layer is silent by design on hosts whose servers don't advertise
`h3` in their `Alt-Svc` response header — no triggers fire on `advertised=false`.
`HTTP/3 advertised but unreachable` (AVERAGE) catches the case where the
server claims h3 support but the proxy can't complete the QUIC handshake on
3 consecutive checks (UDP/443 dropped on the path, CDN regression, etc). The
site still answers over HTTP/2, so it is not HIGH. Checks that failed on DNS
(`error_code: dns_error`) are not counted.

## Caveats

- **Phrase is a case-insensitive regex by default.** Zabbix Web Scenarios
  treat the `required` field as PCRE. The template prepends
  `{$WEB_SERVICE.PHRASE.FLAGS}` (default `(?i)`) to the user-supplied phrase,
  so `EUROTRADE` matches both `Eurotrade` and `eurotrade` in the response body.
  Set the flags macro to empty string to opt back into case-sensitive matching,
  or to other PCRE flags (`(?s)` dotall, `(?m)` multi-line, etc.). Escape
  regex metacharacters (`. ( [ |`) in the phrase if you want literal matching.

- **Layer 4 is host-specific.** `{$WEB_SERVICE.HOST}` MUST be set on every
  host or the diag items go UNSUPPORTED. Set it to the URL hostname.
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
one Python externalscript.

## License

MIT — see [`../../LICENSE`](../../LICENSE).
Copyright © 2025-2026 Konstantin Tyutyunnik / Константин Тютюнник.
