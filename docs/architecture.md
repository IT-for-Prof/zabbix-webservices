# Architecture

> Status: in production. Template `7.0-2.2.2`, externalscript
> `web_check.py` 2.1.3, installer, and migration script all shipped and
> running on 5 Zabbix server/proxy nodes; 59 hosts migrated from
> `Template Website metrics (itmicus.ru)` on 2026-05-14.

## Goal

Replace `Template Website metrics (itmicus.ru)` (legacy, templateid 10329 in
production, linked to 59 hosts (migration completed 2026-05-14, see CHANGELOG)) with a Zabbix-7.0 native + single-externalscript
design that:

- Attaches as one template to any web-host, just like the legacy template did.
- Runs every check from the same proxy or server that already monitors that
  host (correct egress for GEO/RKN/internal-DNS scenarios — same property the
  legacy template had).
- Delivers richer cert/TLS data than the legacy template, comparable to the
  monitoring-relevant subset of an SSL Labs report.
- Provides RDAP-first WHOIS for every domain, with port-43 fallback only where
  RDAP is genuinely unavailable.
- Deduplicates WHOIS at the registered-apex level (`mon.itforprof.com`,
  `mail.itforprof.com`, and `itforprof.com` ask once for `itforprof.com`).
- Adds Zabbix-native network-diagnostic items (DNS, TCP-connect, ICMP
  latency) so a "site is down" alert can be triaged without leaving Zabbix.
- Replaces `website_metrics.py` (`requests` monkey-patch, abandoned
  `python-whois` / `tldextract` / `python-dateutil` deps, Python-2 compat
  hacks) with a Python 3.11+ codebase using stdlib + the actively-maintained
  `cryptography` library, with type hints, lint, and unit tests.

## Principles

1. **One template per concern, attached to any host.** No probe-host siblings.
   No host duplication. The web-host that already exists in Zabbix is the
   only host that gets touched.

2. **Native Zabbix wherever it suffices.** Web scenarios for HTTP. Simple
   checks for DNS / TCP-perf / ICMP-perf. LLD for things that come in
   variable counts (TLS protocol matrix, cipher findings). External script
   only for what Zabbix natives cannot do: TLS X.509 metadata extraction
   and RDAP/WHOIS.

3. **`monitored_by`-aware execution.** External-check items and Zabbix simple
   checks both run on the server-or-proxy that polls the host. Web scenarios
   too. Egress automatically matches the rest of the host's monitoring; no
   extra plumbing.

4. **Apex deduplication for WHOIS.** Identifying the registered apex of a
   hostname is a deterministic local operation (Public Suffix List).
   Caching RDAP/WHOIS at apex granularity collapses N host-checks into one
   network round-trip per apex per day.

5. **Modern, maintainable code.** Python 3.11+, type hints, `ruff` + `mypy
   --strict` + `pytest`, single file deploy via packaged `.pyz`, CI on
   GitHub Actions, semantic versioning aligned with the template's
   `vendor.version`.

6. **Honest scope.** This is monitoring, not auditing. No Heartbleed
   detectors, no full browser TLS handshake matrix per poll. Daily deep
   scan covers the slow-changing parts.

## Constraints (Zabbix 7.0 reality)

These shaped the design and must be remembered when extending it:

- `web.certificate.get` exists only as a Zabbix agent 2 item type. There is
  no server-side or proxy-side native way to extract `not_after`. Hence the
  external script.
- Script items (Zabbix 7.0 JS runtime with `HttpRequest`) cannot reach TLS
  cert metadata either — no `getPeerCertificate` equivalent.
- `configuration.import` in Zabbix 7.0 silently rejects httptest blocks
  when any step `timeout` carries a time-suffix. Step `timeout` is integer
  seconds. (Tested live, May 2026; cost us a debug round.)
- `wizard_ready` field on templates is 7.4+ only. The current production is
  7.0. Leave it out of YAML.
- Web scenarios are intentionally *not* part of `configuration.importcompare`
  in 7.0, so no dry-run diff is available for them. Plan reviews
  out-of-band.

## System overview

```
┌────────────────────────────────────────────────────────────────────────┐
│  Source web-host (e.g. eurotrade-group.ru, monitored_by=ET-VPS01)      │
│                                                                        │
│  Template: Web service by itforprof.com                                │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Layer 1 — HTTP availability                                      │  │
│  │   Web scenario "Web service" (native, 1m)                        │  │
│  │   → web.test.fail, web.test.error, web.test.time                 │  │
│  │   Runs on ET-VPS01.                                              │  │
│  ├──────────────────────────────────────────────────────────────────┤  │
│  │ Layer 2 — TLS + certificate                                      │  │
│  │   External item: web_check.py cert <url>      (master, 5m)       │  │
│  │   → dependent items: cert.days_to_expire, cert.fingerprint, …    │  │
│  │   Runs on ET-VPS01.                                              │  │
│  ├──────────────────────────────────────────────────────────────────┤  │
│  │ Layer 3 — Domain WHOIS                                           │  │
│  │   External item: web_check.py whois <apex>    (master, 1h*)      │  │
│  │   FS cache, 24h TTL, apex-keyed: collapses to ~1 query/apex/day  │  │
│  │   → dependent items: whois.days_to_expire, whois.registrar, …   │  │
│  │   Runs on ET-VPS01.                                              │  │
│  ├──────────────────────────────────────────────────────────────────┤  │
│  │ Layer 4 — Network diagnostics                                    │  │
│  │   net.tcp.service.perf[https,…,443]           (native, 1m)       │  │
│  │   net.dns.record[…,A], net.dns.record[…,AAAA] (native, 5m)       │  │
│  │   net.dns.record[…,CAA]                       (native, 1h)       │  │
│  │   All run on ET-VPS01.                                           │  │
│  ├──────────────────────────────────────────────────────────────────┤  │
│  │ Layer 5 — Daily deep TLS scan                                    │  │
│  │   External item: web_check.py tls-scan <url>  (master, 1d)       │  │
│  │   LLD discovers supported protocols & weak ciphers               │  │
│  │   → prototype triggers per finding                               │  │
│  │   Runs on ET-VPS01.                                              │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

(*) The `whois` item's `delay` is `1h` because the cache lookup is cheap;
real network queries happen ~once/day per apex. See
[Apex deduplication](#apex-deduplication-algorithm).

## Layer 1 — HTTP availability (native web scenario)

**Why native:** A web scenario in Zabbix 7.0 already does everything the
HTTP portion of `website_metrics.py` did (status code, response time,
phrase match, redirect handling) without the script-process cost and
without a deploy step. It is `monitored_by`-aware. It supports macros for
URL/timeout/expected-code, and exposes `web.test.error` with detailed
failure diagnostics in operational data.

**Configuration:**

| Macro | Default | Purpose |
|---|---|---|
| `{$WEB_SERVICE.URL}` | required, no default | Full URL to monitor. |
| `{$WEB_SERVICE.PHRASE}` | empty | Substring expected on response body. Empty = skip phrase check. |
| `{$WEB_SERVICE.EXPECTED_CODE}` | `200` | Status codes considered healthy. Supports `200,204,301-302`. |
| `{$WEB_SERVICE.TIMEOUT}` | `15` | Step timeout in seconds (integer). |
| `{$WEB_SERVICE.CHECK.INTERVAL}` | `1m` | Scenario delay. |
| `{$WEB_SERVICE.SLOW.WARN}` | `5` | Avg response time threshold for WARNING. |
| `{$WEB_SERVICE.NODATA.PERIOD}` | `10m` | No-data trigger period. |
| `{$WEB_SERVICE.USER_AGENT}` | `Zabbix-WebService-by-itforprof/2.0` | HTTP `User-Agent`. Honest default. |
| `{$WEB_SERVICE.FOLLOW_REDIRECTS}` | `YES` | Whether to follow 3xx redirects. |

**Items (auto-generated by the scenario):**

- `web.test.fail[Web service]` — 0/1, scenario-level overall.
- `web.test.error[Web service]` — text, last failure reason.
- `web.test.in[Web service,,bps]` — download bandwidth.
- `web.test.time[Web service,GET,resp]` — per-step response time, seconds.

**Triggers:**

| Name | Severity | Expression |
|---|---|---|
| `Web service is failing` | HIGH | `last(.../web.test.fail[Web service])<>0` |
| `Web service slow response time` | WARNING | `avg(.../web.test.time[…,resp],10m) > {$WEB_SERVICE.SLOW.WARN}` (depends on "is failing") |
| `Web service no data received` | AVERAGE | `nodata(.../web.test.fail[Web service], {$WEB_SERVICE.NODATA.PERIOD})=1` |

**Tags on items/triggers:** `scope: availability`, `scope: performance`,
`scope: data-collection` — matching the legacy categorisation for event
routing.

This layer is already imported into production (templateid 13996) — only
the macros (`USER_AGENT`, `FOLLOW_REDIRECTS`) and the related trigger
docstrings still need adding.

## Layer 2 — TLS + certificate (externalscript, per host)

**Why externalscript:** Zabbix 7.0 has no native server- or proxy-side way
to extract `not_after` from a TLS handshake. Agent 2 has it, but our
constraint forbids new probe-hosts. External check is the remaining option
and it is also `monitored_by`-aware.

**Item:**

```
web_check.py["cert", "{$WEB_SERVICE.URL}"]
```

- Type: External check.
- Value type: text (JSON).
- Delay: `{$WEB_SERVICE.CERT.CHECK.INTERVAL}` (default `5m`). Cert data
  changes ~once per validity period; even 5m is far more often than
  needed.
- Master item; everything else is `Dependent item` with JSONPath
  preprocessing.

**JSON shape returned by the script:**

```json
{
  "ok": true,
  "checked_at": "2026-05-13T12:34:56Z",
  "url": "https://eurotrade-group.ru",
  "host": "eurotrade-group.ru",
  "port": 443,
  "tls": {
    "protocol": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "alpn": "h2",
    "forward_secrecy": true,
    "handshake_ms": 184
  },
  "cert": {
    "subject_cn": "eurotrade-group.ru",
    "subject_dn": "CN=eurotrade-group.ru",
    "issuer_cn": "R3",
    "issuer_dn": "CN=R3, O=Let's Encrypt, C=US",
    "issuer_org": "Let's Encrypt",
    "serial": "04A3F1...",
    "not_before": "2026-04-02T00:00:00Z",
    "not_after": "2026-07-01T23:59:59Z",
    "days_to_expire": 49,
    "sans": ["eurotrade-group.ru", "www.eurotrade-group.ru"],
    "hostname_covered": true,
    "signature_algorithm": "sha256WithRSAEncryption",
    "public_key_algorithm": "rsa",
    "public_key_bits": 2048,
    "fingerprint_sha256": "AB:CD:EF:…",
    "fingerprint_sha1": "12:34:56:…",
    "ocsp_uri": "http://r3.o.lencr.org",
    "ca_issuers_uri": "http://r3.i.lencr.org/",
    "chain_status": "ok",
    "chain_length": 2
  }
}
```

On error: `{"ok": false, "error_code": "dns_error|tcp_timeout|tls_error|cert_invalid|…", "error_message": "…", "checked_at": "…"}`.

`days_to_expire` is signed: `−7` means the certificate has been expired
for a week. This is a deliberate departure from the legacy script, which
clamped to 0 and lost diagnostic information.

**Dependent items (preprocessing: JSONPath):**

| Name | Key | Value type | JSONPath |
|---|---|---|---|
| Cert days to expire | `cert.days_to_expire` | int | `$.cert.days_to_expire` |
| Cert not after | `cert.not_after` | text | `$.cert.not_after` |
| Cert subject CN | `cert.subject_cn` | text | `$.cert.subject_cn` |
| Cert issuer CN | `cert.issuer_cn` | text | `$.cert.issuer_cn` |
| Cert issuer organization | `cert.issuer_org` | text | `$.cert.issuer_org` |
| Cert serial | `cert.serial` | text | `$.cert.serial` |
| Cert SANs | `cert.sans` | text (comma-joined via JS preproc) | `$.cert.sans` |
| Cert signature algorithm | `cert.signature_algorithm` | text | `$.cert.signature_algorithm` |
| Cert key bits | `cert.public_key_bits` | int | `$.cert.public_key_bits` |
| Cert fingerprint SHA256 | `cert.fingerprint_sha256` | text | `$.cert.fingerprint_sha256` |
| Cert chain status | `cert.chain_status` | text | `$.cert.chain_status` |
| Cert hostname covered | `cert.hostname_covered` | uint (0/1) | `$.cert.hostname_covered` |
| TLS protocol used | `tls.protocol` | text | `$.tls.protocol` |
| TLS cipher | `tls.cipher` | text | `$.tls.cipher` |
| TLS handshake duration | `tls.handshake_ms` | int | `$.tls.handshake_ms` |
| Check status | `cert.check_ok` | uint (0/1) | `$.ok` |
| Check error code | `cert.error_code` | text | `$.error_code` |

**Triggers (per host):**

| Name | Severity | Expression |
|---|---|---|
| Certificate expired | DISASTER | `last(.../cert.days_to_expire) <= 0` |
| Certificate expires within 7 days | HIGH | `last(.../cert.days_to_expire) <= 7` (depends on Expired) |
| Certificate expires within 14 days | WARNING | `last(.../cert.days_to_expire) <= 14` (depends on <7d) |
| Certificate expires within 30 days | INFO | `last(.../cert.days_to_expire) <= 30` (depends on <14d) |
| Certificate untrusted / chain invalid | HIGH | `last(.../cert.chain_status) <> "ok"` |
| Certificate hostname mismatch | HIGH | `last(.../cert.hostname_covered) = 0` |
| Certificate weak signature algorithm | WARNING | `find(.../cert.signature_algorithm, , "regexp", "(sha1|md5)")` |
| Certificate weak key | WARNING | `last(.../cert.public_key_bits) > 0 and last(.../cert.public_key_bits) < 2048` (RSA branch; ECDSA branch separate) |
| Certificate rotated | INFO | `change(.../cert.fingerprint_sha256) <> ""` (manual close required) |
| Certificate rotated unexpectedly | HIGH | as above AND prior `cert.days_to_expire > 60` |
| TLS protocol weak | WARNING | `last(.../tls.protocol) in (TLSv1.0, TLSv1.1)` |
| Cert check failing | INFO | `last(.../cert.check_ok) = 0` (no data ≠ check error; this catches `error_code` from the script itself) |

Severity hierarchy uses Zabbix trigger *dependencies* (lower severities depend
on higher), so an "expired" event suppresses the "<7d" through "<30d" cascade.

## Layer 3 — Domain WHOIS (externalscript, apex-deduped via FS cache)

**Library choice:** `asyncwhois` 1.1.12 (Oct 2025), MIT-licensed,
actively maintained. Speaks both **RDAP** (where the TLD is in IANA
bootstrap) and **port-43 WHOIS** (everywhere else), with one unified
API call. Routes via IANA's whois-server registry automatically. Returns
`(raw_text, parsed_dict)` so we can post-process the raw text for the
small set of TLDs whose parsers have gaps.

Why not in-house code: we tested four libraries (`whoisit`, `asyncwhois`,
`python-whois`, our own port-43 socket loop) against our actual 47-host
parc (.com / .ru / .рф / .hu) on the production mon node. Only
`asyncwhois` covered the breadth without a per-TLD parser pack. See
`docs/validation.md` Finding F-7.

**Why apex-dedup:** A web-host's registered domain (apex) is computed via
the Public Suffix List. `mon.itforprof.com`, `mail.itforprof.com`, and
`itforprof.com` all collapse to `itforprof.com`. Querying WHOIS three
times in 5 minutes for the same apex is wasteful and risks
rate-limiting. The script caches the unified result keyed by apex; later
invocations within the TTL read the cache.

**Item:**

```
web_check.py["whois", "{$WEB_SERVICE.URL}"]
```

- Delay: `{$WEB_SERVICE.WHOIS.CHECK.INTERVAL}` (default `1h`). Most calls
  are cache hits and return in <10ms.
- Cache TTL: `{$WEB_SERVICE.WHOIS.CACHE.TTL}` (default `86400` seconds).
- Cache location: `/opt/web_check/data/cache/whois_<sha256(apex)>.json`.

**Algorithm:**

1. Extract apex from URL via PSL (`tldextract` or our PSL-driven
   resolver).
2. Read cache. If present and `now - mtime < TTL`, return cached JSON
   plus `cache_age_seconds`.
3. `asyncwhois.whois(apex)` → `(raw_text, parsed_dict)`. Library
   internally:
   - Looks up authoritative RDAP/whois server via IANA;
   - Tries RDAP first if available, port-43 otherwise;
   - Parses common response formats.
4. If `parsed_dict["expires"] is None` but our **per-TLD augmenter**
   knows the format (e.g. `.рф` / TCI: regex on `paid-till:`), extract
   the missing fields from `raw_text` and patch the dict.
5. Atomic write to cache (tmpfile + `os.replace`). `fcntl.flock` to
   serialise concurrent first-writers; on lock contention, return stale
   cache rather than block.

**JSON shape (normalised across RDAP and port-43 sources):**

```json
{
  "ok": true,
  "checked_at": "2026-05-13T12:34:56Z",
  "apex": "itforprof.com",
  "source": "rdap_via_asyncwhois",
  "cache_age_seconds": 0,
  "registrar": "Registrar of Domain Names REG.RU LLC",
  "registrar_iana_id": "1606",
  "registered_at": "2016-03-21T07:52:09Z",
  "last_updated": "2026-03-07T01:58:14Z",
  "expires_at": "2027-03-21T07:52:09Z",
  "days_to_expire": 308,
  "statuses": ["clientTransferProhibited"],
  "name_servers": ["ns1.reg.ru", "ns2.reg.ru"],
  "dnssec": false,
  "abuse_email": "abuse@reg.ru",
  "provider_no_expiry": false
}
```

The flag `provider_no_expiry` is set true when the upstream registry
intentionally omits expiration (notably `.hu` via `whois.nic.hu`). In
that case, `expires_at` and `days_to_expire` are `null` and the
"domain expires" triggers are suppressed for the host (via a calculated
item using this flag as gate).

**Dependent items:** `whois.days_to_expire`, `whois.expires_at`,
`whois.registrar`, `whois.name_servers` (joined), `whois.dnssec`,
`whois.cache_age_seconds`, `whois.source`, `whois.provider_no_expiry`.

**Triggers (per host, but data is shared via cache):**

| Name | Severity | Expression |
|---|---|---|
| Domain expired | DISASTER | `last(.../whois.days_to_expire) <= 0` |
| Domain expires within 7 days | DISASTER | `last(.../whois.days_to_expire) <= 7` (depends on Expired) |
| Domain expires within 30 days | HIGH | `last(.../whois.days_to_expire) <= 30` (depends on <7d) |
| Domain expires within 60 days | WARNING | `last(.../whois.days_to_expire) <= 60` (depends on <30d) |
| Domain registrar changed | WARNING | `change(.../whois.registrar) <> ""` (potential transfer) |
| Domain nameservers changed | INFO | `change(.../whois.name_servers) <> ""` |
| Domain DNSSEC removed | WARNING | previous `whois.dnssec` was 1, now 0 |
| WHOIS check failing | INFO | `last(.../whois.check_ok) = 0` |

## Layer 4 — Network diagnostics (native simple checks)

These are pure Zabbix simple checks (no agent, no script), used to
*triage* an availability or latency event. All run on the host's
`monitored_by` (server or proxy) — same egress as the rest of the
checks.

| Key | Purpose | Delay | Notes |
|---|---|---|---|
| `net.dns[,{HOST.HOST},A]` | DNS resolution success (A) | 5m | Detects DNS-server failure or hijack. 0/1. |
| `net.dns.record[,{HOST.HOST},A]` | A-record value | 5m | Latest data → alert if IPs drift unexpectedly. |
| `net.dns.record[,{HOST.HOST},AAAA]` | AAAA-record value | 5m | IPv6 coverage tracking. |
| `net.dns.record[,{HOST.HOST},CAA]` | CAA records | 1h | Verify cert issuer is in CAA-allowed list. |
| `net.tcp.service.perf[https,{HOST.HOST},443]` | TCP connect-only latency | 1m | Separates connect time from total request time. |
| `net.tcp.service.perf[http,{HOST.HOST},80]` | HTTP TCP connect latency | 1m | For sites that should redirect HTTP→HTTPS. |

Most of these are simple checks; `icmp*` requires `fping` on the proxy
node (already required by the existing `ICMP Ping` template — no new
ops cost).

**Triggers:**

| Name | Severity | Expression |
|---|---|---|
| DNS resolution failed | HIGH | `last(.../net.dns[,...,A]) = 0 for 5m` |
| TCP 443 connect failed | HIGH | `nodata(.../net.tcp.service.perf[https,…,443],5m)=1` OR `last(...)>0` if 0 is "service unavailable" — depends on Zabbix version behaviour. Verify before use. |
| TCP 443 connect slow | WARNING | `avg(.../net.tcp.service.perf[https,…,443],10m) > 0.5` (seconds) |
| CAA disallows current issuer | WARNING | regexp match between `net.dns.record[,…,CAA]` and `cert.issuer_org` mismatch — composite, computed via calculated item |

## Layer 5 — Daily deep TLS scan

**Why separate item:** Negotiating TLS 1.0, 1.1, 1.2, 1.3 separately costs 4
handshakes per probe. At every 5m that's 480 handshakes/host/day. At every
1d that's 4 — proportional to "did the server become more permissive
overnight," which is exactly the question this layer answers.

**Item:**

```
web_check.py["tls-scan", "{$WEB_SERVICE.URL}"]
```

- Delay `1d`.
- Returns JSON containing supported protocols, weak ciphers found, etc.

**LLD:** Drives item prototypes and trigger prototypes from the discovered
protocols / weak findings:

```json
{
  "supported_protocols": ["TLSv1.2", "TLSv1.3"],
  "weak_findings": [
    {"category": "protocol", "name": "TLSv1.0", "severity": "WARNING"},
    {"category": "cipher",   "name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "severity": "WARNING"}
  ]
}
```

**LLD rule:** `web_check.tls_scan.discover` keying on `{#TLS_FINDING}` and
`{#TLS_FINDING.SEVERITY}`. Item prototype reports presence; trigger
prototype fires per finding with appropriate severity.

This is the "ssllabs-comparable" portion of the design: ongoing monitoring
of TLS server posture without doing a full ssllabs scan every minute.

## Item taxonomy (consolidated)

Concise view of every item / prototype the template will provide. Y = yes
in the legacy template, N = new.

| Category | Item | Type | Source | Legacy? |
|---|---|---|---|---|
| HTTP | Web scenario "Web service" (master) | Web scenario | native | Y (via script) |
| HTTP | web.test.fail[Web service] | Auto-derived | native | Y |
| HTTP | web.test.error[Web service] | Auto-derived | native | Y |
| HTTP | web.test.time[Web service,GET,resp] | Auto-derived | native | Y |
| HTTP | web.test.in[Web service] | Auto-derived | native | Y |
| Cert | cert (master JSON) | External | `web_check.py cert` | N (richer than legacy) |
| Cert | cert.days_to_expire | Dependent | JSONPath | Y |
| Cert | cert.not_after | Dependent | JSONPath | Y |
| Cert | cert.subject_cn | Dependent | JSONPath | partial |
| Cert | cert.issuer_cn | Dependent | JSONPath | Y |
| Cert | cert.issuer_org | Dependent | JSONPath | N |
| Cert | cert.serial | Dependent | JSONPath | Y |
| Cert | cert.sans | Dependent | JSONPath | N |
| Cert | cert.fingerprint_sha256 | Dependent | JSONPath | N |
| Cert | cert.signature_algorithm | Dependent | JSONPath | N |
| Cert | cert.public_key_bits | Dependent | JSONPath | N |
| Cert | cert.hostname_covered | Dependent | JSONPath | N |
| Cert | cert.chain_status | Dependent | JSONPath | N (legacy uses single OK/FAIL via `ssl_verify_cert`) |
| Cert | cert.check_ok | Dependent | JSONPath | N |
| TLS  | tls.protocol | Dependent | JSONPath | N |
| TLS  | tls.cipher | Dependent | JSONPath | N |
| TLS  | tls.handshake_ms | Dependent | JSONPath | N |
| Whois | whois (master JSON) | External | `web_check.py whois` | Y (script) |
| Whois | whois.days_to_expire | Dependent | JSONPath | Y |
| Whois | whois.expires_at | Dependent | JSONPath | Y |
| Whois | whois.registrar | Dependent | JSONPath | Y |
| Whois | whois.name_servers | Dependent | JSONPath | N |
| Whois | whois.dnssec | Dependent | JSONPath | N |
| Whois | whois.cache_age_seconds | Dependent | JSONPath | N |
| Whois | whois.source | Dependent | JSONPath | N |
| Diag | net.dns[,…,A] | Simple check | native | N |
| Diag | net.dns.record[,…,A] | Simple check | native | N |
| Diag | net.dns.record[,…,AAAA] | Simple check | native | N |
| Diag | net.dns.record[,…,CAA] | Simple check | native | N |
| Diag | net.tcp.service.perf[https,…,443] | Simple check | native | N |
| Diag | net.tcp.service.perf[http,…,80] | Simple check | native | N |
| Scan | tls_scan (master JSON) | External | `web_check.py tls-scan` | N |
| Scan | LLD `tls_finding` + per-finding prototype | LLD | JSONPath | N |

## Trigger taxonomy (consolidated)

| Category | Trigger | Severity |
|---|---|---|
| HTTP | Web service is failing | HIGH |
| HTTP | Web service slow response time | WARNING |
| HTTP | Web service no data received | AVERAGE |
| Cert | Certificate expired | DISASTER |
| Cert | Certificate expires within 7 days | HIGH |
| Cert | Certificate expires within 14 days | WARNING |
| Cert | Certificate expires within 30 days | INFO |
| Cert | Certificate untrusted / chain invalid | HIGH |
| Cert | Certificate hostname mismatch | HIGH |
| Cert | Certificate weak signature algorithm | WARNING |
| Cert | Certificate weak key | WARNING |
| Cert | Certificate rotated | INFO |
| Cert | Certificate rotated unexpectedly | HIGH |
| Cert | Cert check failing | INFO |
| TLS  | TLS protocol weak (current) | WARNING |
| Whois | Domain expired | DISASTER |
| Whois | Domain expires within 7 days | DISASTER |
| Whois | Domain expires within 30 days | HIGH |
| Whois | Domain expires within 60 days | WARNING |
| Whois | Domain registrar changed | WARNING |
| Whois | Domain nameservers changed | INFO |
| Whois | Domain DNSSEC removed | WARNING |
| Whois | WHOIS check failing | INFO |
| Diag | DNS resolution failed | HIGH |
| Diag | TCP 443 connect failed | HIGH |
| Diag | TCP 443 connect slow | WARNING |
| Diag | CAA disallows current issuer | WARNING |
| Scan | (per-finding LLD prototypes) | WARNING |

## Macros catalog

Full list of user macros the template declares.

| Macro | Default | Purpose |
|---|---|---|
| `{$WEB_SERVICE.URL}` | (required) | Full URL to monitor. |
| `{$WEB_SERVICE.PHRASE}` | "" | Response-body substring; empty = skip check. |
| `{$WEB_SERVICE.EXPECTED_CODE}` | 200 | Expected HTTP status codes. |
| `{$WEB_SERVICE.TIMEOUT}` | 15 | Web scenario step timeout (seconds). |
| `{$WEB_SERVICE.CHECK.INTERVAL}` | 1m | Web scenario `delay`. |
| `{$WEB_SERVICE.CERT.CHECK.INTERVAL}` | 5m | Cert master-item delay. |
| `{$WEB_SERVICE.WHOIS.CHECK.INTERVAL}` | 1h | Whois master-item delay (mostly cache hits). |
| `{$WEB_SERVICE.WHOIS.CACHE.TTL}` | 86400 | Whois cache TTL in seconds. |
| `{$WEB_SERVICE.TLS_SCAN.CHECK.INTERVAL}` | 1d | Daily deep TLS scan delay. |
| `{$WEB_SERVICE.SLOW.WARN}` | 5 | Slow-response trigger threshold (seconds). |
| `{$WEB_SERVICE.NODATA.PERIOD}` | 10m | No-data trigger period. |
| `{$WEB_SERVICE.USER_AGENT}` | `Zabbix-WebService-by-itforprof/2.0` | HTTP User-Agent for web scenario. |
| `{$WEB_SERVICE.FOLLOW_REDIRECTS}` | YES | Whether the web scenario follows 3xx. |
| `{$WEB_SERVICE.CERT.WARN_DAYS}` | 30 | Soft expiry threshold for INFO trigger. |
| `{$WEB_SERVICE.CERT.CRIT_DAYS}` | 7 | Hard expiry threshold for HIGH trigger. |
| `{$WEB_SERVICE.WHOIS.CRIT_DAYS}` | 30 | Hard expiry threshold for HIGH trigger. |

All macros are documented in the template descriptions; descriptions are
also visible in the Zabbix UI.

## Apex deduplication algorithm

**Why:** Saves ~60% of WHOIS round-trips on a parc like ours (59 hosts,
~25 unique apex domains). Avoids registry-side rate limiting. Cache layer
is also where we record fingerprint-history for `whois.registrar`
change-detection.

**Components:**

1. **Public Suffix List (PSL):** Mozilla-maintained list of effective
   top-level domains. We use the snapshot bundled in the `tldextract`
   release; the extractor is instantiated at module scope with
   `suffix_list_urls=()` and `fallback_to_snapshot=True` so it never
   makes a network call. Refresh the snapshot by bumping `tldextract`
   in `scripts/deploy/requirements.in` (typically quarterly).

2. **Cache directory:** `/opt/web_check/data/cache/`, owned
   `zabbix:zabbix`, mode `0750`. Created by `scripts/deploy/install.sh`;
   the script `mkdir(parents=True, exist_ok=True)`s it on first use as a
   fallback. Lives under `INSTALL_ROOT` (default `/opt/web_check`).

3. **Cache files:** `whois_<sha256(apex)>.json`. SHA-256 keeps file names
   filesystem-safe and constant length.

4. **TTL:** `{$WEB_SERVICE.WHOIS.CACHE.TTL}` (default 86400 s, passed via
   the master item's `--ttl` arg). Stale ⇒ refresh. A separate negative
   TTL (`WEB_CHECK_WHOIS_NEG_TTL` env, default 3600 s) covers
   `provider_no_expiry: true` and registry-unreachable responses.

5. **Stampede protection:** `fcntl.flock(LOCK_EX | LOCK_NB)` on a lock
   file `whois_<sha256(apex)>.lock`. On contention the script does not
   block: it returns the current cache entry (fresh or stale) — better
   to serve slightly-stale data than block a Zabbix poller slot. All
   competing pollers see the same cache once whichever one wrote first
   releases the lock.

6. **Atomic writes:** write to `whois_<sha256(apex)>.json.tmp` then
   `os.replace`. No partially-written files visible.

7. **Cache content versioning:** the JSON record includes `schema_version`.
   `WhoisCache.read()` reads but does not currently *enforce* a minimum
   version — adequate while `SCHEMA_VERSION=1` and the format is fixed.
   When the format changes, bump `SCHEMA_VERSION` and add a version
   check at read time so older entries auto-invalidate.

**Reasonable cache size:** For our parc, ~25 apex × ~600 bytes/file =
~15 KiB. Effectively free.

## Python implementation: `web_check.py`

### File layout in the repo

```
scripts/
├── _zabbix_client.py       (unchanged — already-shared helper)
├── externalscripts/
│   └── web_check.py        (the script that gets deployed)
├── pyproject.toml          (formal package: ruff, mypy, pytest config; lockfile)
└── tests/
    ├── test_cert.py
    ├── test_whois_rdap.py
    ├── test_whois_port43.py
    ├── test_psl.py
    ├── test_cache.py
    ├── test_cli.py
    └── fixtures/
        ├── self_signed.pem
        ├── expired.pem
        ├── weak_sig.pem
        ├── rdap_response.json
        └── whois_port43_response.txt
```

### Single-file deploy + project venv

The externalscript is a plain `.py` deployed to
`/usr/lib/zabbix/externalscripts/web_check.py`. Its shebang points at a
project-local **Python 3.12 virtual environment** (managed by `uv`)
installed once per node:

```
/opt/web_check/
├── python/                  # uv-managed CPython 3.12 (host's system Python untouched)
├── venv/                    # python3.12 venv with asyncwhois + cryptography + tldextract + aioquic
└── data/
    └── cache/               # WHOIS apex cache (owner zabbix:zabbix)
```

Shebang: `#!/opt/web_check/venv/bin/python`.

Why venv: avoids dependence on distro Python (CentOS Stream 8 ships
3.6.8 as default; mon also has `python3.11` from EPEL but without
`cryptography`/`asyncwhois`). The current installer goes one step
further and provisions its own Python via `uv` so distro Python
upgrades cannot break the deploy. Single
`uv pip install -r requirements.lock` step. Codebase floor is 3.11
(CI runs 3.11/3.12/3.13); production currently ships 3.12.

Validated on mon and on every relevant proxy (et-vps01, sr-vps01,
ifp-vps12, ifp-vps15) — see `docs/validation.md` Finding F-8.

`scripts/deploy/install.sh`:
```bash
set -euo pipefail
INSTALL_ROOT=/opt/web_check
EXTERNAL_DIR=/usr/lib/zabbix/externalscripts

# Find a Python ≥3.11 — prefer explicit python3.11 (CentOS 8), fall back to
# `python3` if its version is ≥3.11 (Ubuntu 24.04 ships 3.12, Debian 12 ships 3.11).
for cand in python3.11 python3.12 python3.13 python3; do
    if command -v "$cand" >/dev/null \
       && "$cand" -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' 2>/dev/null; then
        PYTHON="$cand"
        break
    fi
done
: "${PYTHON:?No Python ≥3.11 found. Install python3.11 (CentOS: dnf install python3.11) or upgrade the distro.}"

"$PYTHON" -m venv "${INSTALL_ROOT}/venv"
"${INSTALL_ROOT}/venv/bin/pip" install --upgrade pip
"${INSTALL_ROOT}/venv/bin/pip" install -r requirements.lock
install -d -m 0750 -o zabbix -g zabbix "${INSTALL_ROOT}/data/cache"
install -m 0750 -o zabbix -g zabbix web_check.py "${EXTERNAL_DIR}/"
"${EXTERNAL_DIR}/web_check.py" self-test
```

Confirmed working end-to-end on the actual fleet (mon CentOS Stream 8
python 3.11.7; ifp-vps12 Debian 12 python 3.11.2; et-vps01 / sr-vps01 /
ifp-vps15 Ubuntu 24.04 python 3.12.3) — `docs/validation.md` Finding
F-10.

`requirements.lock` is checked into the repo with version pins
generated via `pip freeze` on a clean install; CI verifies the lock
stays valid against current upstreams.

### Module structure (internal classes within one file)

```
web_check.py
├── PSL                — Public Suffix List, embedded data + apex lookup.
├── Cache              — FS-backed JSON cache with TTL and stampede lock.
├── CertChecker        — TLS handshake, cert parse via cryptography, optional OCSP staple read, JSON output.
├── TLSScanner         — Multi-protocol/cipher matrix (daily).
├── WhoisChecker       — RDAP-first + port-43 fallback, apex extraction via PSL, returns JSON.
├── DiscoveryFormatter — LLD JSON formatting for TLS scan findings.
└── Cli                — argparse subcommands: cert / whois / tls-scan / discover-tls / self-test.
```

### Subcommands

```
web_check.py cert <url>           # returns JSON for Layer 2 master item
web_check.py whois <url>          # returns JSON for Layer 3 master item
web_check.py tls-scan <url>       # returns JSON for Layer 5 master item (slow)
web_check.py discover-tls <url>   # returns LLD JSON for Layer 5 LLD rule
web_check.py self-test            # smoke test on bundled fixtures, no network
```

### Error model

Every subcommand returns valid JSON to stdout, exit code 0. Network/parse
failures encode themselves into the JSON (`{"ok": false, "error_code":
"…"}`). The host's check items show "Last value: error_code", Zabbix
items don't go UNSUPPORTED, and triggers like "WHOIS check failing" can
fire cleanly.

### Dependencies

- Standard library, plus three third-party packages — all actively
  maintained, MIT-licensed, installed into a project-local venv (see
  Deployment):
  - `cryptography` (PyCA) — X.509 parsing.
  - `asyncwhois` — RDAP + port-43 WHOIS with auto-routing.
  - `tldextract` — Public Suffix List apex extraction.

Excluded (vs legacy `website_metrics.py`): `requests` (and the
HTTPResponse monkey-patch trick), `python-whois` (abandoned), the old
`python-dateutil`, `pyOpenSSL`. Our HTTP-side is handled by the native
Zabbix web scenario (Layer 1), so no HTTP client lib is needed in
`web_check.py` at all.

### Code quality

- Type hints throughout (`mypy --strict` clean).
- `ruff check --select ALL` with project-level pragmatic noqa for E501,
  D203/D211, COM812, ANN101, ANN102.
- pytest with `pytest-httpserver` for HTTP mocks and `trustme` for
  generating test certs.
- `pre-commit` config: ruff, mypy, pytest.

## Deployment

### Target nodes

`web_check.py` is deployed to `/usr/lib/zabbix/externalscripts/` on:

- The Zabbix server (`mon.itforprof.com`)
- Every Zabbix proxy that monitors web-hosts. Currently:
  - `ET-VPS01` (proxyid 13938) — EUROTRADE customers
  - `SR-VPS01-PROXY` (13905) — SeaRegion
  - `IFP-VPS12-PROXY` (13936), `IFP-VPS15-PROXY` (13937) — HA pair for IFP/voffice24

The same file, identical lockfile-pinned venv across all nodes. SSH
access to all of these was validated (`docs/validation.md` G1 PASS).

### Permissions

- `web_check.py` and `/opt/web_check/data/cache/` owned `zabbix:zabbix`,
  mode `0750`.
- venv `/opt/web_check/venv/` owned `root:zabbix` mode `0755` — readable
  by Zabbix, writable only by root (deployer).

### Distribution mechanism

`scripts/Makefile`:

- `make package` → builds `dist/web_check.pyz` (single-file executable
  with bundled cryptography if requested).
- `make install LOC=mon.itforprof.com` → rsync to one node.
- `make install-all` → fan out across all known nodes (list in
  `scripts/deploy/inventory.txt`).
- `make smoke LOC=mon.itforprof.com` → ssh and run `web_check.py
  --self-test` on the target.

A minimal Ansible role `deploy/ansible/web_check/` is included as the
preferred path for ops; the Makefile is for quick installs.

### Operating system requirements

- Python 3.11+ on the system (used only to bootstrap the venv).
  Default `python3` of the distro is not used; we explicitly call
  `python3.11`.
- `fping` ≥ 3.10 if Layer 4 ICMP items are used (already required by
  `ICMP Ping` template — already installed on all our proxies).
- venv-provided libs (pinned in `requirements.lock`): `cryptography
  ≥ 41`, `asyncwhois ≥ 1.1.12`, `tldextract ≥ 5`.

### Configuration

No config file. The script reads its arguments from the item key and its
cache TTL from environment variable `WEB_CHECK_CACHE_TTL` (set via
systemd drop-in if you need a non-default), but typically just reads
defaults. Macros at the Zabbix layer control everything operationally.

## Testing & CI

### Unit tests

Each module is unit-tested independently:

- **CertChecker:** synthetic certs (valid, expired, weak-signature,
  multi-SAN, ECDSA, RSA-1024) generated via `trustme` at test time. Local
  TLS server fixture serves them. Assertions on the JSON shape, all
  fields populated, error paths produce the expected `error_code`.

- **WhoisChecker (RDAP):** `pytest-httpserver` serves a recorded RDAP
  response. Assertions on field extraction, event-action normalization,
  source = "rdap".

- **WhoisChecker (port-43):** mock TCP server returning recorded
  registrar response text. Per-TLD regex parsers tested individually for
  .ru, .com, .hu, .net, .org.

- **PSL:** assert apex extraction for `mail.itforprof.com`,
  `xn--80abbpbovebeji9ph3b.xn--p1ai`, `subdomain.user.gov.uk`, edge
  cases like `gov.uk` itself (which is in PSL).

- **Cache:** TTL respected, atomic write semantics, stampede tested with
  two processes vying for the lock.

- **CLI:** subcommands wire to the right module. `--self-test` returns
  exit 0 on fixtures.

### Integration tests

A small set of integration tests hits real public domains (e.g.
`example.com`, `mozilla.org`) and asserts shape only (not specific
values, since those change). Run nightly on CI, not on every PR.

### CI (GitHub Actions)

`.github/workflows/ci.yml`:

- On every push / PR: ruff (lint+format), mypy, pytest unit tests
  matrix-tested against Python 3.11 / 3.12 / 3.13.
- Nightly cron: integration tests, PSL freshness check (downloads
  current PSL, diffs against bundled, opens issue if drift > 1%).

### Smoke deploys

`scripts/deploy/smoke.sh` runs after install on each node and exercises
each subcommand against a controlled URL (e.g. `https://mon.itforprof.com`
itself). Exit 0 = all OK; non-zero = something is wrong on this node.

## Migration plan

Phased and reversible. Per-host work is automated; the high-level steps
are scripted in `scripts/migrate-from-itmicus.py`, which already handles
template link/unlink and macro translation.

1. **Pre-deploy.** Build & install `web_check.py` on `mon.itforprof.com`
   and `ET-VPS01`. Run `--self-test`. Confirm cache directory created and
   permissions correct.

2. **Pilot — 2 hosts.** `mon.itforprof.com` (server-monitored) and
   `eurotrade-group.ru` (proxy-monitored via ET-VPS01). Link new template
   with `--keep-old`. Run for 24 hours in parallel with the legacy
   template. Compare each value: cert.days_to_expire vs legacy
   `ssl.daystoexpire`, whois.days_to_expire vs legacy
   `domain.daystoexpire`. Look for systematic divergence.

3. **Stabilise.** Fix anything the pilot reveals. Re-deploy. Re-test.

4. **Tenant by tenant.** EUROTRADE (mostly via ET-VPS01) → SeaRegion (via
   SeaRegion proxy) → IFP (server) → ARC/NORD/AVAKS/EXTRO (mostly
   server). 12-hour soak between tenant batches. After each batch:
   `scripts/migrate-from-itmicus.py --apply` on that tenant's hosts to
   unlink the legacy template; macros are already translated by then.

5. **Final cleanup.** Disable `Template Website metrics (itmicus.ru)` in
   the Zabbix UI. Remove `website_metrics.py` from
   `/usr/lib/zabbix/externalscripts/` on mon, vps12, vps15, ET-VPS01,
   SeaRegion proxy. Confirm no items reference it via `item.get`.

6. **Post-mortem.** Record any surprises in `docs/migration-notes.md`.

## Known limitations

These are honest accuracy/coverage gaps in the design; alerts are
suppressed where appropriate so we don't manufacture false positives.

- **`.hu` domain expiration:** Hungarian registry (`whois.nic.hu`)
  intentionally omits expiration from port-43 responses. RDAP is not
  offered. Our `web_check.py whois` returns
  `provider_no_expiry: true` for `.hu`; the
  "Domain expires within N days" triggers are gated on this flag and
  stay silent. SSL-cert expiry on the same host still alerts (and
  typically expires well before the domain). Mitigation if needed:
  WhoisXML-API or similar paid feed, for `.hu` hosts only.
- **TCI RDAP unreachable:** `rdap.tcinet.ru` is not in IANA bootstrap and
  not publicly DNS-resolvable from outside the .ru ecosystem. We use
  port-43 to `whois.tcinet.ru` (works for `.ru`, `.рф`, `.su`); for
  `.рф` punycode we augment the parser dict from raw response.

## Registry rate-limit policy

Each authoritative WHOIS / RDAP server enforces its own rate limit. The
script must respect these per-registry; getting blocked from `whois.tcinet.ru`
or `whois.nic.hu` would make the WHOIS layer go dark.

Hard rules implemented in `WhoisChecker`:

| Registry / Server | Max queries from one source IP | Our throttle |
|---|---|---|
| TCI (`whois.tcinet.ru`, .ru / .рф / .su) | "fair use" (no published number; community reports flag bans at >1/min sustained) | **≤ 1 query per apex per 24h** (enforced by FS cache) + global ≤ 4/min across all `.ru` apexes (token bucket per-node) |
| `.hu` (`whois.nic.hu`) | unspecified; intentionally minimal data | ≤ 1 query per apex per 24h |
| `.com` / VeriSign RDAP | RDAP 7480 says 429 with Retry-After | ≤ 10 / 10s per `rdap.org` redirect policy; we hit upstream so even softer in practice |
| Any RDAP server returning 429 | client must back off (RFC 7480 §5.5) | exponential: 30s, 2m, 10m; max 3 retries; honour `Retry-After` if present |

The 24h cache already gives us the dominant throttling (1 query/apex/day).
The token bucket is belt-and-braces for the case where many cold-cache
apexes are queried in a burst (e.g. just after deploy or after the cache
directory is wiped).

`provider_no_expiry: true` results are also cached, with a shorter TTL
(`{$WEB_SERVICE.WHOIS.NEGATIVE_CACHE.TTL}`, default 1h) so we don't keep
hammering registries that simply don't have the data.

Retry policy (in pseudocode):

```
attempts = 0
while attempts < 3:
    try:
        result = asyncwhois.whois(apex, timeout=15)
        break
    except (asyncwhois.WhoisQueryConnectError, TimeoutError) as e:
        sleep(30 * (2 ** attempts) + jitter)
        attempts += 1
    except asyncwhois.WhoisQueryRateLimitError:
        # parsed from "% Try later" / 429 / similar
        sleep(retry_after_or_default)
        attempts += 1
else:
    # All retries failed; return ok=false with stale cache if available
```

## Non-goals and explicit trade-offs

We deliberately do NOT try to:

- **Detect TLS-implementation vulnerabilities** (Heartbleed, POODLE,
  ROBOT, CRIME). Those are one-shot scans, not continuous monitoring.
  Run the standalone `testssl.sh` or hosted SSL Labs once per change.

- **Full browser-level UX testing** (page load metrics, JS error
  detection). Zabbix `Browser` item type exists in 7.0 but is meant for
  Selenium-style automation. Out of scope; track via a different system
  (synthetic monitoring, RUM) if needed.

- **DANE / TLSA record validation.** Rare in our parc; revisit if anyone
  starts using DANE.

- **Per-cipher fingerprint of every TLS handshake.** Daily LLD-driven
  scan is enough.

- **Cert Transparency log searching.** Would require external service or
  significant local infrastructure. Out of scope for now.

- **DMARC/SPF/DKIM monitoring.** Already covered by
  `Template Mail DNS Audit Zabbix` (templateid 13957). Stays separate.

## Open questions

These need answers before the implementation phase, listed for explicit
review:

1. **WHOIS source-of-truth conflicts.** When RDAP says "expires 2027-09-15"
   and port-43 says "expires 2027-09-16" (because TLD registry rolls at a
   different moment), do we prefer RDAP and ignore the discrepancy, or
   alert on disagreement? Default proposal: prefer RDAP silently.

2. **Cache distribution.** Each proxy keeps its own cache. If
   `mon.itforprof.com` already pulled `itforprof.com` 6 hours ago, ET-VPS01
   still pulls it independently when it gets a host with apex
   `itforprof.com`. Acceptable cost given the data is small; otherwise
   we'd need a shared cache (Redis, NFS) — not worth it.

3. **What to do on legacy LLD residue.** Hosts already monitored by the
   legacy template may have host-level overrides on prototype-created
   items. After migration these dangle. Migration script will detect
   them and report, but auto-delete only with `--cleanup-residue` flag.

4. **TLS-scan host count.** Layer 5 scans 4 protocols, several ciphers.
   That's ~20 handshakes/host/day = ~1180/day total for 59 hosts. Some
   registries / CDNs detect this and rate-limit. If anyone complains,
   stagger or move to weekly.

5. **Vendor-version semver.** Bumped to `7.0-2.2.0` to reflect the
   cert+WHOIS+diag+TLS-scan layers added on top of the original HTTP-only
   v1. Future bumps follow the per-template semver convention documented in
   the top-level [README](../README.md#versioning).

## Document history

- 2026-05-13 (rev 2) — Layer 3 redesigned around `asyncwhois`
  (single library, RDAP + port-43 with auto-routing). venv-based
  deploy formalised. `.hu`-expiration limitation acknowledged.
  Drives from `docs/validation.md` Findings F-7 and F-8.
- 2026-05-13 (rev 1) — rewrite: probe-host pattern dropped, replaced by
  single externalscript design with apex-deduped WHOIS and native
  diagnostic layer. Five-layer model. Modern Python stack.
- (prior) — initial scaffold with probe-host pattern. Superseded.
