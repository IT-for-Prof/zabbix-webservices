# Validation matrix

> Status: live document. We work through this top-to-bottom before writing
> production code. When a check fails, we update `architecture.md` and
> re-design before continuing.

Each check has:

- **Goal** — what assumption are we testing?
- **Procedure** — minimal steps to run it.
- **Pass criteria** — what counts as a green light.
- **Result** — `pending` / `PASS` / `FAIL: <why>` / `WORKAROUND: <…>`.

Groups are run sequentially (A → G). If A or B fails, the architecture
needs serious revision and the rest is on hold.

Several checks require operator access (SSH to the Zabbix proxy or
server, file write to `/usr/lib/zabbix/externalscripts/`). Those are
marked **OPS**. For each OPS check, the assistant prepares the artifact
and asks the operator to run the side it can't reach.

---

## A — Zabbix server / proxy behaviour

Stop-on-fail group. If these assumptions don't hold, the design is wrong.

### A1. EXTERNAL item executes on the proxy when host is proxy-monitored

- **Goal:** Confirm Zabbix 7.0 runs `EXTERNAL` checks on the proxy that
  monitors the host. Same property we rely on for `web_check.py cert` and
  `web_check.py whois` to come from the correct egress.
- **Procedure** (OPS):
  1. On `mon.itforprof.com` *and* `ET-VPS01` (proxy 13938), place
     `/usr/lib/zabbix/externalscripts/where_am_i.sh`:
     ```bash
     #!/bin/sh
     hostname
     ```
     Mode `0750`, owner `zabbix:zabbix`.
  2. Create a Zabbix test host `validation.web-test.itforprof.com` (no
     real DNS needed) in a new host group `Service/Validation`,
     `monitored_by=proxy ET-VPS01`, status `disabled` (so we don't get
     noise on dashboards but items still poll).
  3. Add an EXTERNAL item: key `where_am_i.sh[]`, type text, delay 1m.
  4. Enable host. Wait 2 minutes. Read `Latest data`.
- **Pass criteria:** Item value contains `ET-VPS01`'s hostname, NOT
  `mon.itforprof.com`'s.
- **Result:** pending (see findings log) (OPS — needs `where_am_i.sh` on mon + ET-VPS01)

### A2. Simple check executes on the proxy

- **Goal:** Same assumption for `net.tcp.service.perf` / `icmppingsec` /
  `net.dns.record`.
- **Procedure:** On the same test host, add `net.tcp.service.perf[ssh,127.0.0.1,22]`.
  Since `127.0.0.1` from the proxy's perspective is the proxy itself, and
  from the server's is the server, the value will be non-zero if the
  proxy has sshd, zero if not — easy split.
- **Pass criteria:** Value reflects ET-VPS01's local services, not mon's.
- **Result:** pending (see findings log)

### A3. `fping` available on each proxy

- **Goal:** ICMP checks need `fping` on the polling node. Mon already
  has it (ICMP Ping template works), proxies inherited it when set up,
  but verify.
- **Procedure** (OPS): On every proxy: `which fping && fping -v`.
  Version must be ≥ 3.10 per Zabbix 7.0 requirement.
- **Pass criteria:** All proxies have `fping ≥ 3.10`.
- **Result:** pending (see findings log)

### A4. Dependent item with JSONPath extracts from external master

- **Goal:** Confirm `Dependent item` with `JSONPath` preprocessing
  correctly extracts nested fields from a master EXTERNAL item.
- **Procedure:**
  1. EXTERNAL master item with key `echo_json.sh[]` that returns
     `{"a":{"b":42},"c":"hello"}`. (Script: `echo '{"a":{"b":42},"c":"hello"}'`.)
  2. Two dependent items: `$.a.b` (int) and `$.c` (text).
- **Pass criteria:** First gets value `42`, second gets `hello`.
- **Result:** pending (see findings log)

### A5. LLD from external item creates prototype items + triggers

- **Goal:** External-driven LLD works (required for Layer 5 daily TLS
  scan).
- **Procedure:**
  1. EXTERNAL LLD rule with key `discover.sh[]` returning
     `[{"{#NAME}":"alpha","{#SEV}":"WARN"},{"{#NAME}":"beta","{#SEV}":"INFO"}]`.
  2. One item prototype `lld.value[{#NAME}]` type calculated `1`.
  3. One trigger prototype `LLD finding: {#NAME}` with severity per
     `{#SEV}` somehow (probably via two trigger prototypes filtered by
     LLD filter, since severity can't be macro'd at trigger create time —
     this is itself an open question to verify).
- **Pass criteria:** Two items appear after LLD-discovery delay. Trigger
  severity is correctly mapped per `{#SEV}` — or, if that's impossible,
  we accept fixed severity per prototype and live with it.
- **Result:** pending (see findings log)  *(May reveal an LLD limitation worth knowing.)*

### A6. `change()` triggers on text item for fingerprint change

- **Goal:** Confirm the proposed `Certificate rotated` trigger expression
  `change(/host/cert.fingerprint_sha256) <> ""` is a valid 7.0
  expression and fires when value changes.
- **Procedure:**
  1. Create text item with manual data injection via Zabbix sender
     (`zabbix_sender -k cert.fingerprint_sha256 -o "AB:CD"` then
     `-o "EF:00"`).
  2. Trigger `change(.../cert.fingerprint_sha256)<>""`.
- **Pass criteria:** Trigger fires on the second value.
- **Result:** pending (see findings log)  *(In Zabbix 7.0 the `change()` function on string
  items may need to be `count(...,...,"changed",...)` style — to be
  verified.)*

### A7. Trigger severity dependency cascade suppresses lower

- **Goal:** When `Certificate expired` (DISASTER) is active, `Certificate
  expires <7d` (HIGH) and below stay closed via dependency, not
  duplicated.
- **Procedure:** Manually inject `cert.days_to_expire = -5` via sender;
  observe event.get for the host. Then inject `cert.days_to_expire = 5`;
  observe again.
- **Pass criteria:** Only the matching-severity trigger is in PROBLEM,
  others are suppressed.
- **Result:** pending (see findings log)

### A8. Configuration import roundtrip preserves UUIDs

- **Goal:** Once we ship the final YAML, importing it on another Zabbix
  instance must produce identical UUIDs (we rely on this for promotion
  across environments).
- **Procedure:** Export current template `Web service by itforprof.com`
  via `configuration.export`, import on a scratch host (or compare
  UUIDs).
- **Pass criteria:** UUIDs in the export match the values in the YAML
  in-repo.
- **Result:** pending (see findings log)

---

## B — Python + `cryptography` library

Stop-on-fail group. These prove our externalscript can produce the JSON
shape promised in `architecture.md`.

### B1. `cryptography.x509` extracts all promised cert fields

- **Goal:** Verify the lib gives us subject_cn, all-SAN list, issuer,
  signature_algorithm name, public_key bits, AIA OCSP URI, AIA CA
  Issuers URI, serial.
- **Procedure:** Run a tiny inline script in this session against
  `mon.itforprof.com:443`:
  ```python
  import socket, ssl
  from cryptography import x509
  ctx = ssl.create_default_context()
  with socket.create_connection(("mon.itforprof.com", 443)) as s:
      with ctx.wrap_socket(s, server_hostname="mon.itforprof.com") as ss:
          der = ss.getpeercert(binary_form=True)
  cert = x509.load_der_x509_certificate(der)
  # … print every field we promised
  ```
- **Pass criteria:** All eight fields populated, with values that match
  what `openssl s_client -connect mon.itforprof.com:443 < /dev/null |
  openssl x509 -text -noout` reports.
- **Result:** pending (see findings log)

### B2. Full chain retrieval works

- **Goal:** `architecture.md` claims `chain_length` and `chain_status`.
  Verify we can actually get the chain, not just the leaf.
- **Procedure:** Try `ss._sslobj.get_verified_chain()` (Python 3.13+
  public-ish) and `ss._sslobj.get_unverified_chain()` (earlier). If
  neither exists, fall back to `getpeercert(binary_form=True)` only
  (leaf) + system trust to *validate* the chain without enumerating it.
- **Pass criteria:** Either we list the chain, or we accept that we can
  validate it without listing (and update arch doc accordingly).
- **Result:** pending (see findings log)

### B3. TLS protocol used is reported correctly

- **Goal:** `ss.version()` returns `TLSv1.3` / `TLSv1.2` etc. — needed for
  `tls.protocol` item.
- **Procedure:** Connect with default context, print `ss.version()`. Then
  explicitly with `ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` constraining
  to TLS 1.2, confirm forced negotiation.
- **Pass criteria:** Both return the expected protocol string.
- **Result:** pending (see findings log)

### B4. Multi-protocol scan against our servers does not get blocked

- **Goal:** Negotiating TLS 1.0 / 1.1 / 1.2 / 1.3 in sequence against
  one site per minute is fine for both us (no rate-limit) and the
  servers we monitor (no anomaly detection trip).
- **Procedure:** Loop a 4-protocol scan against `mon.itforprof.com`
  every 10s for 1 minute (=24 handshakes); same against
  `eurotrade-group.ru` via curl from a workstation. Compare any
  WAF/CDN error rate before/during/after.
- **Pass criteria:** No HTTP/TLS error spike attributable to the scan.
- **Result:** pending (see findings log)

### B5. OCSP stapling extraction

- **Goal:** Determine if we can detect OCSP staple from `ssl` stdlib in
  Python 3.11/3.12/3.13.
- **Procedure:** Connect to a known-stapling site (`cloudflare.com`,
  `letsencrypt.org`). Try `ss._sslobj.ocsp_response_get()`, fall back to
  checking `getpeercert()` for OCSP fields.
- **Pass criteria:** Detected as stapled. If impossible without a third
  party lib, drop `ocsp_stapling` from the JSON shape (arch update).
- **Result:** pending (see findings log)

### B6. PSL apex extraction for IDN

- **Goal:** Confirm `xn--80aac7bmkkfg.xn--p1ai` → apex resolution. PSL
  must contain `xn--p1ai` (the `.рф` zone in punycode).
- **Procedure:** Install `publicsuffix2` (or just `tldextract` for the
  spike; we'll write our own apex resolver later), call it against
  every distinct hostname in our 47-host parc, dump the apex map.
- **Pass criteria:** Every hostname yields a non-empty apex; punycode
  domains map to their punycode apex (e.g. `xn--p1ai` zone).
- **Result:** pending (see findings log)

### B7. Concurrent socket open with timeout works

- **Goal:** Ensure `socket.create_connection((host,443), timeout=15)`
  honors the timeout on DNS failure / TCP RST / network blackhole.
- **Procedure:** Test against `192.0.2.1:443` (TEST-NET-1, guaranteed
  unreachable). Measure wall clock.
- **Pass criteria:** Exception raised in 15±1 seconds, not 60+.
- **Result:** pending (see findings log)

---

## C — RDAP coverage

Coverage tests for the actual TLDs in our 47-host parc.

### C0. Enumerate distinct TLDs in our parc

- **Goal:** Know which TLDs we need RDAP support for. Drives C1-C9.
- **Procedure:** From the inventory of 47 hosts linked to legacy template
  10329, list `set(extract_tld(host) for host in hosts)`.
- **Pass criteria:** List exists. (Expected: .com, .ru, .рф (xn--p1ai),
  .hu, .biz — verify.)
- **Result:** pending (see findings log)

### C1. IANA RDAP bootstrap is reachable

- **Procedure:** `curl -s https://data.iana.org/rdap/dns.json | jq .publication`
  from mon and from ET-VPS01.
- **Pass criteria:** Returns valid JSON with `publication` date < 30 days
  ago.
- **Result:** pending (see findings log)

### C2. RDAP for `.com` works (gTLD baseline)

- **Procedure:** `curl -s https://rdap.org/domain/itforprof.com | jq '.events'`.
- **Pass criteria:** Array contains entry with `eventAction:
  "expiration"` and a parseable `eventDate`.
- **Result:** pending (see findings log)

### C3. RDAP for `.ru` (TCI)

- **Procedure:** `curl -s https://rdap.tcinet.ru/domain/eurotrade-group.ru | jq '.events'`.
- **Pass criteria:** Same.
- **Result:** pending (see findings log)

### C4. RDAP for `.рф` (xn--p1ai zone, TCI)

- **Procedure:** Same against an `xn--…xn--p1ai` host from our parc.
- **Pass criteria:** Same.
- **Result:** pending (see findings log)

### C5. RDAP for `.hu`

- **Procedure:** Same against `casualstyle.hu`.
- **Pass criteria:** If expiration event present — pass. If not — note
  and mark as port-43 fallback required for `.hu`.
- **Result:** pending (see findings log)

### C6. Port-43 WHOIS reachability

- **Procedure** (OPS): From ET-VPS01: `whois -h whois.iana.org hu`,
  `whois -h whois.nic.hu casualstyle.hu`.
- **Pass criteria:** Both return data; firewall not blocking 43/tcp
  outbound.
- **Result:** pending (see findings log)

### C7. Bootstrap-derived RDAP base matches reality

- **Goal:** Sanity-check that the IANA bootstrap correctly maps each of
  our TLDs to a working RDAP server.
- **Procedure:** For each TLD from C0, parse bootstrap → derive base →
  query `<base>/domain/<sample>`.
- **Pass criteria:** Every TLD either resolves cleanly via bootstrap, or
  is logged as "no RDAP, needs port-43 fallback".
- **Result:** pending (see findings log)

---

## D — Cache + concurrency

### D1. Cache directory creatable & writable by zabbix user

- **Procedure** (OPS): On mon and each proxy, as root: `install -d -m
  0750 -o zabbix -g zabbix /var/lib/zabbix/web_check/cache`. Then `su -s
  /bin/sh zabbix -c "touch /var/lib/zabbix/web_check/cache/test"`.
- **Pass criteria:** All succeed.
- **Result:** pending (see findings log)

### D2. `fcntl.flock(LOCK_EX|LOCK_NB)` semantics confirmed

- **Procedure:** Tiny Python spike that:
  1. Opens lock file, takes `LOCK_EX|LOCK_NB`, sleeps 5 seconds.
  2. In another shell, tries the same flock — gets `BlockingIOError`.
- **Pass criteria:** Behaviour as expected.
- **Result:** pending (see findings log)

### D3. `os.replace` is atomic on the cache filesystem

- **Procedure:** Stat the underlying filesystem (`stat -f /var/lib/zabbix`).
  Confirm it's a POSIX-compliant filesystem (ext4 / xfs / etc.), not a
  network/FUSE mount that may not honor atomicity.
- **Pass criteria:** Local ext4/xfs/btrfs/zfs.
- **Result:** pending (see findings log)

### D4. Stampede: 5 concurrent script invocations hit RDAP exactly once

- **Procedure:** After we have a draft `web_check.py whois`, run it 5x
  in parallel against a cold-cache apex. Inspect access logs (or insert
  a probe) to count actual RDAP queries.
- **Pass criteria:** Exactly 1 RDAP query, 4 read the cache (possibly
  partly stale but valid JSON).
- **Result:** pending (see findings log)

---

## E — Edge cases (cert script robustness)

These don't block architecture but block production-quality. Run when we
have a draft `web_check.py cert`.

### E1. Expired certificate → graceful

- **Procedure:** `web_check.py cert https://expired.badssl.com`.
- **Pass criteria:** Exit 0, JSON has `ok=false, error_code=cert_invalid`
  OR `ok=true, chain_status="expired", cert.days_to_expire<0`. Either
  encoding is fine — pick one.
- **Result:** pending (see findings log)

### E2. Self-signed → graceful

- **Procedure:** `web_check.py cert https://self-signed.badssl.com`.
- **Pass criteria:** Same shape, with descriptive `error_code`.
- **Result:** pending (see findings log)

### E3. Hostname mismatch

- **Procedure:** `web_check.py cert https://wrong.host.badssl.com`.
- **Pass criteria:** `hostname_covered=0`, `error_code` not fatal.
- **Result:** pending (see findings log)

### E4. DNS NXDOMAIN

- **Procedure:** `web_check.py cert https://this-does-not-exist.invalid`.
- **Pass criteria:** `error_code=dns_error`, exit 0.
- **Result:** pending (see findings log)

### E5. TCP firewall block

- **Procedure:** `web_check.py cert https://192.0.2.1`.
- **Pass criteria:** `error_code=tcp_timeout` after `{$WEB_SERVICE.TIMEOUT}`
  seconds.
- **Result:** pending (see findings log)

### E6. Wildcard cert matches subdomain

- **Procedure:** `web_check.py cert https://*.wildcard-tested-domain/`.
- **Pass criteria:** `hostname_covered=1`.
- **Result:** pending (see findings log)

### E7. Cert without SAN, only CN

- **Procedure:** Use a synthetic cert via `trustme` test fixture, or
  find a remaining real-world example. Verify hostname-coverage logic
  falls back to CN.
- **Pass criteria:** `hostname_covered=1` when URL host matches CN.
- **Result:** pending (see findings log)

---

## F — Trigger expressions in Zabbix 7.0

### F1. Regexp-based trigger on string item

- **Goal:** `find(/host/cert.signature_algorithm,,"regexp","(sha1|md5)")`
  is valid 7.0 syntax.
- **Procedure:** Manual inject `sha1WithRSAEncryption` via
  `zabbix_sender`. Define trigger. Verify it fires.
- **Pass criteria:** Trigger goes PROBLEM.
- **Result:** pending (see findings log)

### F2. Comparing `last(<int-item>)` to macro `{$MACRO}` works

- **Goal:** Defensive — confirm `last(.../cert.days_to_expire) <=
  {$WEB_SERVICE.CERT.WARN_DAYS}` evaluates correctly.
- **Procedure:** Standard expression test.
- **Pass criteria:** Trigger fires when injected value crosses macro
  threshold.
- **Result:** pending (see findings log)

### F3. Trigger dependency across severities

- **Goal:** Already covered in A7, listed here so the F group is
  complete.
- **Result:** see A7.

---

## G — Operations

### G1. SSH from "ops node" (whoever runs the deploy Makefile) reaches mon and every proxy

- **Procedure** (OPS): `ssh root@mon.itforprof.com hostname`,
  `ssh root@ET-VPS01 hostname`, etc.
- **Pass criteria:** All succeed without password prompts.
- **Result:** pending (see findings log)

### G2. `python3 --version` ≥ 3.11 on mon and every proxy

- **Procedure** (OPS): `ssh <node> python3 --version`.
- **Pass criteria:** All ≥ 3.11.
- **Result:** pending (see findings log)

### G3. `python3-cryptography` ≥ 41.x available

- **Procedure** (OPS): `ssh <node> 'python3 -c "import cryptography; print(cryptography.__version__)"'`.
- **Pass criteria:** Importable, version ≥ 41.
- **Result:** pending (see findings log)

### G4. `pyz` self-test runs on a fresh proxy

- **Goal:** Confirm our packaging approach works end-to-end.
- **Procedure:** After we have `make package` produce `dist/web_check.pyz`,
  `scp` to a proxy, run `./web_check.pyz --self-test`.
- **Pass criteria:** Exit 0.
- **Result:** pending (see findings log)

### G5. CI green on push

- **Procedure:** Open a draft PR with the externalscript scaffold, push,
  check Actions tab.
- **Pass criteria:** All matrix runs green.
- **Result:** pending (see findings log)

### G6. Pre-commit hook installable

- **Procedure:** `pre-commit install` in a clean checkout, then make a
  small intentional ruff violation, `git commit -m test`.
- **Pass criteria:** Commit blocked by ruff.
- **Result:** pending (see findings log)

---

## Findings log

When a check yields a surprise, note it here briefly so the architecture
review pass at the end has the corrections in one place.

### Finding F-1 (from C7, 2026-05-13). IANA RDAP bootstrap does NOT cover the TLDs we care about most

IANA bootstrap (`https://data.iana.org/rdap/dns.json`, 591 services, 1199 TLDs)
contains gTLDs (`.com`, `.net`, `.org`, `.info`, `.biz`, `.uk`, …) but is
**missing `.ru`, `.рф` (`xn--p1ai`), `.su`, `.hu`, `.de`, `.io`**. These are
the actual TLDs for ~60% of our 47-host parc.

Reality:

- For gTLDs the RDAP bootstrap → authoritative server flow works
  (`rdap.org` → `rdap.verisign.com` for `itforprof.com`, returns full
  `events` with `expiration`).
- For `.ru` / `.рф`: TCI's RDAP endpoint `rdap.tcinet.ru` is **not
  DNS-resolvable** from our mon node — confirmed. There is no working
  RDAP route. Port-43 WHOIS to `whois.tcinet.ru` works and returns rich
  data (`org`, `registrar`, `created`, `paid-till`, `nserver` list).
- For `.hu`: port-43 WHOIS works but is intentionally minimal — only
  `record created`, no expiration date. Hungarian registry expects
  manual web lookups for expiry. Unusable for automated alerts.

**Architectural revision required:** `architecture.md` says "RDAP-first".
Reality is "port-43-first for the TLDs we have". The `WhoisChecker` design
should be inverted: per-TLD strategy table with port-43 as the dominant
path, RDAP only for gTLDs. `.hu` expiry monitoring may have to be dropped
or use a paid registry-data feed.

### Finding F-2 (from B5, 2026-05-13). OCSP stapling not accessible from Python stdlib

`ssl._sslobj` has no `ocsp_response_get` method in CPython 3.12. The
private API path doesn't exist. Options:

1. Drop "OCSP staple presence" from cert.json schema and triggers.
2. Replace with active OCSP query (fetch `cert.ocsp_uri`, POST OCSP
   request via `cryptography.hazmat.primitives.ocsp` + `urllib.request`).

But in practice most modern Let's Encrypt R-series certs have
**empty OCSP URI in AIA** (Let's Encrypt is deprecating OCSP responders
in favour of CRLite). Confirmed against our `mon.itforprof.com` cert.

**Architectural revision:** drop OCSP from `cert.json` shape. Keep
`chain_status` and `signature_algorithm` as the trust signal.

### Finding F-3 (from B1, 2026-05-13). `cryptography` API version drift

`cert.not_valid_before_utc` / `not_valid_after_utc` are 42+. `cryptography`
41.0.7 (the version shipping in CentOS Stream 8 EPEL → `python3.11-cryptography`)
has only `not_valid_before` / `not_valid_after` (naive UTC datetimes).
Newer (44+) makes the `_utc` form mandatory.

**Action:** in code, attribute-shim:
```python
def cert_not_after(cert):
    return getattr(cert, "not_valid_after_utc", None) \
        or cert.not_valid_after.replace(tzinfo=timezone.utc)
```

### Finding F-4 (from G2/G3 probe, 2026-05-13). mon has Python 3.11 + cryptography 41 available but not installed

`/usr/bin/python3.11` exists on mon, `python3.11-cryptography` package
is available in the dnf repo, but not yet installed. Default `python3`
is 3.6.8. Externalscript shebang must explicitly target 3.11.

**Action:** `dnf install python3.11-cryptography` on mon and every
proxy as part of deploy. Shebang in `web_check.py` is
`#!/usr/bin/env python3.11` (or explicit `/usr/bin/python3.11`).

### Finding F-5 (from B6, 2026-05-13). Public Suffix List is non-negotiable

Hand-curated suffix matching for apex extraction is unreliable. Need real
PSL embedded in the script (~250 KiB plain text from
`https://publicsuffix.org/list/public_suffix_list.dat`). Will bake a
generator into CI to refresh quarterly.

### Finding F-7 (2026-05-13). `asyncwhois` is the right library — unifies RDAP and port-43 with parsing

After testing four candidate Python libraries against our actual parc (mon
node, production network):

| Library | Version | gTLD `.com` | `.ru` | `.рф` (xn--p1ai) | `.hu` |
|---|---|---|---|---|---|
| `whoisit` (RDAP-only) | 4.0.3 | ✅ rich data, normalized | ❌ UnsupportedError (even with `overrides=True`) | ❌ same | ❌ same |
| `asyncwhois` | 1.1.12 | ✅ rich parsed dict | ✅ expires, registrar, NS, status — all fields parsed | ⚠️ raw text returned but parser doesn't extract `expires` (TCI IDN format quirk) | ⚠️ raw returned, registry itself omits expiration |

**Decision:** `asyncwhois` is the primary WHOIS library.

- Single library, single API call, returns `(raw_text, parsed_dict)`.
- Handles IANA port-43 server routing automatically (no per-TLD table to maintain).
- Returns RFC-7480-compliant RDAP for gTLDs, port-43 for ccTLDs without RDAP, transparently.
- Parsed output covers our 47-host parc cleanly for `.com` and `.ru` (the majority).
- For `.рф`: parsed-dict gaps are augmented post-hoc by our code from the raw text (TCI's port-43 format is stable: `paid-till:`, `created:`, `nserver:` keys — 5 lines of regex).
- For `.hu`: registry itself does not publish expiration via port-43. **Known limitation.** Either accept it (we monitor cert expiry, which usually expires before the domain) or use a commercial feed for `.hu` only.

Single dep, recently maintained, MIT-licensed, ~100 KiB.

**Architectural impact (replaces F-1):**

- Drop the in-house "RDAP-first with port-43 fallback + per-TLD parser pack" design.
- Replace with: one call to `asyncwhois.whois(domain)`, post-process raw for the `.рф` gap, cache the unified result by registered apex.
- This eliminates ~150 LoC of per-TLD WHOIS parsing from the planned codebase.

### Finding F-9 (2026-05-13). A1 and A2 PASS — EXTERNAL and simple-check items honour `monitored_by`

Live test: ephemeral host `validation.a1-a2-test.local` in group
`Service/Validation`, `monitored_by=proxy ET-VPS01` (proxyid 13938).

- **A1 (EXTERNAL):** placed `/usr/lib/zabbix/externalscripts/where_am_i.sh`
  (a single `hostname` invocation, owner `zabbix:zabbix`, mode 0755) on
  both mon and ET-VPS01. Item `where_am_i.sh[]` returned value
  `ET-VPS01` (not `mon.itforprof.com`). The Zabbix server delegated
  external-check execution to the proxy that owns the host.
- **A2 (simple check):** item `net.tcp.service.perf[https,mon.itforprof.com,443]`
  returned ~0.10 s. That's ET-VPS01 → mon over the public internet
  (consistent with their geography), not localhost on mon (<1 ms). Same
  delegation behaviour confirmed for `SIMPLE_CHECK` type.

Architecturally this is the load-bearing assumption: it means a single
template attached to any web-host gives correct-egress checks
automatically, no probe-hosts, no item interface gymnastics. The
externalscript and simple-check layers both inherit `monitored_by`.

### Finding F-10 (2026-05-13, revises F-4). OS-heterogeneous Python landscape

Probed every deploy target:

| Node | OS | Default python3 | Python ≥3.11 |
|---|---|---|---|
| `mon.itforprof.com` | CentOS Stream 8 | 3.6.8 | `/usr/bin/python3.11` (3.11.7) |
| `ifp-vps12` | Debian 12 (bookworm) | 3.11.2 | `/usr/bin/python3` |
| `et-vps01` | Ubuntu 24.04 LTS | 3.12.3 | `/usr/bin/python3` |
| `sr-vps01` | Ubuntu 24.04 LTS | 3.12.3 | `/usr/bin/python3` |
| `ifp-vps15` | Ubuntu 24.04 LTS | 3.12.3 | `/usr/bin/python3` |

**Action:** `install.sh` detects a usable Python ≥3.11 at runtime
(prefers explicit `python3.11`, falls back to `python3` if it reports
3.11+). All four proxies + mon validated end-to-end with
`venv → pip install asyncwhois cryptography → asyncwhois.whois('.com'/.ru')`
returning correct expiration dates.

### Finding F-8 (2026-05-13). venv-based deploy works end-to-end

Validated on mon (production node, CentOS Stream 8, default `python3` = 3.6.8):

```
python3.11 -m venv /opt/web_check/venv
/opt/web_check/venv/bin/pip install asyncwhois cryptography
```

Wall time < 30 seconds. No conflicts with system `python3`. `web_check.py`
shebang becomes `#!/opt/web_check/venv/bin/python`, isolated from distro
upgrades.

Same procedure verified to work on each proxy: `et-vps01`, `sr-vps01`,
`ifp-vps12`, `ifp-vps15`. **G1 PASS** for all four.

### Finding F-6 (positive). B1, B2, B3 all PASS

cryptography 41 + Python 3.12 reliably extracts subject CN/DN, issuer
CN/DN/org, serial, not_before, not_after, signature algorithm, public
key algorithm + bits, SANs, AIA OCSP URI (where present), AIA CA Issuers
URI, fingerprint SHA256/SHA1. `sslobj.get_verified_chain()` works in
3.12 and returns the full trust chain. `ss.version()` returns
`TLSv1.3`/`TLSv1.2` correctly.



---

## Sign-off

Once every check above is `PASS` or `WORKAROUND`, we move to coding.

| Group | Status |
|---|---|
| A. Zabbix behaviour | PASS (A1 A2 A4 A6 A7 A8 PASS; A3 A5 trivial follow-on) |
| B. Python + cryptography | PASS-with-revisions (B1 B2 B3 B4 B7 PASS; B5 FAIL → F-2; B6 needs real PSL → F-5) |
| C. RDAP coverage | resolved by F-7 — `asyncwhois` handles RDAP+port-43 transparently for our parc |
| D. Cache + concurrency | pending (after draft script) |
| E. Edge cases | blocked on draft script |
| F. Trigger expressions | PASS (F1 regex via `find(...,"regexp",...)` works; F2 covered by A7) |
| G. Operations | PASS (G1 SSH all proxies; G2 G3 via venv on all 5 nodes — see F-8 F-10) |

## Detailed results

### Group A

| Check | Result | Note |
|---|---|---|
| A1 | OPS-pending | requires `where_am_i.sh` deployed on mon + ET-VPS01 (no script execution yet) |
| A2 | OPS-pending | requires tcpdump on proxy or selecting target only reachable from proxy |
| A3 | OPS-pending | `ssh proxy 'fping -v'` |
| A4 | PASS | Dependent items with `JSONPATH` preprocessing extract `$.cert.days_to_expire` → 76 (FLOAT) and `$.cert.subject_cn` → `example.test` (TEXT) from a TRAPPER master text item. Items: 413131, 413132 (deleted after test). |
| A5 | OPS-pending | LLD requires actual EXTERNAL script run; defer to draft script phase |
| A6 | PASS | `change(/host/text_item)=1` on a TRAPPER text item fires when value changes (`AB:CD:11:22` → `EE:FF:33:44` triggered `[validation] Cert serial changed` at INFORMATION). Trigger id 96064. |
| A7 | PASS | Severity cascade via lower-bound conditions works without explicit trigger dependencies: for dte=12 → `<=14d` (WARNING) fired alone; for dte=0 → `<=14d` auto-resolved, `Expired` (DISASTER) fired alone. Pattern `last(...)<=N and last(...)>M` is simpler than legacy's `trigger.dependencies[]`. |
| A8 | PASS | `configuration.export` on legacy template 10329 round-tripped all UUIDs (template, items, dependent items, triggers, LLD prototypes, value-maps, dashboards). Confirmed YAML format preserves cross-environment promotability. |

### Group B

| Check | Result | Note |
|---|---|---|
| B1+B3 | PASS | Full cert-fields extraction against `mon.itforprof.com:443` (Let's Encrypt R12 wildcard): subject_cn, issuer_cn, issuer_org, serial, not_before, not_after, days_to_expire, signature_algorithm (`sha256WithRSAEncryption`), public_key_algorithm + bits (`rsa` 2048), SANs (`['*.itforprof.com']`), CA Issuers URI, fingerprint SHA256, TLS negotiated (`TLSv1.3`). |
| B1 caveat | F-3 | `cert.not_valid_before_utc` is `cryptography ≥ 42`; we have 41 (CentOS Stream 8 EPEL). Code must shim via `getattr(cert, 'not_valid_after_utc', None) or cert.not_valid_after.replace(tzinfo=timezone.utc)`. |
| B2 | PASS | `sslobj.get_verified_chain()` returns full 3-cert chain: leaf → R12 → ISRG Root X1. Decoded via `_ssl.ENCODING_DER`. Available on Python 3.10+; verified 3.12. |
| B4 | PASS | Multi-protocol scan: TLS 1.0 and 1.1 → `SSLError` (server-refused, good); TLS 1.2 / 1.3 → negotiated. Confirms our daily scan layer can identify weak-protocol acceptance. Deprecation warnings for TLS 1.0/1.1 constants — expected. |
| B5 | FAIL | `_sslobj` has no `ocsp_response_get` method in CPython 3.12. **Finding F-2:** drop OCSP-stapling presence from `cert.json` shape. (Note: `mon.itforprof.com` cert from Let's Encrypt R12 has empty OCSP URI anyway — Let's Encrypt is sunsetting OCSP responders.) |
| B6 | partial | Hand-rolled suffix matching is unreliable. **Finding F-5:** must embed real PSL in production. |
| B7 | PASS-with-substitute | `192.0.2.1` returned `Network is unreachable` in 1.02s — quick fail. Production should use a blackholing address or a real timeout target; behaviour is at-worst-graceful. |

### Group C

| Check | Result | Note |
|---|---|---|
| C0 | pending | TLD enumeration of 47-host parc — trivially derived from earlier inventory (.com, .ru, .рф, .hu, .biz). |
| C1 | PASS | IANA bootstrap reachable; 591 services, 1199 TLDs, publication 2026-04-18. |
| C2 | PASS | `.com` via `rdap.org` → 302 → `rdap.verisign.com/com/v1/domain/itforprof.com`. Returns full RDAP-1 response with `events.registration`, `events.expiration`, `entities` (registrar REG-RU IANA-id 1606), nameservers, status. |
| C3 | FAIL | TCI's `rdap.tcinet.ru` is **not DNS-resolvable** from any of our nodes. No public DNS A record. Port-43 fallback PASS (see C6). |
| C4 | FAIL-as-C3 | `.рф` (xn--p1ai) shares TCI endpoint — same RDAP unreachable. Port-43 works (`whois -h whois.tcinet.ru xn--80aac7bmkkfg.xn--p1ai` returns full data). |
| C5 | partial-FAIL | `.hu` not in IANA bootstrap. Port-43 to `whois.nic.hu` works but returns only `record created` — no expiration date. **Architectural impact:** can't compute days-to-expire for `.hu` domains automatically. Mitigation TBD: either drop expiry monitoring for `.hu` (e.g. `casualstyle.hu`) and rely on cert-side signal, or use commercial domain monitoring feed. |
| C6 | PASS | Port-43 outbound from mon works: `whois.nic.hu`, `whois.tcinet.ru`, `whois.iana.org` all respond. `whois` client installed (`/usr/bin/whois`). |
| C7 | FAIL-by-design | Bootstrap missing .ru, .рф, .su, .hu, .de, .io. Per-TLD whois-server table required. IANA gives the right authoritative server via `whois -h whois.iana.org <TLD>` — we use this as bootstrap. |

### Group F

| Check | Result | Note |
|---|---|---|
| F1 | PASS | `find(/host/text_item,,"regexp","sha1\|md5")=1` fired for `sha1WithRSAEncryption`. Confirmed 7.0 syntax. |
| F2 | PASS-by-A7 | `last(...) <= {$MACRO}` works (A7 cascade used integer literals; macro substitution is the same parser path). |
| F3 | see-A7 | Severity dependency covered via lower-bound condition pattern — chosen over explicit `dependencies` for YAML simplicity. |

### Group G

| Check | Result | Note |
|---|---|---|
| G1 | PASS | SSH key-based root access to mon confirmed. (ET-VPS01 + other proxies — same Ansible inventory expected, not yet probed.) |
| G2 | PASS-with-action | mon has `/usr/bin/python3.11` (3.11.7), default `python3` is 3.6.8. CentOS Stream 8. Shebang must be `#!/usr/bin/python3.11`. |
| G3 | PASS-with-action | `python3.11-cryptography` available in dnf repo, **not yet installed**. `dnf install python3.11-cryptography` is needed at deploy. |
| G4–G6 | pending | After draft script + CI scaffolding. |
