# Changelog

All notable changes to this project will be documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning per template
is documented in [README.md](README.md#versioning).

## [7.0-2.2.2 / web_check 2.1.4] - 2026-05-17

### web_check.py 2.1.4 — silence tldextract cache-write warning leaking into the WHOIS JSON envelope
- **Fix:** `TLDExtract` is now constructed with `cache_dir=None`. Previously,
  even though `suffix_list_urls=()` disabled the network fetch, tldextract's
  `DiskCache` still attempted to write the parsed PSL into
  `$HOME/.cache/python-tldextract/`. The zabbix user's `$HOME`
  (`/var/lib/zabbix/`) is root-owned with no writable `.cache/`, so
  tldextract emitted a `[Errno 13] Permission denied` warning via the
  stdlib `logging` module (logger `tldextract.cache`, default destination
  stderr). In our deployment the Zabbix externalscript handler captured
  stderr alongside stdout into the master item's lastvalue — the JSON
  payload arrived with a multi-line warning prefix, and every dependent
  JSONPath-preprocessed WHOIS item failed to parse. Registrar /
  days_to_expire / NS-list items showed as unsupported across all
  monitored web hosts.
- Disabling the disk cache is safe here: the on-disk cache only memoised
  the parsed PSL across processes; with `suffix_list_urls=()` there is
  nothing remote to memoise, and re-parsing the bundled snapshot per
  externalscript invocation is negligible. The snapshot is loaded
  in-memory from the wheel on the first call and memoised on the
  extractor for the lifetime of the process.
- New regression test `tests/test_apex.py::test_psl_extractor_cache_disabled`
  asserts (a) the extractor's `DiskCache.enabled` is False and (b)
  resolving an apex emits nothing on stdout or stderr. Future maintainers
  who drop `cache_dir=None` will fail this test.
- No installer change required — the fix is fully contained in the script,
  surviving any future change to the zabbix user's home directory layout.
- The comment block around `_PSL_EXTRACTOR` now documents BOTH tldextract
  default-behavior hazards (network fetch AND cache write) so the next
  maintainer doesn't reintroduce the trap.
- `docs/architecture.md` status banner version reference bumped to match.

### Known follow-up
- `asyncwhois.whois(apex)` (called in `_query_whois`) constructs its own
  internal `TLDExtract()` with library defaults if no `tldextract_obj=` is
  passed — i.e. exactly the bug we just fixed, latent. Threading our
  `_PSL_EXTRACTOR` through to asyncwhois retires the bug class locally.
  Tracked separately; not blocking this release because the observed
  field corruption was from our own extractor call, not asyncwhois's.

## [7.0-2.2.2 / web_check 2.1.3] - 2026-05-14

Initial public release. Cumulative changelog of all in-tree work prior
to the public cut is preserved below for context.

### Template 7.0-2.2.2 — manual_close on all expiry triggers
- All 8 expiry-tier triggers (4 WHOIS tiers — expired / CRIT / NOTICE /
  WARN — and 4 TLS cert tiers) now have `manual_close: YES`. Lets admins
  suppress an open expiry problem during a planned renewal without
  waiting for the natural state change.
- Stale event_name text from earlier template revisions no longer stays
  on screen indefinitely.

### Template 7.0-2.2.1 — from→to event_name for change-detection triggers
- "Registrar changed" and "Name servers changed" event_names now show
  both the previous and the new value, using Zabbix 7.0 expression macro
  `{?last(.../web_check.whois.registrar,#2)}`.
- DNSSEC trigger already informative ("went unsigned") — unchanged.

### web_check.py 2.1.3 — typing-consistency follow-ups (review nits)
- **`_cert_attr_utc` symmetry.** Both branches now use the same typed-local
  pattern (`val_utc: datetime = getattr(...)` / `val: datetime = getattr(...)`)
  instead of one branch carrying a `# type: ignore[no-any-return]`. No
  suppression, no behavior change.
- **`_first` no longer coerces `str(v)`.** Reverted to `return …value` with
  `-> Any` return type. The 2.1.2 refactor accidentally turned a bytes-valued
  attribute (theoretical, not seen in practice for CN/SAN) into its `"b'…'"`
  repr; the only call sites read string attributes, so no live regression —
  but the "hygiene only" promise demands a clean revert.

### web_check.py 2.1.2 — strict-typing + ergonomic polish (third review pass)
- **`mypy --strict` clean.** Added explicit `Any` annotations on functions
  that handle untyped 3rd-party objects (`_cert_attr_utc`, `_first`, `iso`,
  `lock`, `chain`), plus `# type: ignore[import-untyped]` for asyncwhois.
  CI's `typecheck` job upgraded from `--ignore-missing-imports` to
  `--strict --ignore-missing-imports` to keep this clean across PRs.
- **Narrowed DeprecationWarning filter.** Was: a blanket
  `filterwarnings("ignore", category=DeprecationWarning)` that would
  silence warnings from asyncwhois / aioquic / cryptography future-removals
  too. Now: `module=r"web_check.*"` — only our own TLSv1.0/1.1 probes are
  silenced; dependency-deprecation warnings still surface during
  `self-test` and in CI.
- **`_alt_svc_advertises_h3` socket-leak guard.** Wrapped the
  `HTTPSConnection` in `try/finally + suppress(Exception)` so a mid-handshake
  exception cannot leak the fd on long-lived callers.
- **`registered_apex` now raises `ImportError`** instead of silently returning
  `None` when `tldextract` is missing. `check_whois` and `cmd_self_test`
  catch and emit a `missing_dependency` envelope — clearer than the
  ambiguous `apex_unresolved`.
- **`cert_untrusted` semantics documented inline.** Spells out why
  `res.ok` stays True when the chain is untrusted (so the script-failure
  trigger doesn't double-alert against the dedicated chain-untrusted
  trigger).
- **Operator-precedence parens** in `_normalize_whois` no-expiry
  expression (`a or (b and c)`) for clarity.

### web_check.py 2.1.1 + migration script hardening (second deep-review pass)
- **`tldextract` now offline-only.** Was: default `tldextract.extract()`
  which fetches the Public Suffix List from publicsuffix.org on first
  use — a network call per Zabbix-server restart, under `zabbix:zabbix`
  whose `$HOME` is often unwritable. Fix: module-level extractor with
  `suffix_list_urls=()` and `fallback_to_snapshot=True`. Architecture
  doc claimed offline behavior; this commit makes the code match.
- **`_query_whois` capped at 10 s wall-time.** Was: 30 + 60 + 120 = 210 s
  worth of post-failure sleeps. Zabbix externalscript timeout is typically
  3-30 s, so a 210 s sleep means SIGKILL mid-sleep + no negative-cache
  written + held poller slot. Now: hard 10 s budget across all attempts,
  no sleep after the final failure, backoffs reduced to 0.5 s / 1.5 s.
- **`derive_host_macro` returns A-labels for IDN URLs.** Was:
  `http://тамбурато.рф → тамбурато.рф` (U-label). Now:
  `http://тамбурато.рф → xn--80aac7bmkkfg.xn--p1ai`. Matters because
  `{$WEB_SERVICE.HOST}` flows into `net.tcp.service.perf[https,...,443]`
  whose IDNA handling is implementation-defined across glibc / Zabbix
  versions. ASCII hosts unchanged.
- **Migration script divergence warnings.** When a host has BOTH the
  legacy `{$WEBSITE_METRICS_*}` macro AND the corresponding
  `{$WEB_SERVICE.*}` macro set to DIFFERENT values, the script now emits
  a `WARN:` line in the plan output before the action list, so the
  operator sees the override before applying.
- **`docs/architecture.md` "Apex deduplication algorithm" reconciled
  with the code**: corrected cache directory path
  (`/var/lib/zabbix/web_check/cache/` → `/opt/web_check/data/cache/`),
  PSL bundling wording (we don't bundle PSL in the script — we use the
  one shipped with `tldextract`), stampede protection (we don't retry on
  lock contention, we serve current cache immediately), and
  schema-version invalidation (read but not currently enforced).
- **New test file `scripts/tests/test_migration.py`** with 10 parametrized
  cases for `derive_host_macro` (ASCII, IDN, schemes, edge cases) +
  invariant checks on `MACRO_MAP` and `OLD_TEMPLATE_NAME`. Total tests:
  58 → 68.
- **web_check.py 2.1.0 → 2.1.1.** Patch version; no schema changes.

### Code-review follow-ups (post-`f0c7ea8`)
- **Critical fix**: WHOIS expiry tier triggers (CRIT/NOTICE/WARN) had
  `{ITEM.LASTVALUE3}` on the `apex` Zabbix tag and in trigger descriptions,
  but `LASTVALUE3` resolves to the second `days_to_expire` reference (a
  number like "12"), not the apex string. Patched to `{ITEM.LASTVALUE4}`
  (apex is the 4th `last()` reference in these expressions). The
  "Domain expired" trigger correctly uses `LASTVALUE3` — only 3 refs total.
  Without this fix, the apex-tag-based dedup the Telegram bot relies on
  was deduping by integer day counts on 3 of 4 tiers.
- **`CUSTOM_ERROR` behavior clarified**: confirmed live that
  `CUSTOM_ERROR` replaces the *error message* but state still transitions
  to NOT_SUPPORTED on every failure. The post-disable+enable observation
  of "state=OK" was transient. Decision: keep `CUSTOM_ERROR`. The
  alternatives (`CUSTOM_VALUE` with sentinel or empty string) would
  trigger false positives: e.g., `cert.days_to_expire` is FLOAT, a
  sentinel `-1` fires the "Cert expired" trigger (`last()<0`) on every
  HTTP-only host. Clean error TEXT is the right UX improvement here;
  NOT_SUPPORTED state is correct signal that data is unavailable.
- **TCP-slow window**: `avg(...,10m)` → `avg(...,30m)` (6 samples instead
  of 2 at the 5m DIAG.CHECK.INTERVAL). 2-sample averaging risked flapping
  on single network blips on intercontinental paths.
- **TCP-slow redundant clause**: dropped `... and avg(...) > 0` (since
  the primary threshold `>{$WEB_SERVICE.TCP.SLOW_SEC}=3` already implies >0).
- **Trailing whitespace**: collapsed multi-line expression in
  `Domain DNSSEC removed` to a single line — prevents Zabbix-side
  normalization causing dirty-diff on re-export.
- **Doc drift fixed**:
  - `docs/architecture.md`: dropped 8 stale ICMP references (item table,
    trigger taxonomy, macros catalog, system overview ASCII), corrected
    host count `47 → 59` (migration completed 2026-05-14).
  - Top-level `README.md` (RU) and `README_EN.md`: version block bumped
    `7.0-2.1.0 → 7.0-2.2.0`, "5-layer" → "6-layer", Mermaid diagram's
    Layer-4 box and arrow no longer mention ICMP, dropped `fping`
    requirement line, added HTTP/3 to intro feature lists. Bump rules
    table updated to reflect the new baseline version.
  - `templates/web-service-by-itforprof/README.md`: `TCP.SLOW_SEC` table
    row bumped `1 → 3`. Template description in YAML now says
    "Network diagnostics — native simple checks (TCP)" instead of
    "(DNS / TCP / ICMP)". The `{$WEB_SERVICE.HOST}` macro description
    no longer mentions `icmpping`.

### v7.0-2.2.0 (continued) — trigger informativeness + ICMP removal + group move
- **Removed ICMP layer.** This template is now HTTP/HTTPS-only per scope; the
  `icmppingsec` + `icmppingloss` simple-check items and their `Avg RTT high` /
  `Packet loss` triggers were dropped, along with the
  `{$WEB_SERVICE.PING.HIGH_RTT_SEC}` and `{$WEB_SERVICE.PING.LOSS_PCT}` macros.
  TCP/443 + TCP/80 net.tcp.service.perf checks stay (they're HTTP-relevant).
- **Every trigger now has an informative event_name** with the monitored
  URL + host. 10 triggers that had no event_name got one; 5 that had a value
  but no host context got fixed. Pattern: "<what> — {$WEB_SERVICE.URL} on
  {HOST.HOST}". WHOIS expiry triggers retain the apex via {ITEM.LASTVALUE3}.
- **Added `url={$WEB_SERVICE.URL}` Zabbix tag to every trigger** for
  notification routing / dedup. Combined with the existing `scope=...` tag
  and the WHOIS-only `apex=...` tag, alert bots can group by URL/apex/layer.
- **`manual_close: YES`** added to 8 informational change-detection triggers
  that don't auto-recover cleanly: Cert rotated, Cert rotated unexpectedly,
  Cert check failing, WHOIS check failing, HTTP/3 check failing, Domain
  registrar/NS/DNSSEC changed.
- **Template group moved**: `Templates/Custom` → `Templates/Applications`
  (the Zabbix-shipped standard group, uuid `bd327ca2dab24c4aa6ba757655aa052f`).
  Reflects that this is an application monitoring template, not a one-off.
- Final counts: **41 items, 32 triggers + 1 LLD trigger prototype, 27 macros,
  1 valuemap.**

### v7.0-2.2.0 — informative WHOIS alerts + comprehensive trigger dependencies
- **WHOIS expiry severity remap** at user request:
  - 30d = WARNING (was HIGH), 7d = AVERAGE (was DISASTER), 1d = HIGH,
    expired = DISASTER. Macros remapped: `{$WEB_SERVICE.WHOIS.WARN_DAYS}`
    60→30, `{$WEB_SERVICE.WHOIS.NOTICE_DAYS}` 30→7,
    `{$WEB_SERVICE.WHOIS.CRIT_DAYS}` 7→1.
- **Informative event names** for WHOIS expiry triggers — now embed the
  apex domain via `{ITEM.LASTVALUE3}` (referenced through
  `length(last(.../web_check.whois.apex))>0` in the trigger expression,
  so first-fire `*UNKNOWN*` is impossible). Example:
  `Domain searegion.com expires in 28d (host: docs.searegion.com)`.
- **Apex tag** added to every WHOIS expiry trigger: `apex={ITEM.LASTVALUE3}`.
  Alert routing can dedup multiple hosts on the same apex.
- **New item**: `web_check.whois.apex` (CHAR) — extracts the registered
  apex from the master JSON. Referenced by triggers; also available for
  dashboards.
- **Trigger dependency cascades** (user-requested: "all triggers must
  have dependencies"). Every trigger that can be suppressed by another now
  declares the parent in `dependencies`. 32 of 35 triggers gained deps; 6
  top-level "no data received" / "TCP 443 connect failed" triggers
  intentionally have none. Pattern: nodata → check-failing → expired →
  N-day tiers (CERT, WHOIS, HTTP/3 layers).
- **Diag triggers** `TCP 443 connect failed/slow`, `Avg RTT high`,
  `Packet loss` gained `event_name` fields that include the monitored host
  via `{$WEB_SERVICE.HOST}` — previously they only printed the value.
- Cleaned up 4 orphan template triggers (pre-rework legacy expiry
  triggers) that survived the import due to dependency back-references.

### Attribution & license clarity (2026-05-14, post-cutover)
- LICENSE rewritten: copyright **Konstantin Tyutyunnik (https://itforprof.com)
  2025-2026**, plus a short attribution paragraph clarifying that this
  project supersedes itmicus's `Template Website metrics (itmicus.ru)`,
  defines the same problem domain, but copies **no code** — only macro
  names, and only via the migration script.
- SPDX headers (`# SPDX-License-Identifier: MIT` + copyright line) added
  to all original source files: `scripts/externalscripts/web_check.py`,
  `scripts/migrate-from-itmicus.py`, `scripts/_zabbix_client.py`,
  `scripts/deploy/install.sh`.
- README.md (Russian) + README_EN.md gained "Credits" and "Migration from
  itmicus" sections with the script's typical invocations spelled out.
- Template README footer now carries an explicit Credits paragraph + MIT
  copyright line.
- Template YAML `description:` block updated: bumped to "Six layers" (Layer 6
  HTTP/3 added in v7.0-2.1.0), added a Credits paragraph crediting itmicus,
  expanded License line to "MIT (c) 2025-2026 Konstantin Tyutyunnik". Live
  in production via configuration.import.

### Migration completed (2026-05-14)
- All 59 previously-`Template Website metrics (itmicus.ru)`-monitored hosts
  migrated to `Web service by itforprof.com` v7.0-2.1.0. Legacy template
  deleted from the production Zabbix server (templateid 10329).
- Legacy externalscripts (`website_metrics.py`, `website_metrics.py.bak`,
  `website_metrics.py.good`, `test_website_metrics.py`, `website_settings.py`)
  archived to `/var/backups/zabbix-legacy-2026-05-14/` on each of the 5
  monitor nodes (mon + 4 proxies), then removed from
  `/usr/lib/zabbix/externalscripts/`.
- Legacy template YAML captured under
  `docs/archive/template_website_metrics_itmicus_legacy.yaml` for forensics.
- Pilot bugs uncovered + fixed during the rollout: install.sh idempotency
  (b24d5d5/eb40a06), Zabbix 7.0 YAML schema (8efd7bc), migrate-script host
  filter (d9c675e), DeprecationWarning + http-URL cert handling + DNS-item
  drop (73a77dc), pruned stray dep (f2181bf), case-insensitive phrase
  default (580bf3c), informative event_name (e6282b6), Layer 6 (f2e1b1e),
  uuid4 + docs (2fd41f2).

### Added (v7.0-2.1.0)
- **Layer 6 — HTTP/3 / QUIC.** New `web_check.py http3` subcommand uses
  `aioquic` to verify Alt-Svc h3 advertisement and perform a real QUIC
  TLS-1.3 handshake. Silent by design on hosts that don't advertise h3
  (the common case for stock nginx). Catches "advertised but unreachable"
  failures — typically UDP/443 dropped on the path or CDN QUIC regression.
- 7 new template items (master + 6 dependents: alt_svc_advertised,
  reachable, handshake_ms, alpn, quic_version, check ok), 4 new triggers
  (advertised-but-unreachable HIGH, slow WARNING, check failing INFO,
  nodata AVERAGE), 3 new macros (`{$WEB_SERVICE.HTTP3.CHECK.INTERVAL}`,
  `.TIMEOUT`, `.SLOW_MS`).
- Pre-flight validation: probed UDP/443 + QUIC handshake against
  cloudflare.com / google.com from all 5 monitor nodes — egress is
  open everywhere (27–172 ms handshake latency depending on path).
- web_check.py bumped 2.0.1 → 2.1.0. aioquic 1.3.0 pinned in
  requirements.lock.

### Added (v7.0-2.0.0)
- **`Web service by itforprof.com`** v7.0-2.0.0 — full 5-layer template
  (118 → ~1090 lines). 39 items, 32 triggers, LLD per weak TLS finding.
  - Layer 1 (HTTP availability) — native Zabbix Web Scenario, kept from v1.
  - Layer 2 (TLS + cert) — EXTERNAL `web_check.py cert` master + ~13 dependents
    (chain status, hostname coverage, public key, SHA-256 fingerprint, rotation
    detection, weak-signature trigger via `find(...,"regexp","sha1|md5")`).
  - Layer 3 (Domain WHOIS) — EXTERNAL `web_check.py whois` (apex-deduped via
    24h FS cache, asyncwhois RDAP+port-43, TCI augmenter for `.рф`). `.hu`
    expiry triggers gated on `provider_no_expiry`.
  - Layer 4 (Network diagnostics) — native simple checks: `net.dns.record`
    A/AAAA/CAA, `net.tcp.service.perf` https/http, `icmppingsec`, `icmppingloss`.
  - Layer 5 (Deep TLS scan, daily) — EXTERNAL `web_check.py tls-scan` matrix +
    LLD rule (`{#TLS_FINDING}`/`.CATEGORY`/`.SEVERITY`) with item/trigger
    prototypes per finding.
  - 26 macros (full catalog in [template README](templates/web-service-by-itforprof/README.md)).
  - NODATA triggers on web scenario + each EXTERNAL master.
- **`scripts/externalscripts/web_check.py`** v2.0.0 (single-file deploy,
  ~970 lines) — replaces legacy `website_metrics.py`. Subcommands: `cert`,
  `whois`, `tls-scan`, `discover-tls`, `self-test`. Deps: `cryptography`,
  `asyncwhois`, `tldextract` (all actively-maintained, MIT). Pinned via
  `scripts/deploy/requirements.lock`.
- **`scripts/deploy/install.sh`** — uv-based one-liner installer building a
  project-local Python 3.11 venv at `/opt/web_check/venv` and dropping the
  externalscript at `/usr/lib/zabbix/externalscripts/web_check.py`.
- **`scripts/migrate-from-itmicus.py`** — idempotent migration (`--dry-run`
  default; `--apply` to write). Links new template, translates
  `{$WEBSITE_METRICS_URL/PHRASE/TIMEOUT}` → `{$WEB_SERVICE.URL/PHRASE/TIMEOUT}`,
  derives `{$WEB_SERVICE.HOST}` from the URL hostname (required for Layer 4),
  unlinks the legacy template (or keeps it with `--keep-old`).
- **CI** (`.github/workflows/ci.yml`) — ruff lint+format, mypy, pytest
  matrix on Python 3.11/3.12/3.13. Release artifact attachment on tag.
- **Tests** (`scripts/tests/`) — 45 pytest tests covering apex extraction,
  FS cache (stampede + atomic write), CertChecker via `trustme`, WHOIS
  normalisation, TLS scan matrix probing (mocked weak ciphers), and CLI
  plumbing.
- **Documentation**
  - `docs/architecture.md` (rev 2, ~1020 lines) — full 5-layer design,
    constraints, taxonomy, registry rate-limit policy.
  - `docs/validation.md` (~700 lines) — 30-check matrix, all relevant groups
    PASS or covered by pytest.
  - `docs/migration-checklist.md` — phased rollout playbook.

### Removed
- `docs/proxy-agent-server-edit.md` — obsolete; described an additive
  `Server=,127.0.0.1` change on proxy agent2 needed for the dropped
  probe-host pattern. No longer applicable.
- (pre-release, b88430b) `scripts/provision-cert-probes.py` — the probe-host
  design was abandoned in favour of the integrated `web_check.py cert`
  EXTERNAL item.
