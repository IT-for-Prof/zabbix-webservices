# Changelog

All notable changes to this project will be documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning per template
is documented in [README.md](README.md#versioning).

## [7.0-2.2.8] - 2026-06-03

Template-only release (no `web_check` change).

### Fixed — cert "rotated" triggers false-fired on recovery from a check outage
On 2026-06-03 the HIGH **"Cert rotated unexpectedly (was about to expire)"**
fired on `rdgw01.voffice24.com` and `avs.itforprof.ru` with no real rotation
(events `20276842` / `20276895`). Root cause: a ~6h cert-check OUTAGE wrote the
error envelope (`cert.ok=0`, `days_to_expire=0`, `fingerprint_sha256=""`) into
the dependent items. On recovery the fingerprint went `""→<real>`, so
`change(fingerprint)=1` even though the SHA-256 was unchanged across the gap
(identical before/after; `not_after` confirmed ~81d / ~68d remaining — the
certs never rotated and never expired). The `days_to_expire` window was full of
the envelope's `0`s, so `max(days,2h:now-15m)<ROTATE_MIN_DAYS` was also true.
The INFO **"Cert rotated"** trigger fired the same way.

The `Cert check failing` dependency could not help: Zabbix dependencies are
evaluated on the parent's *current* state, but `change()` fires exactly on the
recovery tick when `cert.ok` is already back to `1` — a level dependency cannot
suppress an edge trigger.

- **Fix is at the item layer:** the `cert.fingerprint_sha256` item gains a
  `MATCHES_REGEX` (`^[0-9A-Fa-f]{64}$`) preprocessing step with
  `DISCARD_VALUE` on no-match, before `DISCARD_UNCHANGED_HEARTBEAT`. The
  envelope's `""` (and any non-64-hex value) is dropped, so the fingerprint
  history holds only real fingerprints and `change()` can only ever see a
  genuine `<real>→<real>` rotation. The two triggers revert to their plain
  2.2.7 form (`change(fingerprint_sha256)=1` [`and max(days_to_expire,
  2h:now-15m)<{$WEB_SERVICE.CERT.ROTATE_MIN_DAYS}` for HIGH]).
- **Why not in-trigger guards.** An earlier cut added
  `last(cert.ok)=1 and length(last(fp))>0 and length(last(fp,#2))>0` to mirror
  the WHOIS change-triggers. Code review caught that the `,#2` guard introduces
  a FALSE NEGATIVE on the flagship scenario: a genuinely late rotation that
  spans a single failed poll (`<old>→""→<new>`) has `#2=""` → suppressed —
  silently missing the very "renewed after the cert lapsed" case the HIGH
  trigger exists to catch. In-trigger guards cannot win both edges (dropping
  `#2` reinstates the false positive; keeping it causes the false negative).
  Discarding `""` at ingestion fixes both: `<old>→""→<new>` stores
  `<old>→<new>` (fires correctly) and `<real>→""→<real>` collapses to no change
  (silent). `cert.ok`/`error_code`/`error_message` items still carry the
  envelope for visibility; the level expiry triggers keep their `cert.ok=0`
  dependency.
- Validated on a live Zabbix engine (myzabbix): the exported preprocessing
  serialises to exactly `MATCHES_REGEX` / `DISCARD_VALUE` (import-safe); and a
  master→dependent trapper feed of `<real-A> → "" → <real-B>` produced a
  dependent history of `[A, B]` (the `""` discarded), with `prevvalue=A` — i.e.
  the late-rotation-through-an-outage case fires and the recovery case stays
  silent. Contract tests added in `test_template_contract.py`.
- **Deploy:** apply to `production` (template 14003) and `myzabbix` (template
  10690) via `item.update` (add the preprocessing step) + `trigger.update`
  (revert the two expressions). Existing false-positive events
  (`20276842` / `20276895` on prod, plus the matching INFO "Cert rotated") are
  not real — close them manually.

### Fixed — WHOIS change-triggers had the same sentinel-flap (registrar/NS/DNSSEC)
The same root cause was found — and confirmed firing in production — on the
three WHOIS `change()` triggers. The WHOIS error envelope writes per-field
sentinels (`registrar:""`, `name_servers:[]`, `dnssec:"unknown"`) into the
dependent items, so a WHOIS-lookup outage makes them flap. Production proof
(`elma.hss.center`, current template): `whois.registrar` went `""` (while
`whois.ok=0`) → `…REG.RU…` on recovery → fired **"Registrar changed to REG.RU"**
(WARNING) although the registrar was REG.RU before and after. Recurring across
`searegion`, `cloud.searegion`, `misterlogistic`, `millystyle`, `elma`, … The
pre-existing `last(ok)=1 / <>"" / <>"null" / <>"[]"` guards only mask the
*entering-error* edge, not recovery (no `#2` check); `dnssec`'s `last(,#2)=
"signed"` guard instead causes a FALSE NEGATIVE (a real `signed→unsigned`
removal that spans a failed poll has `#2="unknown"` → suppressed).

- **Same item-layer fix**, one mechanism (regex discard before
  `DISCARD_UNCHANGED_HEARTBEAT`), chosen so each series holds only real values:
  - `whois.registrar`: `NOT_MATCHES_REGEX ^(null)?$` → drops `""` and the
    port-43 parser's literal `"null"`.
  - `whois.name_servers`: `NOT_MATCHES_REGEX ^\[\]$` → drops `"[]"`.
  - `whois.dnssec`: `MATCHES_REGEX ^(signed|unsigned)$` → drops `"unknown"`.
    Deliberate tradeoff: `"unknown"` is also a legitimate "can't determine"
    state, so for TLDs that never publish DNSSEC the item shows the last
    definite state (or no data), not a live `"unknown"`. No trigger reads
    `"unknown"`, and dropping it is what lets a real removal through an outage
    still fire. The `ok`-gated (JS) alternative would preserve the `"unknown"`
    display but adds a second mechanism for a value nothing alerts on —
    overengineering here.
- **Triggers left as-is (minimal change).** Unlike the cert triggers (whose
  in-expression guards were added and removed within this same unshipped work),
  the WHOIS guards are deployed and test-locked; the discard makes them
  redundant but harmless (a value in history now implies a successful lookup),
  so they are kept rather than ripped out in a bugfix. The discard alone fixes
  both the registrar/NS recovery false positive and the DNSSEC removal-through-
  outage false negative (with `"unknown"` gone, `#2` resolves to `signed`).
- Validated on a live Zabbix engine (myzabbix), real master→dependent
  preprocessing path: a single timeline `signed/GoDaddy/NS → envelope →
  recovery(dnssec signed→unsigned) → genuine registrar+NS change` produced —
  **"Domain DNSSEC removed"** fired on the recovery tick (removal-through-outage
  caught); **"Domain registrar changed"** and **"Domain name servers changed"**
  fired *only* on the genuine change, **not** on the recovery (false positive
  gone). `NOT_MATCHES_REGEX` confirmed import-safe via export. Contract tests
  added.
- **Deploy:** add the preprocessing step to the three `whois.*` items on both
  servers via `item.update`. Past sentinel-flap events
  (`Registrar changed to null`, `Name servers changed to []`, the
  `DNSSEC went unsigned` flaps) are not real registrar/NS/DNSSEC changes.

## [7.0-2.2.7] - 2026-06-02

Template-only release (no `web_check` change).

### Fixed — "Cert rotated unexpectedly (was about to expire)" was a no-op
The HIGH trigger used `change(fingerprint)=1 and last(days_to_expire)<14`.
`days_to_expire` and `fingerprint_sha256` are both DEPENDENT items off one
cert master poll, so they update on the **same clock**: at the instant the
fingerprint changes, `last(days_to_expire)` already reflects the *new* cert
(~89), never the outgoing one — the condition could not become true as
intended and never fired. Confirmed on prod history (mon.itforprof.com: days
`60 → 89` and the fingerprint flip share clock `1780014013`).

- New expression: `change(fingerprint_sha256)=1 and
  max(days_to_expire,2h:now-15m) < {$WEB_SERVICE.CERT.ROTATE_MIN_DAYS}`.
  The `now-15m` shift excludes the just-installed cert; the 2h window ≥ the
  item's `DISCARD_UNCHANGED_HEARTBEAT(1h)` so old-cert data is always present;
  `max()` reads the outgoing cert and rides out single-poll error-envelope
  dips (e.g. `-1898` / `0`) that a naive `last(,#2)` would false-fire on.
- New macro **`{$WEB_SERVICE.CERT.ROTATE_MIN_DAYS}`** (default `14`) separates
  the late-rotation threshold from the expiry ladder (WARN 30 / NOTICE 14 /
  CRIT 7). Macro count 27 → 28.
- Validated on a live Zabbix engine (trapper scenarios: healthy rotation =
  silent, late = HIGH fired, transient glitch before rotation = silent).
- **Deploy:** applied to both `production` (template 14003) and `myzabbix`
  (template 10690) via API (`usermacro.create` + `trigger.update` +
  `template.update`). No host re-link needed — template propagation handles it.

### Docs
Fact-checked `docs/architecture.md` and the READMEs against the live template:
corrected the cert/whois trigger tables (real thresholds `1/7/30` and
severities, dropped never-shipped `DNS resolution failed` / `CAA disallows`
/ `Domain expires within 60 days` / cert "rotated > 60d"), the macro catalog
(`SLOW.WARN` 5→10, `TCP.SLOW_SEC` 1→3, `HTTP3.SLOW_MS` 250→1000, removed the
phantom `FOLLOW_REDIRECTS` macro — it is a web-scenario field), the trigger
count (34 → 32 + 1 LLD prototype), and stale version strings (2.2.3 → 2.2.7).

## [7.0-2.2.6 / web_check 2.2.0] - 2026-06-01

### web_check 2.2.0 — RDAP-first registration lookup
RDAP (RFC 9082/9083) is authoritative for gTLDs since ICANN's 2025 WHOIS
sunset; some registries (e.g. Identity Digital `.center`) no longer serve
usable port-43 WHOIS. `web_check` now queries RDAP first and falls back to
port-43 WHOIS.

- **`_query_registration`** tries `asyncwhois.rdap()` first (IANA-bootstrapped
  by `whodap`), then `asyncwhois.whois()`. RDAP-less TLDs (`.ru`/`.рф` via TCI)
  fail the RDAP bootstrap locally (~0.4 s) and use the unchanged port-43 path
  and its TCI augmenters. One 10 s monotonic deadline gates both phases (RDAP
  only starts with budget left; WHOIS short-circuits if RDAP overran), and the
  RDAP HTTP client uses a bounded per-operation httpx timeout (connect capped
  tighter than read) so a hung/unreachable registry endpoint fails fast.
- **`_normalize_rdap`** parses the raw RFC-9083 JSON (not `whodap`'s convenience
  dict, which drops `.com` `registrar expiration` expiry and `secureDNS`):
  expiry from `events[]` (`expiration` / `registrar expiration` /
  `registry expiration`), `dnssec` from `secureDNS.delegationSigned`, registrar
  / IANA id / abuse email from `entities`, NS from `nameservers[].ldhName`.
  Output envelope is identical to the WHOIS path (no nulls, `dnssec` tri-state).
- **No new dependency** — `httpx`/`whodap` are already pinned via `asyncwhois`;
  `requirements.lock` is unchanged.
- **Cache `SCHEMA_VERSION` 2→3** invalidates 2.1.8 entries so RDAP-only domains
  (e.g. `hss.center`) re-query once after deploy.
- **No template change.** Verified on the live fleet that RDAP and WHOIS produce
  identical registrar / NS order / dnssec / expiry, so the source switch fires
  no `change()`-based trigger.
- **Deploy:** redeploy via `install.sh` to **all six** monitor nodes including
  `TRC-ENERGY-ZBX-PROXY` (missed in the 2.1.8 rollout). RDAP needs outbound
  HTTPS/443 per node; a 443-blocked node degrades gracefully to WHOIS (no
  regression). No dedup re-run needed (no template change).

## [7.0-2.2.6 / web_check 2.1.8] - 2026-06-01

### web_check 2.1.8 — output schema the 2.2.6 triggers depend on
The `7.0-2.2.6` hardening below was written against *this* script's output
schema but shipped paired with `web_check 2.1.6`; this release closes that gap.
(`2.1.7` was an unreleased interim.) **Requires a node-side redeploy**
(`scripts/deploy/install.sh`) on every monitor node — until each node pulls
2.1.8 the items below keep their 2.1.6 values and the DNSSEC trigger stays dead.

- **`dnssec` is now a tri-state string `"signed"` / `"unsigned"` / `"unknown"`**
  (was a JSON boolean). The `Domain DNSSEC removed` trigger compares
  `last(…whois.dnssec,#2)="signed" and last(…whois.dnssec)="unsigned"`; against
  the old boolean the `CHAR` item stored `"true"`/`"false"`, so the trigger could
  never fire. Verified dead in production before the fix — every WHOIS-owner host
  read `"false"`.
- **No nulls in any template-consumed field.** WHOIS, cert, TLS, tls-scan and
  HTTP/3 error/partial paths now emit every key the template reads, with typed
  defaults (`""`, `0`, `[]`, `{}`, `false`), so dependent items never go
  UNSUPPORTED and triggers never see `*UNKNOWN*`. `CertResult.tls`/`.cert` default
  to full shapes; `cmd_cert` no longer flattens failures to a sparse envelope.
- **`whois_incomplete` error path.** A normal TLD that parses with no expiry is a
  script failure (`ok=0`, full fallback fields) rather than `ok=1` with a null
  `days_to_expire`; `provider_no_expiry` is now reserved for TLDs that genuinely
  have no expiry (the old raw-text heuristic was dropped). Blast radius at deploy:
  zero — all 21 WHOIS-owner hosts currently report `provider_no_expiry=0` with a
  parseable expiry.
- **Cache `SCHEMA_VERSION` 1→2.** `WhoisCache.read` rejects entries whose record
  *or* payload schema doesn't match, so stale `ok=true`/null-field payloads are
  re-queried once per apex after deploy (21 apexes; self-healing). `write` now
  stamps the payload too.
- Tests cover the WHOIS schema (dnssec string, `whois_incomplete`, no-expiry
  semantics), cache invalidation, and full-envelope assertions for the
  cert/tls-scan/http3 bad-url paths. `PyYAML` added to `requirements-test.txt`.

## [7.0-2.2.6 / web_check 2.1.6] - 2026-06-01

### Template 7.0-2.2.6 — harden WHOIS triggers + apex-dedup tooling
Production was already at `7.0-2.2.5` via out-of-band `trigger.update`s; this
entry codifies that state plus the hardening below into the YAML and a new
script. (Interim `2.2.4`/`2.2.5` were out-of-band hotfixes with no standalone
changelog entry.)

- **WHOIS trigger false-positive hardening.** Registry data is frequently empty
  or sentinel-valued for a poll or two (registry hiccups, RDAP gaps), which fired
  spurious change/expiry alerts. Added guards:
  - `Domain expired` and all three expiry tiers now require
    `length(last(…whois.expires_at))>0` (and keep the existing
    `length(…whois.apex)>0`) so a missing expiry can't read as "expired". The
    extra item reference shifted the `{ITEM.LASTVALUE<N>}` indices (apex 4→5 on
    the tiers); event names, descriptions and the `apex` tag were renumbered to
    match.
  - `Domain registrar changed` excludes `<>""` and `<>"null"`.
  - `Domain name servers changed` excludes `<>"[]"`.
  - `Domain DNSSEC removed` now requires the previous value
    `last(…whois.dnssec,#2)="signed"` so it only fires on a real signed→unsigned
    transition.
- **`web_check.whois.error_code` / `web_check.whois.error_message`** dependent
  items codified in the YAML (already present on hosts out-of-band), with
  `CUSTOM_VALUE` empty-string error handlers so they never go UNSUPPORTED.
- **`scripts/sync-domain-registry-owners.py` (new) — apex deduplication.** Picks
  one deterministic WHOIS "owner" host per registered apex (bare-apex host if one
  exists, else shortest URL hostname, tie-broken by lowest hostid), disables the
  WHOIS items+triggers on the duplicates, and stamps
  `{$WEB_SERVICE.REGISTRY.APEX/OWNER/ROLE}` transparency macros on every host.
  Default dry-run; `--apply` writes; `--only-apex` scopes. Fail-closed: aborts
  with zero writes if any host's WHOIS item/trigger inventory is incomplete.
  - Two bugs fixed before first use: `fetch_trigger_state` must pass
    `expandExpression=true` (the server returns `{functionid}`-form expressions,
    so the `web_check.whois` substring guard otherwise matched nothing and the
    run aborted); and `web_check.whois.statuses` was removed from
    `WHOIS_DEPENDENT_KEYS` (no such item exists).
- **Action required:** re-run `sync-domain-registry-owners.py --apply` after any
  `configuration.import` of this template. Import resets the host-level status of
  any item/trigger whose definition changed back to the template default
  (enabled) — verified live: the 2.2.6 hardening re-enabled the disabled WHOIS
  triggers on all 19 duplicate hosts (items with unchanged keys stayed disabled).
  Skipping the re-run lets the re-enabled "WHOIS no data received" trigger fire on
  every duplicate (their master item has no data).

## [7.0-2.2.3 / web_check 2.1.6] - 2026-05-26

### web_check.py 2.1.6 — silence TLSv1/1.1 `DeprecationWarning` so `tls-scan` JSON stays parseable (weak-TLS alerting was dead fleet-wide)
- **Symptom.** On every host the `web_check.tls_scan.*` dependent items sat
  UNSUPPORTED, so the weak-TLS triggers never fired — servers silently offering
  TLSv1.0/1.1 (e.g. `rdgw01.voffice24.com`) raised no alert.
- **Root cause.** Probing the legacy protocols pins `ctx.minimum_version =
  ssl.TLSVersion.TLSv1` / `TLSv1_1` in `_try_protocol`. On Python 3.12 that
  assignment emits a `DeprecationWarning` to **stderr** (4 lines per scan). Zabbix
  external checks merge stderr into the item value, so the warning text gets
  prepended to the JSON. The master item (`value_type: TEXT`) tolerates the noise,
  but the dependent items' `JSONPATH $.…` preprocessing then can't parse it and,
  via their `CUSTOM_ERROR` handler, go UNSUPPORTED.
- **Why the prior guard missed it.** The module-scoped
  `warnings.filterwarnings(…, module=r"web_check.*")` only matches when the file is
  imported as module `web_check` (i.e. under pytest); at runtime the externalscript
  runs as `__main__`, so the regex never matched and the warning leaked anyway.
  Worse, it *masked* the warning in CI, hiding the regression. Removed it.
- **Fix.** Wrap the two version assignments in `warnings.catch_warnings()` +
  `warnings.simplefilter("ignore", DeprecationWarning)`, exactly as `rdp_check.py`
  does. Verified end to end: `tls-scan` now writes 0 bytes to stderr and clean JSON
  to stdout.
- **Regression test.** `test_try_protocol_emits_no_deprecation_warning` promotes a
  leaked `DeprecationWarning` to an error (resetting filters so a module-scoped
  guard can't mask it) and asserts the probe stays silent.
- No template/item/trigger schema change → template stays `7.0-2.2.3`.
- **Action required:** redeploy `web_check.py` to all nodes for the fix to take
  effect; the dependent items recover on the next `tls-scan` cycle.

## [7.0-2.2.3 / web_check 2.1.5] - 2026-05-22

### Template 7.0-2.2.3 — fix three trigger macros rendering `*UNKNOWN*` on linked hosts
- **Root cause.** `event_name`/`opdata` expression macros referenced items by the
  **literal template host** — `{?last(/Web service by itforprof.com/…)}`. Unlike a
  trigger *expression* (whose item refs rebind to the host via functionids on
  template linkage), a literal `/host/key` inside an expression macro is **not**
  rebound; it keeps pointing at the template, which stores no history, so it
  resolved to the literal string `*UNKNOWN*` on all 55 linked hosts. Surfaced by
  the event `Registrar changed: *UNKNOWN* → RU-CENTER-RU` on `millystyle.ru`.
- **`Domain registrar changed` / `Domain name servers changed` event_names** —
  dropped the previous→new `{?last(…,#2)} →` form (introduced in 2.2.2 below) for
  current-value-only, host-bound macros: `Registrar changed to {ITEM.LASTVALUE1} — …`
  / `Name servers changed to {ITEM.LASTVALUE1} — …`. The prior value stays available
  in item history (`prevvalue`) and the trigger comment.
- **`Web service is failing` opdata** — switched to the empty-host relative form
  `HTTP {?last(//web.test.rspcode[Web service,GET])} | err: {?last(//web.test.error[Web service])}`.
  `//key` resolves to the trigger's own host at evaluation time (the form Zabbix's
  stock templates use), so it rebinds correctly per host.
- **Rule of thumb.** On templated triggers, expression macros must use the empty-host
  `{?func(//key,…)}` form, never the literal template name; host-bound reference
  macros (`{ITEM.LASTVALUE<N>}`, `{HOST.HOST}`) are always safe. The before→new
  display *is* achievable with `{?last(//…,#2)} → {ITEM.LASTVALUE1}` if wanted later.
- Applied live on prod (`mon.itforprof.com`, Zabbix 7.0.26) via `trigger.update` on
  template triggers 96117 / 96118 / 96100. The server `vendor_version` is left at
  `7.0-2.2.2` (out-of-band hotfix); this 2.2.3 YAML carries the same change for the
  next `configuration.import`.

## [7.0-2.2.2 / web_check 2.1.5] - 2026-05-17

### web_check.py 2.1.5 — retire the tldextract cache-write bug class by threading our offline extractor through asyncwhois
- **Fix:** `asyncwhois.whois(apex, tldextract_obj=_get_psl_extractor())`.
  Without `tldextract_obj=`, asyncwhois constructs its own `TLDExtract()`
  with library defaults (network-fetched PSL, default
  `$HOME/.cache/python-tldextract` cache_dir) — the exact bug we
  silenced for our own extractor in 2.1.4. Caught during the 2.1.4
  production rollout: on a proxy where the zabbix user's `$HOME` was
  `/nonexistent` (systemd-managed account), the warning still leaked
  from asyncwhois's internal extractor and corrupted the WHOIS JSON
  envelope even after 2.1.4 was deployed. Other hosts masked the
  symptom because they had a writable `/var/lib/zabbix/.cache/` (either
  natively or via the operator's manual workaround).
- **Refactor:** extracted the lazy-init of `_PSL_EXTRACTOR` into a
  helper `_get_psl_extractor()` so any future caller threading the
  extractor into another library reuses the same configured singleton
  rather than re-constructing it.
- Verified post-deploy on the proxy that exhibited the leak: WHOIS
  output is now JSON-only, no stderr emission.

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
