# RDAP-first registration lookup for `web_check` (target web_check 2.2.0)

Status: design, awaiting review
Date: 2026-06-01
Author: Konstantin Tyutyunnik

## Problem

`web_check` Layer 3 (WHOIS) queries registration data over port-43 WHOIS via
`asyncwhois.whois()`. As of ICANN's 2025 sunset of the WHOIS requirement for
gTLDs, RDAP (RFC 9082/9083, bootstrapped per RFC 9224) is the authoritative
source for gTLDs, and several registries no longer serve usable data over port
43. Concretely, `web_check 2.1.8` raised `whois_incomplete` on `elma.hss.center`
because `.center` (Identity Digital) returns *"TLD is not supported"* over port
43 — yet RDAP returns a clean expiry (`2026-10-10`). The expiry triggers for
that domain have therefore never worked.

This was surfaced (not caused) by 2.1.8: under 2.1.6 the same domain was silently
`ok=1`/`days_to_expire=null`. The fix is to read registration data from RDAP
where it exists, falling back to port-43 WHOIS where it does not.

## Fleet evidence (verified 2026-06-01 from `mon` via `asyncwhois`)

The 21 enabled WHOIS-owner hosts span exactly three TLDs:

| TLD | apexes | RDAP available | expiry in RDAP `events[]` | dnssec source |
|-----|--------|----------------|---------------------------|---------------|
| `.com` | 6 | yes | `registrar expiration` (4) **or** `expiration` (2) | `secureDNS.delegationSigned` |
| `.center` | 1 (`hss.center`) | yes | `expiration` | `secureDNS.delegationSigned` |
| `.ru` | 14 | no — `NotImplementedError: No RDAP server found for .RU domains`, fails locally in ~0.4 s (IANA RDAP bootstrap miss) | n/a → WHOIS fallback | from WHOIS |

Two facts drive the design:
1. **RDAP-less TLDs fail fast and locally** (bootstrap miss, not a network
   timeout), so an RDAP-first attempt costs ~0.4 s before WHOIS fallback on
   `.ru`. No meaningful latency penalty, no hand-maintained TLD list needed.
2. **`whodap`'s convenience `parsed` dict is lossy/inconsistent** — it maps
   eventAction `expiration` but not `registrar expiration`, and does not surface
   `secureDNS`. So `searegion.com` (`.com`) reports `parsed["expires"] = None`
   despite the expiry being present in the raw RDAP `events`. We must parse the
   structured RDAP JSON ourselves.

## Goals

- RDAP-first registration lookup with transparent port-43 WHOIS fallback.
- Full field parity from RDAP: `expires_at`/`days_to_expire`, `registrar`,
  `registrar_iana_id`, `registered_at`, `last_updated`, `name_servers`,
  `dnssec`, `statuses`, `abuse_email`.
- Preserve every existing behavior: apex dedup, FS cache, the `.ru`/`.рф` TCI
  augmenters (reached via the WHOIS fallback), the no-nulls output envelope, the
  `dnssec` tri-state string, and `provider_no_expiry` semantics. Dependent items
  and triggers in the template need **no** change.
- Stay within the deploy model: `uv` venv on monitor nodes via `install.sh`,
  pinned `requirements.lock`.

## Non-goals (explicitly avoiding band-aids / overengineering)

- **No hand-maintained TLD→protocol map.** Routing is delegated to the IANA RDAP
  bootstrap that `whodap` already consumes. A per-TLD table would duplicate it.
- **No new dependency.** `httpx` and `whodap` are already transitive deps of
  `asyncwhois` and pinned in `requirements.lock`; the file does not change.
- **No RDAP for `.ru`/`.рф`** (TCI runs no public RDAP) — they stay on WHOIS.
- **No trigger-suppression logic** for the one-time source-transition (see below).

## Approach

Refactor the single upstream-query function (currently `_query_whois`) into a
source-agnostic `_query_registration(apex)` that tries RDAP, then WHOIS:

```
_query_registration(apex):
    1. tld = tld_of(apex)
    2. RDAP attempt:
         try: raw_json, _ = asyncwhois.rdap(apex)        # whodap + IANA bootstrap; ignore lossy parsed
              norm = _normalize_rdap(json.loads(raw_json), tld)   # our parser, on the raw RFC-9083 JSON
              if norm has usable expiry OR tld is no-expiry:
                  return success(norm, source="rdap")
         except (NotImplementedError, NotFoundError, httpx/transport, ValueError):
              fall through                                # no RDAP / fetch failed
    3. WHOIS attempt (existing path, unchanged):
         raw, parsed = asyncwhois.whois(apex, tldextract_obj=extractor)
         norm = _normalize_whois(parsed, raw, tld)       # TCI augmenters intact
         if norm has usable expiry OR provider_no_expiry:
              return success(norm, source="asyncwhois")
    4. return whois_error_envelope("whois_incomplete", ...)  # genuine dual-source miss
```

- One 10 s monotonic deadline gates both phases: RDAP only starts if budget
  remains, and the WHOIS retry loop trips its deadline check immediately if RDAP
  overran (so WHOIS never stacks a fresh budget). The deadline cannot interrupt
  an in-flight RDAP call mid-leg, so RDAP is additionally bounded by a
  per-operation `httpx` timeout (connect capped tighter than read) — the same
  bounding style as WHOIS's per-attempt socket timeout. RDAP fast-fail on `.ru`
  (~0.4 s, local bootstrap miss) leaves the WHOIS retries their full budget.
- The output envelope is unchanged in shape. The existing `source` field carries
  `"rdap"` or `"asyncwhois"` for transparency.
- `check_whois()`, `WhoisCache`, apex dedup, the negative-cache TTL, and the
  flock coalescing are untouched.

### `_normalize_rdap(d, tld)` — RFC 9083 field extraction (evidence-backed)

Produces the *same dict shape* as `_normalize_whois`, so it feeds the existing
success/`whois_incomplete` logic and the no-nulls coercion identically.

- **expires_at / days_to_expire** — scan `d["events"]` for `eventAction` in
  `{"expiration", "registrar expiration", "registry expiration"}`; prefer
  `expiration`, else `registrar expiration`, else `registry expiration`. Parse
  `eventDate` (ISO-8601). Same `provider_no_expiry` rule as WHOIS: only true for
  `tld in NO_EXPIRY_TLDS`.
- **registered_at** — event `registration`. **last_updated** — event
  `last changed`.
- **dnssec** — `d["secureDNS"]["delegationSigned"]` (bool) → `"signed"`/
  `"unsigned"`; key absent → `"unknown"`. (Same tri-state vocabulary as WHOIS.)
- **registrar** — entity with role `registrar`, vCard `fn`. **registrar_iana_id**
  — that entity's `publicIds` entry of type `IANA Registrar ID`.
- **name_servers** — `d["nameservers"][].ldhName`, lowercased, trailing dot
  stripped (matches the WHOIS normalization).
- **statuses** — top-level `d["status"]` (RDAP status list).
- **abuse_email** — registrar entity's nested `abuse`-role entity vCard `email`
  (best-effort; `""` when absent).

## Caching

Bump `SCHEMA_VERSION` 2 → 3. The payload shape is unchanged, but the bump cleanly
invalidates any entries cached under 2.1.8 (e.g. a `hss.center` negative entry),
forcing a one-time re-query through the new RDAP path. `WhoisCache.read` already
rejects mismatched schema versions.

## Source-transition behavior (verified value-neutral)

Concern: on the first poll after deploy, the 7 gTLD owners (`.com`×6,
`.center`×1) switch source `asyncwhois` → `rdap`, which could differ in
registrar string, NS ordering, status text, or dnssec and fire the
`change()`-based triggers once.

**Measured 2026-06-01 — it does not.** For every live gTLD owner, the
RDAP-derived values are identical to what WHOIS produces / what is currently
stored:

- `searegion.com` / `itforprof.com`: WHOIS vs RDAP normalized `registrar`,
  `name_servers`, `dnssec`, and `expires_at` are byte-identical.
- All 6 `.com` owners: RDAP nameserver **order** exactly matches the value
  currently stored in the `web_check.whois.name_servers` item.
- `hss.center` is currently `ok=0` (broken), so there is no working baseline to
  perturb — RDAP is pure gain (`ok=1`, expiry `2026-10-10`).

Therefore **no `change()`-trigger fires** on cutover for the current fleet, and
**no NS sorting / suppression logic is needed** (adding sorting would itself
cause a one-time re-baseline, so we deliberately do not). The `source` field
(`"rdap"`/`"asyncwhois"`) keeps the active source auditable. Residual note: a
*future* domain whose registrar's RDAP and WHOIS disagree on a value could
re-baseline once; that is acceptable and not a concern for any current host.

## Error taxonomy

User-facing `error_code` values are unchanged (`whois_incomplete`,
`whois_unreachable`, `whois_timeout`, `bad_url`, `apex_unresolved`,
`missing_dependency`). RDAP-specific failures are internal control flow that
trigger WHOIS fallback; they never reach the envelope. `whois_incomplete` now
means "neither RDAP nor WHOIS produced a parseable expiry" — a genuine
dual-source miss.

## Testing (TDD, no network)

Mirror the existing `test_whois.py` fixture style with **recorded real RDAP
JSON** captured 2026-06-01 (no network in tests). Verified fixture sources:

| fixture | captured from | exercises |
|---------|---------------|-----------|
| `rdap_com_registrar_expiration.json` | `searegion.com` | eventAction `registrar expiration`; registrar PDR / IANA 303 / abuse email; 4 NS |
| `rdap_com_expiration.json` | `itforprof.com` | eventAction `expiration`; registrar REG.RU / IANA 1606 |
| `rdap_center.json` | `hss.center` | `.center`; eventAction `expiration` |
| `rdap_signed.json` | `cloudflare.com` | `secureDNS.delegationSigned=true` + `dsData` → `"signed"`; long status list |
| `rdap_securedns_maxsiglife.json` | `nic.center` | `secureDNS={delegationSigned:false, maxSigLife:1}` → `"unsigned"` (not "signed") |

- `_normalize_rdap` cases:
  - `registrar expiration` eventAction → expiry parsed (searegion fixture).
  - `expiration` eventAction → expiry parsed (itforprof fixture).
  - `delegationSigned` true → `signed` (cloudflare); false → `unsigned`
    (searegion); `secureDNS` key absent → `unknown`; `maxSigLife` present but
    `delegationSigned:false` → `unsigned` (nic.center).
  - registrar `fn` / IANA id via `publicIds` / nested abuse-entity email extracted;
    missing registrar or abuse entity → `""` (no nulls).
  - `name_servers` from `nameservers[].ldhName`, lowercased + dot-stripped,
    source order preserved (verified to match stored values — do not sort);
    `statuses` from top-level `status[]` passthrough.
- `_query_registration`:
  - RDAP success → `source="rdap"`, no WHOIS call.
  - RDAP `NotImplementedError` (`.ru`) → WHOIS fallback, `source="asyncwhois"`.
  - RDAP succeeds but no expiry event → WHOIS fallback.
  - RDAP and WHOIS both yield no expiry → `whois_incomplete`.
- Cache: extend the schema-invalidation test for version 3.

## Deploy

- Bump `__version__` 2.1.8 → 2.2.0, `SCHEMA_VERSION` 2 → 3; CHANGELOG entry.
- `requirements.lock` unchanged (verify in CI) — no `uv pip compile` needed.
- Redeploy via `install.sh` to **all six** monitor nodes, including
  `TRC-ENERGY-ZBX-PROXY` (the node missed in the 2.1.8 rollout).
- **Egress check:** RDAP is outbound HTTPS (443) to registry/registrar RDAP
  endpoints. `mon` reaches them; confirm each proxy's egress allows 443 before
  relying on RDAP there — a blocked proxy degrades gracefully to WHOIS fallback,
  so gTLD owners on a 443-blocked proxy would behave as today (no regression),
  just without the RDAP improvement.
- No template re-import and no dedup re-run required (no template change).
- Verify: `hss.center` flips to `ok=1` with `expires_at=2026-10-10`,
  `days_to_expire>0`; the acknowledged `whois_incomplete` event auto-resolves.

## Rollback

Revert the script to 2.1.8 and redeploy via `install.sh`; `SCHEMA_VERSION` drops
back to 2 and caches re-query over WHOIS. The template is untouched, so rollback
is script-only.
