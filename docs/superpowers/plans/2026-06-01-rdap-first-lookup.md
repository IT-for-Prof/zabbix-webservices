# RDAP-first registration lookup — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `web_check` read domain registration data from RDAP first (authoritative for gTLDs since ICANN's 2025 WHOIS sunset), falling back to port-43 WHOIS, so RDAP-only TLDs like `.center` regain expiry monitoring.

**Architecture:** Add `_normalize_rdap()` that parses the raw RFC-9083 RDAP JSON into the *same envelope* as `_normalize_whois()`. Refactor the upstream query into `_query_registration(apex)` = `_query_rdap` (usable result or `None`) → `_query_whois_port43` (existing path) → shared finalize / `whois_incomplete`. No new dependency (`httpx`/`whodap` already locked via `asyncwhois`); the template and triggers are unchanged.

**Tech Stack:** Python 3.12, `asyncwhois` (`asyncwhois.rdap()` + `asyncwhois.whois()`), `pytest`, `uv` venv deployed by `scripts/deploy/install.sh`.

**Spec:** `docs/superpowers/specs/2026-06-01-rdap-first-lookup-design.md` (data-grounded; transition verified value-neutral on the live fleet).

**All field paths below were verified against production RDAP responses on 2026-06-01 — they are facts, not guesses.**

---

## File structure

- **Modify** `scripts/externalscripts/web_check.py`
  - bump `__version__` `2.1.8`→`2.2.0`, `SCHEMA_VERSION` `2`→`3` (line ~47-48)
  - add RDAP helpers + `_normalize_rdap()` next to `_normalize_whois()` (after line 1139)
  - add `_query_rdap()`, rename/split `_query_whois()` into `_query_whois_port43()` + new `_query_registration()` (lines 998-1075)
  - `check_whois()` calls `_query_registration()` instead of `_query_whois()` (line 992)
- **Create** `scripts/tests/fixtures/rdap/*.json` — five recorded real RDAP responses
- **Create** `scripts/tests/test_rdap.py` — `_normalize_rdap` + `_query_registration` tests
- **Modify** `scripts/tests/test_whois.py` — update the one test that calls `_query_whois` (now `_query_registration`)
- **Modify** `scripts/tests/test_cache.py` — schema-version bump in the existing v-mismatch test
- **Modify** `CHANGELOG.md` — add the `web_check 2.2.0` entry

---

## Task 1: Capture real RDAP fixtures from production

**Files:**
- Create: `scripts/tests/fixtures/rdap/searegion_com.json` (eventAction `registrar expiration`)
- Create: `scripts/tests/fixtures/rdap/itforprof_com.json` (eventAction `expiration`)
- Create: `scripts/tests/fixtures/rdap/hss_center.json` (`.center`)
- Create: `scripts/tests/fixtures/rdap/cloudflare_com.json` (`delegationSigned: true` + `dsData`)
- Create: `scripts/tests/fixtures/rdap/nic_center.json` (`delegationSigned: false` + `maxSigLife`)

- [ ] **Step 1: Capture the five raw RDAP responses from `mon`**

These must be *real* recorded responses (no synthetic JSON). Run from the repo root:

```bash
mkdir -p scripts/tests/fixtures/rdap
for pair in searegion.com:searegion_com itforprof.com:itforprof_com hss.center:hss_center cloudflare.com:cloudflare_com nic.center:nic_center; do
  dom="${pair%%:*}"; out="${pair##*:}"
  ssh -o BatchMode=yes mon.itforprof.com "/opt/web_check/venv/bin/python -c \"import asyncwhois,json,sys; raw,_=asyncwhois.rdap('$dom'); print(json.dumps(json.loads(raw), indent=2, sort_keys=True))\"" > "scripts/tests/fixtures/rdap/${out}.json"
done
```

- [ ] **Step 2: Verify each fixture is valid JSON with the expected markers**

Run:
```bash
python3 - <<'PY'
import json, pathlib
fx = pathlib.Path("scripts/tests/fixtures/rdap")
def ev(d): return {e.get("eventAction"): e.get("eventDate") for e in d.get("events",[])}
for f in sorted(fx.glob("*.json")):
    d = json.loads(f.read_text())
    print(f.name, "| exp_actions:", [a for a in ev(d) if "expir" in a],
          "| secureDNS:", d.get("secureDNS"))
PY
```
Expected (markers present):
```
cloudflare_com.json | exp_actions: ['expiration'] | secureDNS: {'delegationSigned': True, 'dsData': [...]}
hss_center.json     | exp_actions: ['expiration'] | secureDNS: {'delegationSigned': False}
itforprof_com.json  | exp_actions: ['expiration'] | secureDNS: {'delegationSigned': False}
nic_center.json     | exp_actions: ['expiration'] | secureDNS: {'delegationSigned': False, 'maxSigLife': 1}
searegion_com.json  | exp_actions: ['registrar expiration'] | secureDNS: {'delegationSigned': False}
```

- [ ] **Step 3: Commit the fixtures**

```bash
git add scripts/tests/fixtures/rdap/
git commit -m "test(rdap): record real RDAP fixtures (com x2 variants, center, signed, maxsiglife)"
```

---

## Task 2: RDAP JSON normalization (`_normalize_rdap` + helpers)

**Files:**
- Modify: `scripts/externalscripts/web_check.py` (add after `_augment_tci_raw`, ~line 1189)
- Test: `scripts/tests/test_rdap.py` (create)

- [ ] **Step 1: Write the failing tests**

Create `scripts/tests/test_rdap.py`:

```python
"""Tests for RDAP (RFC 9083) normalization, using recorded real responses."""

from __future__ import annotations

import json
from pathlib import Path

FIX = Path(__file__).parent / "fixtures" / "rdap"


def load(name: str) -> dict:
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def test_rdap_com_registrar_expiration(web_check_module):
    out = web_check_module._normalize_rdap(load("searegion_com.json"), "com")
    assert out["source"] == "rdap"
    assert out["expires_at"].startswith("2026-06-08")
    assert out["days_to_expire"] is not None
    assert out["registrar"] == "PDR Ltd. d/b/a PublicDomainRegistry.com"
    assert out["registrar_iana_id"] == "303"
    assert out["abuse_email"] == "abuse-contact@publicdomainregistry.com"
    assert out["name_servers"] == ["ns1.timeweb.ru", "ns2.timeweb.ru", "ns3.timeweb.org", "ns4.timeweb.org"]
    assert out["dnssec"] == "unsigned"
    assert out["provider_no_expiry"] is False


def test_rdap_com_plain_expiration(web_check_module):
    out = web_check_module._normalize_rdap(load("itforprof_com.json"), "com")
    assert out["expires_at"].startswith("2027-03-21")
    assert out["registrar_iana_id"] == "1606"
    assert out["dnssec"] == "unsigned"


def test_rdap_center(web_check_module):
    out = web_check_module._normalize_rdap(load("hss_center.json"), "center")
    assert out["expires_at"].startswith("2026-10-10")
    assert out["days_to_expire"] is not None
    assert out["name_servers"] == ["ns1.reg.ru", "ns2.reg.ru"]


def test_rdap_dnssec_signed(web_check_module):
    out = web_check_module._normalize_rdap(load("cloudflare_com.json"), "com")
    assert out["dnssec"] == "signed"


def test_rdap_dnssec_maxsiglife_is_unsigned(web_check_module):
    # delegationSigned=false even though maxSigLife is present -> unsigned, not signed
    out = web_check_module._normalize_rdap(load("nic_center.json"), "center")
    assert out["dnssec"] == "unsigned"


def test_rdap_securedns_absent_is_unknown(web_check_module):
    out = web_check_module._normalize_rdap({"events": [], "nameservers": []}, "com")
    assert out["dnssec"] == "unknown"


def test_rdap_no_nulls_on_sparse_input(web_check_module):
    out = web_check_module._normalize_rdap({}, "com")
    assert out["registrar"] == ""
    assert out["registrar_iana_id"] == ""
    assert out["abuse_email"] == ""
    assert out["expires_at"] == ""
    assert out["name_servers"] == []
    assert out["statuses"] == []
    assert out["days_to_expire"] is None  # gTLD, no expiry parsed -> caller treats as incomplete
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /opt/zabbix-webservices && python3 -m pytest scripts/tests/test_rdap.py -q`
Expected: FAIL — `AttributeError: module 'web_check' has no attribute '_normalize_rdap'`

- [ ] **Step 3: Implement the RDAP helpers and `_normalize_rdap`**

In `scripts/externalscripts/web_check.py`, immediately after `_augment_tci_raw()` (after line 1189, before the `# Subcommand handlers` banner), add:

```python
# =============================================================================
# Layer 3 — RDAP (RFC 9083) normalization
# =============================================================================


def _parse_rdap_dt(s: Any) -> datetime | None:
    """Parse an RDAP ISO-8601 eventDate into an aware UTC datetime, or None."""
    if not isinstance(s, str) or not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def _vcard_get(vcard_array: Any, field: str) -> str | None:
    """Pull a field (e.g. 'fn', 'email') from a jCard ['vcard', [[name,..,value]]]."""
    try:
        for entry in vcard_array[1]:
            if entry[0] == field:
                return entry[3]
    except (IndexError, TypeError, KeyError):
        return None
    return None


def _rdap_find_entity(entities: Any, role: str) -> dict[str, Any] | None:
    for e in entities or []:
        if isinstance(e, dict) and role in (e.get("roles") or []):
            return e
    return None


def _rdap_registrar(d: dict[str, Any]) -> tuple[str | None, str | None, str | None]:
    """(registrar name, IANA registrar id, abuse email) from RDAP entities."""
    reg = _rdap_find_entity(d.get("entities"), "registrar")
    if not reg:
        return (None, None, None)
    name = _vcard_get(reg.get("vcardArray"), "fn")
    iana = None
    for pid in reg.get("publicIds") or []:
        if "IANA" in (pid.get("type") or ""):
            iana = pid.get("identifier")
    abuse = _rdap_find_entity(reg.get("entities"), "abuse")
    abuse_email = _vcard_get(abuse.get("vcardArray"), "email") if abuse else None
    return (name, iana, abuse_email)


def _normalize_rdap(d: dict[str, Any], tld: str) -> dict[str, Any]:
    """Convert an RDAP domain object (RFC 9083) into our stable envelope.

    Mirrors `_normalize_whois`'s output shape exactly (same keys, no nulls,
    `dnssec` tri-state string, `provider_no_expiry` semantics) so callers can't
    tell the source apart beyond the `source` field. We read the raw RDAP JSON,
    not whodap's convenience dict, which drops `.com` `registrar expiration`
    expiry events and `secureDNS`.
    """
    events: dict[str, str] = {}
    for ev in d.get("events") or []:
        action, date = ev.get("eventAction"), ev.get("eventDate")
        if action and date and action not in events:
            events[action] = date

    expires_dt = _parse_rdap_dt(
        events.get("expiration") or events.get("registrar expiration") or events.get("registry expiration")
    )
    created_dt = _parse_rdap_dt(events.get("registration"))
    updated_dt = _parse_rdap_dt(events.get("last changed"))

    sd = d.get("secureDNS")
    if isinstance(sd, dict) and "delegationSigned" in sd:
        dnssec_s = "signed" if sd.get("delegationSigned") else "unsigned"
    else:
        dnssec_s = "unknown"

    registrar, iana_id, abuse_email = _rdap_registrar(d)

    name_servers = [
        ns.get("ldhName").rstrip(".").lower()
        for ns in (d.get("nameservers") or [])
        if isinstance(ns, dict) and ns.get("ldhName")
    ]

    statuses = d.get("status") or []
    if isinstance(statuses, str):
        statuses = [statuses]

    no_expiry = tld in NO_EXPIRY_TLDS
    dte = (expires_dt - datetime.now(UTC)).days if expires_dt is not None else None

    return {
        "source": "rdap",
        "registrar": registrar or "",
        "registrar_iana_id": iana_id or "",
        "registered_at": created_dt.isoformat() if created_dt else "",
        "last_updated": updated_dt.isoformat() if updated_dt else "",
        "expires_at": expires_dt.isoformat() if expires_dt else "",
        "days_to_expire": dte if dte is not None or not no_expiry else 0,
        "statuses": statuses,
        "name_servers": name_servers,
        "dnssec": dnssec_s,
        "abuse_email": abuse_email or "",
        "provider_no_expiry": no_expiry,
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /opt/zabbix-webservices && python3 -m pytest scripts/tests/test_rdap.py -q`
Expected: PASS (8 passed)

- [ ] **Step 5: Commit**

```bash
git add scripts/externalscripts/web_check.py scripts/tests/test_rdap.py
git commit -m "feat(web_check): RDAP RFC-9083 normalization (_normalize_rdap)"
```

---

## Task 3: RDAP-first query with WHOIS fallback (`_query_registration`)

**Files:**
- Modify: `scripts/externalscripts/web_check.py:998-1075` (split `_query_whois`)
- Test: `scripts/tests/test_rdap.py` (append)
- Modify: `scripts/tests/test_whois.py` (the one `_query_whois` caller)

- [ ] **Step 1: Write the failing tests (append to `scripts/tests/test_rdap.py`)**

```python
import sys
import types


def _fake_asyncwhois(*, rdap=None, whois=None):
    """Build a fake asyncwhois module with given rdap/whois callables."""
    def _raise(name):
        def _f(*a, **k):
            raise AssertionError(f"{name} should not be called")
        return _f
    return types.SimpleNamespace(
        rdap=rdap or _raise("rdap"),
        whois=whois or _raise("whois"),
    )


def test_query_registration_prefers_rdap(monkeypatch, web_check_module):
    raw = (FIX / "hss_center.json").read_text(encoding="utf-8")
    fake = _fake_asyncwhois(rdap=lambda apex: (raw, {}))
    monkeypatch.setitem(sys.modules, "asyncwhois", fake)
    out = web_check_module._query_registration("hss.center")
    assert out["ok"] is True
    assert out["source"] == "rdap"
    assert out["expires_at"].startswith("2026-10-10")
    assert out["apex"] == "hss.center"


def test_query_registration_falls_back_to_whois_when_no_rdap(monkeypatch, web_check_module):
    # .ru raises NotImplementedError in real life; WHOIS must then run.
    def rdap_no_server(apex):
        raise NotImplementedError("No RDAP server found for .RU domains")

    def whois_ok(apex, **kwargs):
        return ("paid-till: 2027-01-01T00:00:00Z\n", {"expires": "2027-01-01T00:00:00Z", "registrar": "REGRU-RU"})

    monkeypatch.setitem(sys.modules, "asyncwhois", _fake_asyncwhois(rdap=rdap_no_server, whois=whois_ok))
    monkeypatch.setattr(web_check_module, "_get_psl_extractor", lambda: object())
    out = web_check_module._query_registration("example.ru")
    assert out["ok"] is True
    assert out["source"] == "asyncwhois"
    assert out["expires_at"].startswith("2027-01-01")


def test_query_registration_rdap_without_expiry_falls_back(monkeypatch, web_check_module):
    # RDAP responds but has no usable expiry event -> WHOIS fallback wins.
    def rdap_no_expiry(apex):
        return ('{"events": [], "nameservers": []}', {})

    def whois_ok(apex, **kwargs):
        return ("", {"expires": "2028-05-05T00:00:00Z", "registrar": "Whois Reg"})

    monkeypatch.setitem(sys.modules, "asyncwhois", _fake_asyncwhois(rdap=rdap_no_expiry, whois=whois_ok))
    monkeypatch.setattr(web_check_module, "_get_psl_extractor", lambda: object())
    out = web_check_module._query_registration("example.com")
    assert out["ok"] is True
    assert out["source"] == "asyncwhois"
    assert out["expires_at"].startswith("2028-05-05")


def test_query_registration_both_incomplete_returns_whois_incomplete(monkeypatch, web_check_module):
    def rdap_no_expiry(apex):
        return ('{"events": [], "nameservers": []}', {})

    def whois_no_expiry(apex, **kwargs):
        return ("Domain Name: EXAMPLE.COM\n", {"registrar": "REG"})

    monkeypatch.setitem(sys.modules, "asyncwhois", _fake_asyncwhois(rdap=rdap_no_expiry, whois=whois_no_expiry))
    monkeypatch.setattr(web_check_module, "_get_psl_extractor", lambda: object())
    out = web_check_module._query_registration("example.com")
    assert out["ok"] is False
    assert out["error_code"] == "whois_incomplete"
    assert out["days_to_expire"] == 0
    assert out["provider_no_expiry"] is False


def test_query_registration_whois_transport_error_surfaces(monkeypatch, web_check_module):
    def rdap_no_server(apex):
        raise NotImplementedError("No RDAP server found")

    def whois_boom(apex, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setitem(sys.modules, "asyncwhois", _fake_asyncwhois(rdap=rdap_no_server, whois=whois_boom))
    monkeypatch.setattr(web_check_module, "_get_psl_extractor", lambda: object())
    monkeypatch.setattr(web_check_module.time, "sleep", lambda *_: None)  # no real backoff sleeps
    out = web_check_module._query_registration("example.ru")
    assert out["ok"] is False
    assert out["error_code"] == "whois_unreachable"
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd /opt/zabbix-webservices && python3 -m pytest scripts/tests/test_rdap.py -q`
Expected: FAIL — `module 'web_check' has no attribute '_query_registration'`

- [ ] **Step 3: Replace `_query_whois` (lines 998-1075) with the split functions**

Delete the entire current `_query_whois(apex)` function (lines 998-1075) and put in its place:

```python
def _query_registration(apex: str) -> dict[str, Any]:
    """RDAP-first registration lookup with port-43 WHOIS fallback.

    RDAP (RFC 9082/9083, IANA-bootstrapped by whodap) is authoritative for
    gTLDs since ICANN's 2025 WHOIS sunset. RDAP-less TLDs (.ru/.рф via TCI)
    raise NotImplementedError locally (~0.4 s bootstrap miss) and fall through
    to the existing port-43 path with its TCI augmenters intact.
    """
    rdap_norm = _query_rdap(apex)
    if rdap_norm is not None:
        return _finalize_registration(rdap_norm, apex)

    whois_result = _query_whois_port43(apex)
    if whois_result.get("error_code"):  # transport failure (timeout/unreachable/dep)
        return whois_result
    if whois_result["days_to_expire"] is None and not whois_result["provider_no_expiry"]:
        return whois_error_envelope(
            "whois_incomplete",
            f"no parseable expiration date for apex {apex!r} via RDAP or WHOIS",
            apex=apex,
            source=whois_result["source"],
            registrar=whois_result["registrar"],
            registrar_iana_id=whois_result["registrar_iana_id"],
            registered_at=whois_result["registered_at"],
            last_updated=whois_result["last_updated"],
            statuses=whois_result["statuses"],
            name_servers=whois_result["name_servers"],
            dnssec=whois_result["dnssec"],
            abuse_email=whois_result["abuse_email"],
            provider_no_expiry=False,
        )
    return _finalize_registration(whois_result, apex)


def _finalize_registration(norm: dict[str, Any], apex: str) -> dict[str, Any]:
    """Stamp a successful normalized result (from RDAP or WHOIS) into an envelope."""
    norm.update(
        {
            "ok": True,
            "schema_version": SCHEMA_VERSION,
            "checked_at": now_iso(),
            "apex": apex,
            "cache_age_seconds": 0,
        }
    )
    return norm


def _query_rdap(apex: str) -> dict[str, Any] | None:
    """Return a normalized registration dict from RDAP, or None to fall back.

    Returns None on: no RDAP server for the TLD (NotImplementedError),
    not-found, transport/JSON error, or a response that lacks a usable expiry
    (unless the TLD legitimately has no expiry). Any of these defers to WHOIS.
    """
    try:
        import asyncwhois
    except ImportError:
        return None
    try:
        raw_json, _ = asyncwhois.rdap(apex)
        d = json.loads(raw_json)
    except Exception:  # noqa: BLE001 — any RDAP issue means "try WHOIS instead"
        return None
    norm = _normalize_rdap(d, tld_of(apex))
    if norm["days_to_expire"] is None and not norm["provider_no_expiry"]:
        return None
    return norm


def _query_whois_port43(apex: str) -> dict[str, Any]:
    """One-shot port-43 WHOIS via asyncwhois with retries and a 10 s wall cap.

    Returns a *bare* normalized dict (no `ok`/envelope keys) on a parseable
    response, or a `whois_error_envelope` on a transport-level failure. Zabbix
    SIGKILLs externalscripts after their Timeout; cap total wall-time to 10 s
    and skip the post-failure sleep.
    """
    try:
        import asyncwhois
    except ImportError as e:
        return whois_error_envelope("missing_dependency", f"asyncwhois not importable: {e}", apex=apex)

    extractor = _get_psl_extractor()
    deadline = time.monotonic() + 10.0
    backoffs = [0.5, 1.5]
    raw: str = ""
    parsed: dict[str, Any] = {}
    last_err = ""
    for attempt in range(3):
        if time.monotonic() >= deadline:
            return whois_error_envelope(
                "whois_timeout", f"deadline exceeded after {attempt} attempts: {last_err}", apex=apex
            )
        try:
            raw, parsed = asyncwhois.whois(apex, tldextract_obj=extractor)
            break
        except Exception as e:  # noqa: BLE001 — asyncwhois surfaces a wide error variety
            last_err = f"{type(e).__name__}: {e}"
            if attempt < len(backoffs):
                remaining = deadline - time.monotonic()
                sleep_for = min(backoffs[attempt], max(0.0, remaining - 0.5))
                if sleep_for > 0:
                    time.sleep(sleep_for)
    else:
        return whois_error_envelope("whois_unreachable", last_err, apex=apex)

    return _normalize_whois(parsed or {}, raw or "", tld_of(apex))
```

- [ ] **Step 4: Point `check_whois` at the new entry point**

In `check_whois()`, change line 992 from:
```python
        result = _query_whois(apex)
```
to:
```python
        result = _query_registration(apex)
```

- [ ] **Step 5: Update the stale `_query_whois` caller in `test_whois.py`**

In `scripts/tests/test_whois.py`, the test `test_query_whois_incomplete_gtld_returns_supported_error_payload` calls `_query_whois` and stubs only `whois`. Update it so RDAP is stubbed to defer and it calls the new entry point. Replace its body's stub + call lines:

```python
    def fake_whois(domain, **kwargs):
        return ("Domain Name: SEAREGION.COM\nRegistrar WHOIS Server: whois.reg.ru\n", {"registrar": "REG.RU"})

    def fake_rdap(domain):
        raise NotImplementedError("No RDAP server found")

    monkeypatch.setitem(sys.modules, "asyncwhois", types.SimpleNamespace(whois=fake_whois, rdap=fake_rdap))
    monkeypatch.setattr(web_check_module, "_get_psl_extractor", lambda: object())

    out = web_check_module._query_registration("searegion.com")
```
(Leave the assertions as-is — `error_code == "whois_incomplete"`, `source == "asyncwhois"`, `days_to_expire == 0`, etc. still hold via the WHOIS fallback path.)

- [ ] **Step 6: Run the RDAP + WHOIS tests**

Run: `cd /opt/zabbix-webservices && python3 -m pytest scripts/tests/test_rdap.py scripts/tests/test_whois.py -q`
Expected: PASS (all)

- [ ] **Step 7: Commit**

```bash
git add scripts/externalscripts/web_check.py scripts/tests/test_rdap.py scripts/tests/test_whois.py
git commit -m "feat(web_check): RDAP-first query with port-43 WHOIS fallback (_query_registration)"
```

---

## Task 4: Version + cache schema bump (2.2.0 / SCHEMA_VERSION 3)

**Files:**
- Modify: `scripts/externalscripts/web_check.py:47-48`
- Test: `scripts/tests/test_cache.py` (existing schema test)

- [ ] **Step 1: Update the cache schema test to assert v3 invalidation**

In `scripts/tests/test_cache.py`, `test_old_whois_cache_schema_is_ignored` already writes `SCHEMA_VERSION - 1` and asserts a miss — it stays correct after the bump (it is relative). No change needed there. Add an explicit version assertion test:

```python
def test_schema_version_is_3(web_check_module):
    assert web_check_module.SCHEMA_VERSION == 3
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd /opt/zabbix-webservices && python3 -m pytest scripts/tests/test_cache.py::test_schema_version_is_3 -q`
Expected: FAIL — `assert 2 == 3`

- [ ] **Step 3: Bump version and schema**

In `scripts/externalscripts/web_check.py` lines 47-48, change:
```python
__version__ = "2.1.8"
SCHEMA_VERSION = 2
```
to:
```python
__version__ = "2.2.0"
SCHEMA_VERSION = 3
```

- [ ] **Step 4: Run the full test suite**

Run: `cd /opt/zabbix-webservices && python3 -m pytest scripts/tests/ -q`
Expected: PASS (all previously-passing tests + new RDAP tests; only the optional-dependency skips remain — `trustme`, `aioquic`, `asyncwhois` not installed locally).

- [ ] **Step 5: Commit**

```bash
git add scripts/externalscripts/web_check.py scripts/tests/test_cache.py
git commit -m "feat(web_check): bump to 2.2.0, cache SCHEMA_VERSION 2->3 for RDAP cutover"
```

---

## Task 5: CHANGELOG + branch finish

**Files:**
- Modify: `CHANGELOG.md` (top, under the header)

- [ ] **Step 1: Add the CHANGELOG entry**

Insert above the most recent `## [...]` entry in `CHANGELOG.md`:

```markdown
## [7.0-2.2.6 / web_check 2.2.0] - 2026-06-01

### web_check 2.2.0 — RDAP-first registration lookup
RDAP (RFC 9082/9083) is authoritative for gTLDs since ICANN's 2025 WHOIS
sunset; some registries (e.g. Identity Digital `.center`) no longer serve
usable port-43 WHOIS. `web_check` now queries RDAP first and falls back to
port-43 WHOIS.

- **`_query_registration`** tries `asyncwhois.rdap()` first (IANA-bootstrapped
  by `whodap`), then `asyncwhois.whois()`. RDAP-less TLDs (`.ru`/`.рф` via TCI)
  fail the RDAP bootstrap locally (~0.4 s) and use the unchanged port-43 path
  and its TCI augmenters.
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
```

- [ ] **Step 2: Run the full suite once more, then finish the branch**

Run: `cd /opt/zabbix-webservices && python3 -m pytest scripts/tests/ -q`
Expected: PASS.

```bash
git add CHANGELOG.md
git commit -m "docs(changelog): web_check 2.2.0 RDAP-first lookup"
```

- [ ] **Step 3: Use the finishing-a-development-branch skill**

Invoke `superpowers:finishing-a-development-branch` to merge the work to `main` and push (matching the repo's `--no-ff` merge-commit pattern; no `Co-Authored-By` trailers).

---

## Task 6: Deploy to production and verify

**Not a code task** — operational rollout. Requires SSH to the monitor nodes.

- [ ] **Step 1: Redeploy `web_check` 2.2.0 to all six nodes**

Server + four reachable proxies (idempotent, pulls `main`):
```bash
for h in mon.itforprof.com et-vps01 sr-vps01 ifp-vps12 ifp-vps15; do
  echo "== $h =="
  ssh -o BatchMode=yes "$h" 'curl -fsSL https://raw.githubusercontent.com/IT-for-Prof/zabbix-webservices/main/scripts/deploy/install.sh | sudo sh' 2>&1 | grep -E 'self-test|installed web_check|"version"|error|Traceback'
done
```
Expected per node: `"version":"2.2.0"`, `self-test` `"ok":true`.

`TRC-ENERGY-ZBX-PROXY` (proxyid 13741) has **no SSH alias on this box** — it must be redeployed by someone with access to the TRC-ENERGY network (same `install.sh` one-liner). It serves only the `energy-h.ru` (`.ru`) hosts, which use WHOIS regardless, so RDAP is not required there — but it should still move to 2.2.0 for the schema/version parity (and it is still on stale 2.1.x from the 2.1.8 miss).

- [ ] **Step 2: Force a fresh WHOIS poll on `elma.hss.center` and confirm the fix**

```bash
# itemid 415996 = web_check.whois.ok master's dependent; use the master item.
# Trigger check-now on the hss.center WHOIS master, then read back via the API.
```
Use the Zabbix API: `task.create` (type 6, the `web_check.py["whois",...]` master item on hostid 13802), wait one poll, then `item.get` the `web_check.whois.ok` / `web_check.whois.expires_at` / `web_check.whois.error_code` items for hostid 13802.
Expected: `ok=1`, `expires_at` starts `2026-10-10`, `error_code=""`.

- [ ] **Step 3: Confirm the acknowledged `whois_incomplete` problem auto-resolves**

`problem.get` for hostid 13802 / the `WHOIS check failing` trigger — expected: no active problem (the event acknowledged earlier resolves once `ok=1`).

- [ ] **Step 4: Spot-check a `.com` owner did not regress and shows RDAP source**

`item.get` `web_check.whois.source` (if present) or re-poll `searegion.com`; confirm `expires_at` unchanged and no new `Domain registrar changed` / `Domain name servers changed` problems appeared.

- [ ] **Step 5: Update the rollout memory**

Record in `/home/kos/.claude/projects/-opt-zabbix-webservices/memory/project_domain_registry_dedup_rollout.md`: web_check 2.2.0 RDAP-first shipped; nodes upgraded; `hss.center` expiry restored; TRC-ENERGY status.

---

## Self-review

- **Spec coverage:** RDAP-first+fallback (Task 3) ✓; `_normalize_rdap` field paths (Task 2) ✓; no new dependency (noted, no `requirements.lock` change) ✓; SCHEMA_VERSION 2→3 (Task 4) ✓; transition value-neutral / no sort / no suppression (no such code added) ✓; fixtures = real recorded JSON for both `.com` eventAction variants + `.center` + signed + maxSigLife edge (Task 1) ✓; preserve apex dedup/cache/TCI augmenters/no-nulls/dnssec tri-state/provider_no_expiry (the WHOIS path and envelope are untouched) ✓; deploy all six nodes incl. TRC-ENERGY + RDAP-egress note (Task 6) ✓; verify hss.center + event auto-resolve (Task 6) ✓.
- **Placeholder scan:** none — every code step shows full code; commands have expected output.
- **Type consistency:** `_query_registration` / `_query_rdap` / `_query_whois_port43` / `_finalize_registration` / `_normalize_rdap` / `_parse_rdap_dt` / `_vcard_get` / `_rdap_find_entity` / `_rdap_registrar` names are used consistently across Tasks 2-4; `check_whois` calls `_query_registration`; envelope keys match `_normalize_whois` exactly.
