"""Static checks for the shipped Zabbix template contract."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TEMPLATE_PATH = REPO_ROOT / "templates" / "web-service-by-itforprof" / "template_web_service_by_itforprof_com.yaml"
TCP_HTTPS_KEY = "net.tcp.service.perf[https,{$WEB_SERVICE.HOST},{$WEB_SERVICE.HTTPS.PORT}]"
TCP_HTTP_KEY = "net.tcp.service.perf[http,{$WEB_SERVICE.HOST},{$WEB_SERVICE.HTTP.PORT}]"
TCP_FAILED = "TCP {$WEB_SERVICE.HTTPS.PORT} connect failed"
TCP_SLOW = "TCP {$WEB_SERVICE.HTTPS.PORT} connect slow"
PORT_MISMATCH = "HTTPS port macro does not match the URL port"
HOST_MISMATCH = "Host macro does not match the URL host"
TCP_NODATA = "TCP check no data received"
WEB_NODATA = "Web service no data received"
# Dependents of the cert master that only the full profile has (the mismatch checks).
FULL_ONLY_CERT_DEPENDENTS = {"web_check.cert.port", "web_check.cert.host"}


def _template() -> dict:
    with TEMPLATE_PATH.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)["zabbix_export"]["templates"][0]


def test_whois_expiry_triggers_only_evaluate_when_whois_ok():
    """Expiry tiers must stay silent while the WHOIS probe is failing.

    Dependency suppression alone is not enough in Zabbix: if a referenced
    item is unsupported, the trigger itself enters an evaluation error before
    dependencies can hide any problem event.
    """
    master = next(item for item in _template()["items"] if item["key"].startswith('web_check.py["whois"'))
    expiry_triggers = [
        trigger
        for trigger in master["triggers"]
        if trigger["name"].startswith("Domain expired") or trigger["name"].startswith("Domain expires within")
    ]

    assert expiry_triggers
    for trigger in expiry_triggers:
        assert "web_check.whois.ok)=1" in trigger["expression"], trigger["name"]
        for dependency in trigger.get("dependencies", []):
            expression = dependency["expression"]
            if "web_check.whois.days_to_expire" in expression:
                assert "web_check.whois.ok)=1" in expression, dependency["name"]


def test_whois_change_triggers_are_clean_change_detectors():
    """The WHOIS registrar/NS/DNSSEC change-triggers are bare change() detectors.

    The sentinel discard at the item layer (see
    test_whois_identity_items_discard_error_envelope_sentinels) makes change()
    authoritative, so the old in-expression guards (ok=1, length>0, <>""/<>"null"
    /<>"[]", dnssec #2="signed") are removed — they masked only the entering-error
    edge, not recovery, and the dnssec #2 guard caused a removal-through-outage
    false negative. One mechanism, mirroring the cert change-triggers.
    """
    by_name = {
        trigger["name"]: trigger["expression"]
        for item in _template()["items"]
        for trigger in item.get("triggers", []) or []
    }
    registrar = by_name["Domain registrar changed"]
    name_servers = by_name["Domain name servers changed"]
    dnssec = by_name["Domain DNSSEC removed"]

    assert registrar == "change(/Web service by itforprof.com/web_check.whois.registrar)=1"
    assert name_servers == "change(/Web service by itforprof.com/web_check.whois.name_servers)=1"
    # DNSSEC keeps last(...)="unsigned" (that is the removal condition, not a
    # redundant guard) but drops the now-implied #2="signed" and the ok=1 gate.
    assert dnssec == (
        "change(/Web service by itforprof.com/web_check.whois.dnssec)=1 and "
        'last(/Web service by itforprof.com/web_check.whois.dnssec)="unsigned"'
    )
    for expr in (registrar, name_servers, dnssec):
        assert "web_check.whois.ok)=1" not in expr
        assert ",#2)" not in expr
        assert "length(" not in expr


def test_whois_expiry_triggers_require_valid_expiry_item():
    master = next(item for item in _template()["items"] if item["key"].startswith('web_check.py["whois"'))
    expiry_triggers = [
        trigger
        for trigger in master["triggers"]
        if trigger["name"].startswith("Domain expired") or trigger["name"].startswith("Domain expires within")
    ]

    assert expiry_triggers
    for trigger in expiry_triggers:
        assert "web_check.whois.expires_at" in trigger["expression"], trigger["name"]
        assert "length(last(/Web service by itforprof.com/web_check.whois.expires_at))>0" in trigger["expression"], (
            trigger["name"]
        )


def test_whois_error_details_are_exposed_as_dependent_items():
    keys = {item["key"] for item in _template()["items"]}
    assert "web_check.whois.error_code" in keys
    assert "web_check.whois.error_message" in keys


CERT_CHANGE_TRIGGERS = {"Cert rotated", "Cert rotated unexpectedly (was about to expire)"}


def _cert_triggers_by_name() -> dict:
    return {
        trigger["name"]: trigger
        for item in _template()["items"]
        for trigger in item.get("triggers", []) or []
        if trigger["name"] in CERT_CHANGE_TRIGGERS
    }


def _fingerprint_item() -> dict:
    return next(item for item in _template()["items"] if item["key"] == "web_check.cert.fingerprint_sha256")


def test_fingerprint_item_discards_non_hex_error_envelope():
    """The fix: the fingerprint series must hold ONLY real 64-hex fingerprints.

    On a failed cert check the error envelope yields fingerprint="". Discarding
    any non-64-hex value at the item layer keeps that "" out of history, so the
    change()-based rotation triggers can only ever see a genuine real->real
    rotation. This is what kills the recovery-from-outage false positive
    WITHOUT introducing the late-rotation false negative that an in-trigger
    last(,#2) guard would (the "" is dropped, leaving old->new).
    """
    steps = _fingerprint_item()["preprocessing"]
    types = [s["type"] for s in steps]
    assert "MATCHES_REGEX" in types, types
    regex_idx = types.index("MATCHES_REGEX")
    regex_step = steps[regex_idx]
    assert regex_step["parameters"] == ["^[0-9A-Fa-f]{64}$"], regex_step
    assert regex_step["error_handler"] == "DISCARD_VALUE", regex_step
    # Must run before the discard-unchanged step so a dropped "" is never
    # compared as an "unchanged" value.
    assert regex_idx < types.index("DISCARD_UNCHANGED_HEARTBEAT"), types


def test_cert_change_triggers_are_clean_change_detectors():
    """With the series kept clean at the item layer, the triggers stay simple.

    No in-trigger cert.ok / length / #2 guards: those would either reintroduce
    the false positive (drop #2) or suppress a real late rotation that spanned a
    failed poll (keep #2). The discard step makes change() authoritative.
    """
    triggers = _cert_triggers_by_name()
    assert triggers.keys() >= CERT_CHANGE_TRIGGERS
    fp = "/Web service by itforprof.com/web_check.cert.fingerprint_sha256"
    for name, trigger in triggers.items():
        expression = trigger["expression"]
        assert f"change({fp})=1" in expression, name
        assert "#2" not in expression, name
        assert "web_check.cert.ok)=1" not in expression, name


def _triggers_by_name(template: dict | None = None) -> dict:
    template = template or _template()
    return {t["name"]: t for item in template["items"] for t in item.get("triggers", []) or []}


def _item_by_key(key: str) -> dict:
    return next(item for item in _template()["items"] if item["key"] == key)


def _discard_step(item: dict) -> dict:
    """The MATCHES/NOT_MATCHES regex step that drops error-envelope sentinels."""
    steps = item["preprocessing"]
    types = [s["type"] for s in steps]
    regex_types = {"MATCHES_REGEX", "NOT_MATCHES_REGEX"}
    idx = next(i for i, ty in enumerate(types) if ty in regex_types)
    # Must run before discard-unchanged so a dropped sentinel is never compared.
    assert idx < types.index("DISCARD_UNCHANGED_HEARTBEAT"), types
    step = steps[idx]
    assert step["error_handler"] == "DISCARD_VALUE", step
    return step


def test_whois_identity_items_discard_error_envelope_sentinels():
    """Same class as the cert fingerprint fix, applied to the WHOIS edge-trigger
    items. Discarding the per-field sentinels at ingestion keeps the change()
    triggers to genuine value moves: it kills the WHOIS-outage recovery false
    positive on registrar/name_servers, and (by dropping "unknown") lets a real
    DNSSEC removal that spanned a failed poll still fire.
    """
    reg = _discard_step(_item_by_key("web_check.whois.registrar"))
    assert reg["type"] == "NOT_MATCHES_REGEX"
    assert reg["parameters"] == ["^(null)?$"], reg  # drops "" and "null"

    ns = _discard_step(_item_by_key("web_check.whois.name_servers"))
    assert ns["type"] == "NOT_MATCHES_REGEX"
    assert ns["parameters"] == ["^\\[\\]$"], ns  # drops "[]"

    dnssec = _discard_step(_item_by_key("web_check.whois.dnssec"))
    assert dnssec["type"] == "MATCHES_REGEX"
    assert dnssec["parameters"] == ["^(signed|unsigned)$"], dnssec  # keeps only actionable states


def test_cert_rotated_late_still_reads_outgoing_cert_window():
    """The WARNING late-rotation trigger must keep the 2h:now-15m max() window."""
    trigger = _cert_triggers_by_name()["Cert rotated unexpectedly (was about to expire)"]
    assert "max(/Web service by itforprof.com/web_check.cert.days_to_expire,2h:now-15m)" in trigger["expression"]
    assert "{$WEB_SERVICE.CERT.ROTATE_MIN_DAYS}" in trigger["expression"]


def test_cert_rotated_late_is_warning_not_high():
    """Late rotation is a retrospective near-miss (a fresh cert is already
    installed), so it stays a dashboard WARNING below the Average ticketing
    threshold — never HIGH."""
    trigger = _cert_triggers_by_name()["Cert rotated unexpectedly (was about to expire)"]
    assert trigger["priority"] == "WARNING", trigger.get("priority")


def test_template_vendor_version_was_bumped_for_contract_change():
    assert _template()["vendor"]["version"] == "7.0-2.7.0"


@pytest.mark.parametrize(
    "filename,nodata_period",
    [
        ("template_web_service_by_itforprof_com.yaml", "15m"),
        ("template_web_service_by_itforprof_com_tls.yaml", "{$WEB_SERVICE.CERT.NODATA.PERIOD}"),
    ],
)
def test_persistent_cert_failure_escalates_after_three_polls_and_requires_fresh_data(filename, nodata_period):
    template = yaml.safe_load((TEMPLATE_PATH.parent / filename).read_text())["zabbix_export"]["templates"][0]
    items = {item["key"]: item for item in template["items"]}
    check = items["web_check.cert.ok"]
    triggers = {trigger["name"]: trigger for trigger in check["triggers"]}
    persistent = triggers["Cert check failing on 3 consecutive checks"]
    assert persistent["priority"] == "AVERAGE"
    profile = template["template"]
    fresh = f'nodata(/{profile}/web_check.py["cert","{{$WEB_SERVICE.URL}}"],{nodata_period})'
    failing = f'count(/{profile}/web_check.cert.ok,#3,"eq",0)=3 and {fresh}=0'
    if "_tls" in filename:
        assert persistent["expression"] == failing
        assert "recovery_expression" not in persistent
    else:
        tcp_ok = f"min(/{profile}/{TCP_HTTPS_KEY},#3)>0"
        assert persistent["expression"] == f"{failing} and {tcp_ok}"
        assert persistent["recovery_mode"] == "RECOVERY_EXPRESSION"
        assert persistent["recovery_expression"] == f"last(/{profile}/web_check.cert.ok)=1 or {fresh}=1"
    # A dependency freezes an open problem and re-fires on stale history when the parent recovers.
    assert not persistent.get("dependencies")
    assert all(step["type"] != "DISCARD_UNCHANGED_HEARTBEAT" for step in check["preprocessing"])
    immediate = triggers["Cert check failing"]
    assert immediate["priority"] == "INFO"
    assert immediate["expression"] == f"last(/{profile}/web_check.cert.ok)=0"


def test_http3_unreachable_needs_three_consecutive_failed_checks():
    """One lost DNS or UDP packet must not page anyone.

    `#3` counts stored values, so both inputs must be stored on every check
    without dns_error: with DISCARD_UNCHANGED_HEARTBEAT a run of zeros is one
    value, and the trigger would wait for heartbeats (hours) instead of three
    checks.
    """
    items = {item["key"]: item for item in _template()["items"]}
    for key in ("web_check.http3.alt_svc_advertised", "web_check.http3.reachable"):
        types = [s["type"] for s in items[key]["preprocessing"]]
        assert not any(t.startswith("DISCARD_UNCHANGED") for t in types), (key, types)

    trigger = next(
        t
        for t in items['web_check.py["http3","{$WEB_SERVICE.URL}"]']["triggers"]
        if t["name"] == "HTTP/3 advertised but unreachable"
    )
    assert "min(/Web service by itforprof.com/web_check.http3.alt_svc_advertised,#3)=1" in trigger["expression"]
    assert "max(/Web service by itforprof.com/web_check.http3.reachable,#3)=0" in trigger["expression"]
    assert trigger["priority"] == "AVERAGE", trigger["priority"]


def test_http3_dns_error_checks_are_not_quic_attempts(monkeypatch, web_check_module):
    """A check whose QUIC-path resolve failed is dropped from BOTH trigger inputs.

    Dropping it from `reachable` alone would shift that item's `#3` window back
    onto zeros from checks where Alt-Svc itself failed, while `advertised` keeps
    its last three checks — the trigger would fire without a single QUIC attempt.
    The regex runs against the script's real payload, as `emit` serialises it.
    """
    import json
    import re
    import socket

    web_check = web_check_module

    def no_dns(*a, **kw):
        raise socket.gaierror(socket.EAI_AGAIN, "Temporary failure in name resolution")

    monkeypatch.setattr(web_check, "_alt_svc_advertises_h3", lambda *a, **kw: True)
    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    dns_payload = json.dumps(web_check.run_http3_check("https://example.com", timeout=0.1), separators=(",", ":"))
    ok_payload = dns_payload.replace('"error_code":"dns_error"', '"error_code":""')

    items = {item["key"]: item for item in _template()["items"]}
    for key in ("web_check.http3.alt_svc_advertised", "web_check.http3.reachable"):
        steps = items[key]["preprocessing"]
        first = steps[0]
        assert first["type"] == "NOT_MATCHES_REGEX", (key, first)
        assert first["error_handler"] == "DISCARD_VALUE", (key, first)
        assert steps[1]["type"] == "JSONPATH", (key, steps[1])
        assert re.search(first["parameters"][0], dns_payload), (key, dns_payload)
        assert not re.search(first["parameters"][0], ok_payload), (key, ok_payload)


def test_whois_event_names_reference_data_items_after_ok_guard():
    triggers = [trigger for item in _template()["items"] for trigger in item.get("triggers", []) or []]
    event_name_by_trigger = {trigger["name"]: trigger.get("event_name", "") for trigger in triggers}

    assert event_name_by_trigger["Domain expired"] == (
        "Domain {ITEM.LASTVALUE4} expired ({ITEM.LASTVALUE3} past) (host: {HOST.HOST})"
    )
    for name in (
        "Domain expires within {$WEB_SERVICE.WHOIS.CRIT_DAYS} day(s)",
        "Domain expires within {$WEB_SERVICE.WHOIS.NOTICE_DAYS} days",
        "Domain expires within {$WEB_SERVICE.WHOIS.WARN_DAYS} days",
    ):
        assert event_name_by_trigger[name] == (
            "Domain {ITEM.LASTVALUE5} expires in {ITEM.LASTVALUE3} (host: {HOST.HOST})"
        )
    assert event_name_by_trigger["Domain registrar changed"].startswith("Registrar changed to {ITEM.LASTVALUE2}")
    assert event_name_by_trigger["Domain name servers changed"].startswith("Name servers changed to {ITEM.LASTVALUE2}")


def test_whois_expiry_tags_and_descriptions_reference_apex_item():
    triggers = [trigger for item in _template()["items"] for trigger in item.get("triggers", []) or []]
    by_name = {trigger["name"]: trigger for trigger in triggers}

    expired = by_name["Domain expired"]
    assert "apex {ITEM.LASTVALUE4}" in expired["description"]
    assert next(tag["value"] for tag in expired["tags"] if tag["tag"] == "apex") == "{ITEM.LASTVALUE4}"

    for name in (
        "Domain expires within {$WEB_SERVICE.WHOIS.CRIT_DAYS} day(s)",
        "Domain expires within {$WEB_SERVICE.WHOIS.NOTICE_DAYS} days",
        "Domain expires within {$WEB_SERVICE.WHOIS.WARN_DAYS} days",
    ):
        trigger = by_name[name]
        assert next(tag["value"] for tag in trigger["tags"] if tag["tag"] == "apex") == "{ITEM.LASTVALUE5}"


def test_trigger_dependency_expressions_match_target_triggers():
    triggers = [trigger for item in _template()["items"] for trigger in item.get("triggers", []) or []]
    expression_by_name = {trigger["name"]: trigger["expression"] for trigger in triggers}

    for trigger in triggers:
        for dependency in trigger.get("dependencies", []) or []:
            assert dependency["expression"] == expression_by_name[dependency["name"]], dependency["name"]


def test_tls_scan_timeout_trigger_matches_the_script_payload(monkeypatch, web_check_module):
    """Two timed-out nightly scans in a row raise an INFO event, unless the TCP check already reports the host down.

    The like-pattern is checked against the script's real tls_scan_timeout payload, so a renamed
    error code cannot silently disable the trigger.
    """
    import json
    import time

    pattern = "tls_scan_timeout"
    items = {item["key"]: item for item in _template()["items"]}
    trigger = next(
        t
        for t in items['web_check.py["tls-scan","{$WEB_SERVICE.URL}"]']["triggers"]
        if t["name"] == "TLS scan does not finish within its time limit"
    )
    assert trigger["expression"] == (
        'count(/Web service by itforprof.com/web_check.py["tls-scan","{$WEB_SERVICE.URL}"],#2,"like","'
        + pattern
        + '")=2'
    )
    assert trigger["priority"] == "INFO"
    assert [d["name"] for d in trigger["dependencies"]] == [TCP_FAILED]

    monkeypatch.setattr(web_check_module, "run_tls_scan", lambda url, timeout=10.0: time.sleep(1) or {})
    monkeypatch.setattr(web_check_module, "TLS_SCAN_BUDGET", 0.05)
    payload = json.dumps(web_check_module.bounded_tls_scan("https://example.com"), separators=(",", ":"))
    assert f'"error_code":"{pattern}"' in payload


def test_tls_scan_dependents_fail_on_error_envelope_instead_of_storing_defaults(monkeypatch, web_check_module):
    """The error envelope carries supported_protocols=[] and weak_count=0, so JSONPath alone would
    overwrite the last real values on every failed scan. A leading regex check turns it into the
    item error the CUSTOM_ERROR message already describes."""
    import json
    import re
    import time

    monkeypatch.setattr(web_check_module, "run_tls_scan", lambda url, timeout=10.0: time.sleep(1) or {})
    monkeypatch.setattr(web_check_module, "TLS_SCAN_BUDGET", 0.05)
    failed = json.dumps(web_check_module.bounded_tls_scan("https://example.com"), separators=(",", ":"))
    ok = failed.replace('"ok":false', '"ok":true')

    items = {item["key"]: item for item in _template()["items"]}
    for key in ("web_check.tls_scan.supported_protocols", "web_check.tls_scan.weak_count"):
        steps = items[key]["preprocessing"]
        assert steps[0]["type"] == "NOT_MATCHES_REGEX", (key, steps[0])
        assert steps[0]["error_handler"] == "CUSTOM_ERROR", (key, steps[0])
        assert steps[1]["type"] == "JSONPATH", (key, steps[1])
        assert re.search(steps[0]["parameters"][0], failed), key
        assert not re.search(steps[0]["parameters"][0], ok), key


PROFILES = ("template_web_service_by_itforprof_com.yaml", "template_web_service_by_itforprof_com_tls.yaml")


def _profile(filename: str) -> dict:
    return yaml.safe_load((TEMPLATE_PATH.parent / filename).read_text())["zabbix_export"]["templates"][0]


@pytest.mark.parametrize("filename", PROFILES)
def test_cert_dependents_discard_the_error_envelope(filename, web_check_module):
    """A failed cert probe fills cert/tls with stubs (hostname_covered=false, days_to_expire=0).

    Stored, they fired HIGH "hostname not covered" and "expires in 0 d". Dependency suppression
    on "Cert check failing" loses the race when both flip in one history-sync batch, so every
    dependent drops the whole envelope before JSONPath and keeps its last real value instead.
    """
    import json
    import re
    from dataclasses import asdict

    failed = json.dumps(asdict(web_check_module.check_cert("not a url at all", timeout=1)), separators=(",", ":"))
    ok = json.dumps(asdict(web_check_module.CertResult(ok=True)), separators=(",", ":"))

    template = _profile(filename)
    dependents = [
        i for i in template["items"] if i.get("master_item", {}).get("key", "").startswith('web_check.py["cert"')
    ]
    extra = FULL_ONLY_CERT_DEPENDENTS if filename == PROFILES[0] else set()
    assert extra <= {i["key"] for i in dependents}
    assert len(dependents) == 17 + len(extra)
    for item in dependents:
        first = item["preprocessing"][0]
        if item["key"] == "web_check.cert.ok":
            assert first["type"] == "JSONPATH", first
            continue
        assert first == {"type": "NOT_MATCHES_REGEX", "parameters": ['"ok":false'], "error_handler": "DISCARD_VALUE"}, (
            item["key"]
        )
        assert item["preprocessing"][1]["type"] == "JSONPATH", item["key"]
        assert re.search(first["parameters"][0], failed), item["key"]
        assert not re.search(first["parameters"][0], ok), item["key"]

    # With the envelope discarded the dependency suppresses nothing; it only froze recovery for the
    # 1h discard heartbeat when the probe came back in the same batch.
    triggers = [t for item in template["items"] for t in item.get("triggers", []) or []]
    assert all(d["name"] != "Cert check failing" for t in triggers for d in t.get("dependencies", []) or [])


@pytest.mark.parametrize("filename", PROFILES)
def test_severity_high_means_broken_for_users(filename):
    """HIGH = already broken for users, AVERAGE = still works but needs action; no DISASTER."""
    triggers = _triggers_by_name(_profile(filename))
    assert all(t["priority"] != "DISASTER" for t in triggers.values())
    expected = {
        "Cert expired": "HIGH",
        "Cert hostname not covered": "HIGH",
        "Cert chain untrusted": "HIGH",
        "Cert expires within {$WEB_SERVICE.CERT.CRIT_DAYS} days": "AVERAGE",
    }
    if filename == PROFILES[0]:
        expected |= {
            "Web service is failing": "HIGH",
            "Domain expired": "HIGH",
            "Domain expires within {$WEB_SERVICE.WHOIS.CRIT_DAYS} day(s)": "AVERAGE",
            TCP_FAILED: "AVERAGE",
        }
    assert {name: triggers[name]["priority"] for name in expected} == expected
    assert {t["name"] for t in triggers.values() if t["priority"] == "HIGH"} == {
        name for name, level in expected.items() if level == "HIGH"
    }


def test_availability_triggers_need_two_consecutive_failed_checks():
    """A single failed poll (median 45 s for the web scenario) must not open a problem."""
    triggers = _triggers_by_name()
    assert triggers["Web service is failing"]["expression"] == (
        "min(/Web service by itforprof.com/web.test.fail[Web service],#2)>0"
    )
    assert triggers[TCP_FAILED]["expression"].startswith(
        f"max(/Web service by itforprof.com/{TCP_HTTPS_KEY},#2)=0 and "
    )


def _all_expressions(template: dict) -> list[str]:
    found = []
    for item in template["items"]:
        found.append(item["key"])
        for trigger in item.get("triggers", []) or []:
            found += [trigger["expression"], trigger.get("recovery_expression", "")]
            found += [d["expression"] for d in trigger.get("dependencies", []) or []]
    return found


def test_tcp_ports_come_from_template_macros():
    """A site on a non-standard port gets its TCP diagnostics from one host macro, not a template fork."""
    template = _template()
    macros = {m["macro"]: m for m in template["macros"]}
    assert macros["{$WEB_SERVICE.HTTPS.PORT}"]["value"] == "443"
    assert macros["{$WEB_SERVICE.HTTP.PORT}"]["value"] == "80"
    assert all(macros[m].get("description") for m in ("{$WEB_SERVICE.HTTPS.PORT}", "{$WEB_SERVICE.HTTP.PORT}"))
    assert [s for s in _all_expressions(template) if ",443]" in s or ",80]" in s] == []


def test_tcp_objects_keep_identity_and_tags():
    """Import matches by uuid: the key change must update the existing items and keep their history."""
    https, http = _item_by_key(TCP_HTTPS_KEY), _item_by_key(TCP_HTTP_KEY)
    assert (https["uuid"], http["uuid"]) == ("117107c9c4c0479aa9825347cea751b9", "ccec84b433b442b7a9a94f9f409248c3")
    assert https["name"] == "Diag: TCP {$WEB_SERVICE.HTTPS.PORT} performance"
    assert http["name"] == "Diag: TCP {$WEB_SERVICE.HTTP.PORT} performance"
    triggers = {t["name"]: t for t in https["triggers"]}
    assert triggers[TCP_FAILED]["uuid"] == "fd0ada034a644ca3bf0086101c92395a"
    assert triggers[TCP_SLOW]["uuid"] == "ff15f34c63b247c8a7334a465c45bd73"
    for trigger in (triggers[TCP_FAILED], triggers[TCP_SLOW]):
        assert {t["tag"]: t["value"] for t in trigger["tags"]} == {"scope": "diag", "url": "{$WEB_SERVICE.URL}"}
        assert "443" not in trigger["event_name"] + trigger["description"]


def test_http3_description_names_the_url_port_not_443():
    triggers = _triggers_by_name()
    assert "UDP/443" not in triggers["HTTP/3 advertised but unreachable"]["description"]


def test_port_mismatch_warns_on_fresh_cert_port_only():
    """A forgotten {$WEB_SERVICE.HTTPS.PORT} on a host whose 443 answers would leave TCP diagnostics
    silently checking another service; the cert probe already reports the URL port, so compare them."""
    item = _item_by_key("web_check.cert.port")
    assert item["master_item"]["key"] == 'web_check.py["cert","{$WEB_SERVICE.URL}"]'
    assert item["value_type"] == "UNSIGNED"
    # Stored every poll (no heartbeat discard), read only by last(): keep it short.
    assert (item["history"], item["trends"]) == ("7d", "0")
    assert [step["type"] for step in item["preprocessing"]] == ["NOT_MATCHES_REGEX", "JSONPATH"]
    assert item["preprocessing"][1]["parameters"] == ["$.port"]
    assert {t["tag"]: t["value"] for t in item["tags"]} == {"scope": "diag"}

    [trigger] = item["triggers"]
    assert trigger["name"] == PORT_MISMATCH
    # Fresh-bounded: a cert outage closes it, so a stale mismatch cannot hide a real TCP failure,
    # and nodata() puts it on the 30s timer, so a corrected macro clears it without a new value.
    assert trigger["expression"] == (
        "last(/Web service by itforprof.com/web_check.cert.port)<>{$WEB_SERVICE.HTTPS.PORT}"
        " and nodata(/Web service by itforprof.com/web_check.cert.port,15m)=0"
    )
    assert trigger["priority"] == "WARNING"
    assert trigger["manual_close"] == "YES"
    assert {t["tag"]: t["value"] for t in trigger["tags"]} == {"scope": "diag", "url": "{$WEB_SERVICE.URL}"}
    assert "{$WEB_SERVICE.HTTPS.PORT}" in trigger["event_name"]
    assert "{ITEM.LASTVALUE1}" in trigger["event_name"]
    assert not trigger.get("dependencies")


def test_tcp_failure_is_suppressed_while_a_macro_mismatches():
    """A TCP check on the wrong port or host must not page; the mismatch WARNING names the real cause.

    The guard sits in the expression, not in a dependency: a dependency cannot close a TCP problem
    that opened before the mismatch was known, and it freezes the trigger while the parent is open.
    Without fresh certificate data (nodata) the guard lets the TCP failure through as before.
    """
    t = "/Web service by itforprof.com/"
    assert _triggers_by_name()[TCP_FAILED]["expression"] == (
        f"max({t}{TCP_HTTPS_KEY},#2)=0"
        f" and (last({t}web_check.cert.port)={{$WEB_SERVICE.HTTPS.PORT}} or nodata({t}web_check.cert.port,15m)=1)"
        f' and (last({t}web_check.cert.host)="{{$WEB_SERVICE.HOST}}" or nodata({t}web_check.cert.host,15m)=1)'
    )
    assert not _triggers_by_name()[TCP_FAILED].get("dependencies")


def test_tls_profile_has_no_tcp_port_objects():
    tls = _profile(PROFILES[1])
    assert all(not item["key"].startswith("net.tcp.") and item["key"] != "web_check.cert.port" for item in tls["items"])
    assert not {"{$WEB_SERVICE.HTTPS.PORT}", "{$WEB_SERVICE.HTTP.PORT}"} & {m["macro"] for m in tls.get("macros", [])}


def test_host_mismatch_warns_when_host_macro_differs_from_url_host():
    """An empty, misspelt or copied {$WEB_SERVICE.HOST} sends the TCP checks to another machine
    (or to the host interface, often 127.0.0.1) without any error; compare it with the URL host."""
    item = _item_by_key("web_check.cert.host")
    assert item["master_item"]["key"] == 'web_check.py["cert","{$WEB_SERVICE.URL}"]'
    assert item["value_type"] == "CHAR"
    assert item["history"] == "7d"
    assert [step["type"] for step in item["preprocessing"]] == ["NOT_MATCHES_REGEX", "JSONPATH"]
    assert item["preprocessing"][1]["parameters"] == ["$.host"]
    assert {t["tag"]: t["value"] for t in item["tags"]} == {"scope": "diag"}

    [trigger] = item["triggers"]
    assert trigger["name"] == HOST_MISMATCH
    assert trigger["expression"] == (
        'last(/Web service by itforprof.com/web_check.cert.host)<>"{$WEB_SERVICE.HOST}"'
        " and nodata(/Web service by itforprof.com/web_check.cert.host,15m)=0"
    )
    assert trigger["priority"] == "WARNING"
    assert trigger["manual_close"] == "YES"
    assert {t["tag"]: t["value"] for t in trigger["tags"]} == {"scope": "diag", "url": "{$WEB_SERVICE.URL}"}
    assert "{$WEB_SERVICE.HOST}" in trigger["event_name"]
    assert "{ITEM.LASTVALUE1}" in trigger["event_name"]
    assert not trigger.get("dependencies")


def test_silent_tcp_check_raises_no_data():
    """A NOTSUPPORTED https TCP item (bad port, no address) leaves the TCP triggers and the cert
    trigger's TCP gate UNKNOWN; without this the host just goes quiet."""
    triggers = {t["name"]: t for t in _item_by_key(TCP_HTTPS_KEY)["triggers"]}
    nodata = triggers[TCP_NODATA]
    web_silent = _triggers_by_name()[WEB_NODATA]["expression"]
    assert web_silent.endswith("=1")
    # One ticket per collector failure: gated in the expression, like the cert trigger (2.5.1).
    # A dependency would freeze it, and a NOTSUPPORTED item never brings the value that unfreezes it.
    assert nodata["expression"] == (
        f"nodata(/Web service by itforprof.com/{TCP_HTTPS_KEY},15m)=1 and {web_silent.removesuffix('=1')}=0"
    )
    assert not nodata.get("dependencies")
    assert nodata["priority"] == "AVERAGE"
    assert nodata["manual_close"] == "YES"
    assert {t["tag"]: t["value"] for t in nodata["tags"]} == {"scope": "data-collection", "url": "{$WEB_SERVICE.URL}"}
