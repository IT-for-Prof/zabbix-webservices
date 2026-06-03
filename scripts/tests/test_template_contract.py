"""Static checks for the shipped Zabbix template contract."""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TEMPLATE_PATH = REPO_ROOT / "templates" / "web-service-by-itforprof" / "template_web_service_by_itforprof_com.yaml"


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


def test_whois_change_triggers_only_evaluate_when_whois_ok():
    master = next(item for item in _template()["items"] if item["key"].startswith('web_check.py["whois"'))
    dependent_items = [item for item in _template()["items"] if item.get("key", "").startswith("web_check.whois.")]
    triggers = [
        trigger
        for item in dependent_items
        for trigger in item.get("triggers", []) or []
        if trigger["name"] in {"Domain registrar changed", "Domain name servers changed", "Domain DNSSEC removed"}
    ]

    assert triggers
    assert master
    for trigger in triggers:
        assert "web_check.whois.ok)=1" in trigger["expression"], trigger["name"]


def test_whois_change_triggers_ignore_empty_registry_values():
    triggers = [trigger for item in _template()["items"] for trigger in item.get("triggers", []) or []]
    expression_by_name = {trigger["name"]: trigger["expression"] for trigger in triggers}

    assert (
        'last(/Web service by itforprof.com/web_check.whois.registrar)<>""'
        in expression_by_name["Domain registrar changed"]
    )
    assert (
        'last(/Web service by itforprof.com/web_check.whois.registrar)<>"null"'
        in expression_by_name["Domain registrar changed"]
    )
    assert (
        'last(/Web service by itforprof.com/web_check.whois.name_servers)<>"[]"'
        in expression_by_name["Domain name servers changed"]
    )


def test_dnssec_removed_requires_previous_signed_state():
    triggers = [trigger for item in _template()["items"] for trigger in item.get("triggers", []) or []]
    expression = {trigger["name"]: trigger["expression"] for trigger in triggers}["Domain DNSSEC removed"]

    assert 'last(/Web service by itforprof.com/web_check.whois.dnssec,#2)="signed"' in expression


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
    """The HIGH late-rotation trigger must keep the 2h:now-15m max() window."""
    trigger = _cert_triggers_by_name()["Cert rotated unexpectedly (was about to expire)"]
    assert "max(/Web service by itforprof.com/web_check.cert.days_to_expire,2h:now-15m)" in trigger["expression"]
    assert "{$WEB_SERVICE.CERT.ROTATE_MIN_DAYS}" in trigger["expression"]


def test_template_vendor_version_was_bumped_for_contract_change():
    assert _template()["vendor"]["version"] == "7.0-2.2.8"


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
