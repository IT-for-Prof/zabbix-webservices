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
        if trigger["name"].startswith("Domain expired")
        or trigger["name"].startswith("Domain expires within")
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
    triggers = [
        trigger
        for item in _template()["items"]
        for trigger in item.get("triggers", []) or []
    ]
    expression_by_name = {trigger["name"]: trigger["expression"] for trigger in triggers}

    assert 'last(/Web service by itforprof.com/web_check.whois.registrar)<>""' in expression_by_name[
        "Domain registrar changed"
    ]
    assert 'last(/Web service by itforprof.com/web_check.whois.registrar)<>"null"' in expression_by_name[
        "Domain registrar changed"
    ]
    assert 'last(/Web service by itforprof.com/web_check.whois.name_servers)<>"[]"' in expression_by_name[
        "Domain name servers changed"
    ]


def test_dnssec_removed_requires_previous_signed_state():
    triggers = [
        trigger
        for item in _template()["items"]
        for trigger in item.get("triggers", []) or []
    ]
    expression = {trigger["name"]: trigger["expression"] for trigger in triggers}["Domain DNSSEC removed"]

    assert 'last(/Web service by itforprof.com/web_check.whois.dnssec,#2)="signed"' in expression


def test_whois_expiry_triggers_require_valid_expiry_item():
    master = next(item for item in _template()["items"] if item["key"].startswith('web_check.py["whois"'))
    expiry_triggers = [
        trigger
        for trigger in master["triggers"]
        if trigger["name"].startswith("Domain expired")
        or trigger["name"].startswith("Domain expires within")
    ]

    assert expiry_triggers
    for trigger in expiry_triggers:
        assert "web_check.whois.expires_at" in trigger["expression"], trigger["name"]
        assert "length(last(/Web service by itforprof.com/web_check.whois.expires_at))>0" in trigger[
            "expression"
        ], trigger["name"]


def test_whois_error_details_are_exposed_as_dependent_items():
    keys = {item["key"] for item in _template()["items"]}
    assert "web_check.whois.error_code" in keys
    assert "web_check.whois.error_message" in keys


def test_template_vendor_version_was_bumped_for_contract_change():
    assert _template()["vendor"]["version"] == "7.0-2.2.6"


def test_whois_event_names_reference_data_items_after_ok_guard():
    triggers = [
        trigger
        for item in _template()["items"]
        for trigger in item.get("triggers", []) or []
    ]
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
    assert event_name_by_trigger["Domain registrar changed"].startswith(
        "Registrar changed to {ITEM.LASTVALUE2}"
    )
    assert event_name_by_trigger["Domain name servers changed"].startswith(
        "Name servers changed to {ITEM.LASTVALUE2}"
    )


def test_whois_expiry_tags_and_descriptions_reference_apex_item():
    triggers = [
        trigger
        for item in _template()["items"]
        for trigger in item.get("triggers", []) or []
    ]
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
    triggers = [
        trigger
        for item in _template()["items"]
        for trigger in item.get("triggers", []) or []
    ]
    expression_by_name = {trigger["name"]: trigger["expression"] for trigger in triggers}

    for trigger in triggers:
        for dependency in trigger.get("dependencies", []) or []:
            assert dependency["expression"] == expression_by_name[dependency["name"]], dependency["name"]
