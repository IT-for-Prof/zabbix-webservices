"""Contract checks for the standalone certificate/TLS Zabbix profile."""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_PATH = REPO_ROOT / "templates" / "web-service-by-itforprof" / "template_web_service_by_itforprof_com_tls.yaml"
PROFILE_NAME = "Web service by itforprof.com - Certificate-TLS"
EXPECTED_ITEM_KEYS = {
    'web_check.py["cert","{$WEB_SERVICE.URL}"]',
    "web_check.cert.days_to_expire",
    "web_check.cert.not_after",
    "web_check.cert.subject_cn",
    "web_check.cert.issuer_cn",
    "web_check.cert.issuer_org",
    "web_check.cert.serial",
    "web_check.cert.sans",
    "web_check.cert.fingerprint_sha256",
    "web_check.cert.signature_algorithm",
    "web_check.cert.public_key_algorithm",
    "web_check.cert.public_key_bits",
    "web_check.cert.hostname_covered",
    "web_check.cert.chain_status",
    "web_check.cert.ok",
    "web_check.tls.protocol",
    "web_check.tls.cipher",
    "web_check.tls.handshake_ms",
}
EXPECTED_TRIGGER_NAMES = {
    "Cert externalscript no data received",
    "Cert expired",
    "Cert expires within {$WEB_SERVICE.CERT.CRIT_DAYS} days",
    "Cert expires within {$WEB_SERVICE.CERT.NOTICE_DAYS} days",
    "Cert expires within {$WEB_SERVICE.CERT.WARN_DAYS} days",
    "Cert rotated",
    "Cert rotated unexpectedly (was about to expire)",
    "Cert weak signature algorithm",
    "Cert weak public key",
    "Cert hostname not covered",
    "Cert chain untrusted",
    "Cert check failing",
    "TLS protocol weak (currently negotiating)",
}


def _template() -> dict:
    with TEMPLATE_PATH.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)["zabbix_export"]["templates"][0]


def test_tls_profile_contains_only_certificate_and_live_tls_checks():
    template = _template()
    assert template["template"] == PROFILE_NAME
    assert "httptests" not in template
    assert {item["key"] for item in template["items"]} == EXPECTED_ITEM_KEYS
    assert all(item["type"] in {"EXTERNAL", "DEPENDENT"} for item in template["items"])
    assert all("whois" not in item["key"] for item in template["items"])
    assert all("http3" not in item["key"] for item in template["items"])
    assert all("net.tcp.service" not in item["key"] for item in template["items"])


def test_tls_profile_uses_host_overridable_expiry_defaults():
    macros = {macro["macro"]: macro.get("value") for macro in _template()["macros"]}
    assert macros == {
        "{$WEB_SERVICE.URL}": None,
        "{$WEB_SERVICE.CERT.CHECK.INTERVAL}": "5m",
        "{$WEB_SERVICE.CERT.NODATA.PERIOD}": "15m",
        "{$WEB_SERVICE.CERT.WARN_DAYS}": "90",
        "{$WEB_SERVICE.CERT.NOTICE_DAYS}": "30",
        "{$WEB_SERVICE.CERT.CRIT_DAYS}": "7",
        "{$WEB_SERVICE.CERT.ROTATE_MIN_DAYS}": "3",
        "{$WEB_SERVICE.CERT.MIN_KEY_RSA}": "2048",
        "{$WEB_SERVICE.CERT.MIN_KEY_ECDSA}": "256",
    }


def test_tls_profile_has_certificate_triggers_only():
    triggers = [trigger for item in _template()["items"] for trigger in item.get("triggers", []) or []]
    assert {trigger["name"] for trigger in triggers} == EXPECTED_TRIGGER_NAMES
    assert all("Web service is failing" not in trigger["name"] for trigger in triggers)
    assert all("Web service by itforprof.com/" not in trigger.get("expression", "") for trigger in triggers)
    assert all("Certificate-TLS" in trigger.get("expression", "") for trigger in triggers)


def test_tls_profile_has_standalone_boolean_value_map_and_expected_severity():
    template = _template()
    assert template["valuemaps"] == [
        {
            "uuid": "f5e32c8a0d6b4cf4a3f534ee7e4a89b1",
            "name": "web_check: boolean",
            "mappings": [
                {"value": "0", "newvalue": "no"},
                {"value": "1", "newvalue": "yes"},
            ],
        }
    ]
    triggers = [trigger for item in template["items"] for trigger in item.get("triggers", []) or []]
    expired = next(trigger for trigger in triggers if trigger["name"] == "Cert expired")
    assert expired["priority"] == "HIGH"


def test_tls_profile_uuids_are_unique():
    template = _template()
    uuids = [template["uuid"]]
    uuids.extend(item["uuid"] for item in template["items"])
    uuids.extend(trigger["uuid"] for item in template["items"] for trigger in item.get("triggers", []) or [])
    assert len(uuids) == len(set(uuids))
