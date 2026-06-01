"""Tests for RDAP (RFC 9083) normalization, using recorded real responses."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest

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
    assert out["days_to_expire"] is None


@pytest.mark.parametrize(
    "payload",
    [
        {"events": ["x", 123, None]},
        {"status": 5},
        {"status": {"weird": True}},
        {"nameservers": [{"ldhName": 123}, {"ldhName": "NS1.Example.COM."}]},
        {"entities": [{"roles": "registrar", "vcardArray": ["vcard", [["fn", {}, "text", "X"]]]}]},
        {"entities": ["junk", 5, {"roles": ["registrar"], "publicIds": ["x", 7]}]},
        {"secureDNS": "nope"},
    ],
)
def test_rdap_malformed_never_raises_and_no_nulls(web_check_module, payload):
    out = web_check_module._normalize_rdap(payload, "com")
    for k in (
        "source",
        "registrar",
        "registrar_iana_id",
        "registered_at",
        "last_updated",
        "expires_at",
        "abuse_email",
        "dnssec",
    ):
        assert isinstance(out[k], str)
    assert isinstance(out["statuses"], list)
    assert isinstance(out["name_servers"], list)
    assert out["days_to_expire"] is None or isinstance(out["days_to_expire"], int)


def test_rdap_string_roles_not_substring_matched(web_check_module):
    # roles as a bare string must NOT be substring-matched into a registrar hit
    d = {"entities": [{"roles": "sub-registrar-x", "vcardArray": ["vcard", [["fn", {}, "text", "Nope"]]]}]}
    out = web_check_module._normalize_rdap(d, "com")
    assert out["registrar"] == ""


def test_rdap_registry_expiration_fallback(web_check_module):
    d = {"events": [{"eventAction": "registry expiration", "eventDate": "2029-09-09T00:00:00Z"}]}
    out = web_check_module._normalize_rdap(d, "com")
    assert out["expires_at"].startswith("2029-09-09")


def test_rdap_expiration_wins_over_registrar_expiration(web_check_module):
    d = {
        "events": [
            {"eventAction": "registrar expiration", "eventDate": "2030-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2028-01-01T00:00:00Z"},
        ]
    }
    out = web_check_module._normalize_rdap(d, "com")
    assert out["expires_at"].startswith("2028-01-01")


def _fake_asyncwhois(*, rdap=None, whois=None):
    """Build a fake asyncwhois module with given rdap/whois callables."""

    def _raise(name):
        def _f(*a, **k):
            raise AssertionError(f"{name} should not be called")

        return _f

    return types.SimpleNamespace(rdap=rdap or _raise("rdap"), whois=whois or _raise("whois"))


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
    monkeypatch.setattr(web_check_module.time, "sleep", lambda *_: None)
    out = web_check_module._query_registration("example.ru")
    assert out["ok"] is False
    assert out["error_code"] == "whois_unreachable"


def test_query_rdap_skips_when_deadline_exhausted(monkeypatch, web_check_module):
    called = {"rdap": False}

    def rdap_spy(apex, **k):
        called["rdap"] = True
        return ("{}", {})

    monkeypatch.setitem(sys.modules, "asyncwhois", _fake_asyncwhois(rdap=rdap_spy))
    out = web_check_module._query_rdap("example.com", web_check_module.time.monotonic() - 1)
    assert out is None
    assert called["rdap"] is False  # no work attempted past the shared deadline


def test_query_whois_port43_respects_shared_deadline(monkeypatch, web_check_module):
    def whois_spy(apex, **k):
        raise AssertionError("whois must not be called past the deadline")

    monkeypatch.setitem(sys.modules, "asyncwhois", _fake_asyncwhois(whois=whois_spy))
    monkeypatch.setattr(web_check_module, "_get_psl_extractor", lambda: object())
    out = web_check_module._query_whois_port43("example.com", web_check_module.time.monotonic() - 1)
    assert out["error_code"] == "whois_timeout"
