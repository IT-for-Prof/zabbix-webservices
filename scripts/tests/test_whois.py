"""WHOIS normalisation + TCI augmenter tests.

We don't hit the network — `asyncwhois.whois` is monkey-patched to return
canned tuples. This validates parser-output normalisation and our TCI
augmenter logic for `.рф` / `.ru` without flakiness.
"""

from __future__ import annotations

from datetime import UTC, datetime

TCI_RAW = """\
% TCI Whois Service. Terms of use:
% https://tcinet.ru/documents/whois_ru_rf.pdf (in Russian)

domain:        XN--80AAC7BMKKFG.XN--P1AI
nserver:       ns1.reg.ru.
nserver:       ns2.reg.ru.
state:         REGISTERED, DELEGATED, UNVERIFIED
registrar:     REGRU-RF
created:       2013-07-19T08:16:15Z
paid-till:     2026-07-19T09:16:15Z
source:        TCI
"""


def test_tci_augmenter_extracts_dates_and_ns(web_check_module):
    paid, created, ns = web_check_module._augment_tci_raw(TCI_RAW)
    assert paid == datetime(2026, 7, 19, 9, 16, 15, tzinfo=UTC)
    assert created == datetime(2013, 7, 19, 8, 16, 15, tzinfo=UTC)
    assert ns == ["ns1.reg.ru.", "ns2.reg.ru."]


def test_normalise_com_via_asyncwhois_shape(web_check_module):
    """gTLD .com via asyncwhois — parser already populated everything."""
    parsed = {
        "domain_name": "ITFORPROF.COM",
        "registrar": "REG.RU",
        "registrar_iana_id": "1606",
        "registrar_abuse_email": "abuse@reg.ru",
        "created": datetime(2016, 3, 21, 7, 52, 9, tzinfo=UTC),
        "updated": datetime(2026, 3, 7, tzinfo=UTC),
        "expires": datetime(2027, 3, 21, 7, 52, 9, tzinfo=UTC),
        "status": ["clientTransferProhibited"],
        "name_servers": ["NS1.REG.RU", "NS2.REG.RU"],
        "dnssec": "unsigned",
    }
    out = web_check_module._normalize_whois(parsed, raw="not used", tld="com")
    assert out["registrar"] == "REG.RU"
    assert out["expires_at"].startswith("2027-03-21")
    assert out["days_to_expire"] > 0
    assert out["name_servers"] == ["ns1.reg.ru", "ns2.reg.ru"]
    assert out["dnssec"] is False  # "unsigned" → False
    assert out["provider_no_expiry"] is False


def test_normalise_rf_invokes_augmenter(web_check_module):
    """asyncwhois .рф parser ships only registrar; expires comes from TCI raw."""
    parsed = {"registrar": "REGRU-RF"}
    out = web_check_module._normalize_whois(parsed, raw=TCI_RAW, tld="xn--p1ai")
    assert out["expires_at"].startswith("2026-07-19")
    assert out["registered_at"].startswith("2013-07-19")
    assert "ns1.reg.ru" in out["name_servers"]
    assert out["provider_no_expiry"] is False


def test_normalise_hu_marks_no_expiry(web_check_module):
    """Hungarian registry omits expiration intentionally."""
    parsed = {"domain_name": "casualstyle.hu", "registrar": None}
    raw_min = "% Whois server 4.0 serving the hu ccTLD\n\ndomain:         casualstyle.hu\nrecord created: 2021-02-24\n"
    out = web_check_module._normalize_whois(parsed, raw=raw_min, tld="hu")
    assert out["expires_at"] is None
    assert out["days_to_expire"] is None
    assert out["provider_no_expiry"] is True


def test_normalise_dnssec_signed(web_check_module):
    parsed = {"dnssec": "signedDelegation"}
    out = web_check_module._normalize_whois(parsed, raw="", tld="com")
    assert out["dnssec"] is True


def test_check_whois_cache_hit(monkeypatch, web_check_module, tmp_cache):
    """When cache is fresh, no upstream query happens."""
    apex = "itforprof.com"
    payload = {
        "ok": True,
        "apex": apex,
        "registrar": "REG",
        "expires_at": "2030-01-01T00:00:00+00:00",
        "days_to_expire": 9999,
        "provider_no_expiry": False,
        "name_servers": [],
        "schema_version": 1,
        "checked_at": "2026-05-13T00:00:00+00:00",
    }
    tmp_cache.write(apex, payload, ttl=86400)

    # Sentinel: if the upstream is touched, the test fails.
    called = []

    def fake_query(_apex):
        called.append(_apex)
        return {"ok": False}

    monkeypatch.setattr(web_check_module, "_query_whois", fake_query)
    out = web_check_module.check_whois("https://mail.itforprof.com", cache=tmp_cache)
    assert called == []
    assert out["registrar"] == "REG"
    assert out["cache_age_seconds"] >= 0
