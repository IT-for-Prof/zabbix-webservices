"""Apex extraction + hostname coverage tests."""

from __future__ import annotations

import pytest


@pytest.mark.parametrize(
    ("host", "want"),
    [
        ("itforprof.com", "itforprof.com"),
        ("mon.itforprof.com", "itforprof.com"),
        ("mail.itforprof.com", "itforprof.com"),
        ("eurotrade-group.ru", "eurotrade-group.ru"),
        ("a.b.eurotrade-group.ru", "eurotrade-group.ru"),
        ("xn--80aac7bmkkfg.xn--p1ai", "xn--80aac7bmkkfg.xn--p1ai"),
        ("casualstyle.hu", "casualstyle.hu"),
        # PSL edge case: .gov.uk is a public suffix (a registrant lives one
        # label below). tldextract handles this correctly.
        ("foo.gov.uk", "foo.gov.uk"),
        ("bar.foo.gov.uk", "foo.gov.uk"),
    ],
)
def test_apex_extraction(web_check_module, host, want):
    assert web_check_module.registered_apex(host) == want


def test_apex_none_for_invalid(web_check_module):
    assert web_check_module.registered_apex("localhost") is None
    assert web_check_module.registered_apex("") is None


@pytest.mark.parametrize(
    ("host", "names", "want"),
    [
        ("example.com", ["example.com"], True),
        ("example.com", ["other.com"], False),
        ("mail.itforprof.com", ["*.itforprof.com"], True),
        ("itforprof.com", ["*.itforprof.com"], False),  # wildcard doesn't cover apex
        ("deep.sub.itforprof.com", ["*.itforprof.com"], False),  # one label only
        ("EXAMPLE.com", ["example.com"], True),  # case-insensitive
        ("example.com", [], False),
    ],
)
def test_hostname_covered(web_check_module, host, names, want):
    assert web_check_module._hostname_covered(host, names) is want


def test_url_host_parsing(web_check_module):
    assert web_check_module.url_host("https://example.com") == ("example.com", 443)
    assert web_check_module.url_host("http://example.com:8080/path") == ("example.com", 8080)
    assert web_check_module.url_host("example.com") == ("example.com", 443)
    assert web_check_module.url_host("http://example.com") == ("example.com", 80)


def test_tld_of(web_check_module):
    assert web_check_module.tld_of("itforprof.com") == "com"
    assert web_check_module.tld_of("xn--80aac.xn--p1ai") == "xn--p1ai"
    assert web_check_module.tld_of("noperiod") == "noperiod"


def test_psl_extractor_cache_disabled(web_check_module, capfd, caplog, monkeypatch):
    """Regression for the tldextract stdout/stderr pollution bug (2.1.4).

    The module-level `_PSL_EXTRACTOR` must be constructed with
    `cache_dir=None` so tldextract's `DiskCache` never attempts to write
    under `$HOME/.cache/python-tldextract/`. Under the zabbix:zabbix
    runtime that directory is unwritable and the failed write surfaces
    as a `tldextract.cache` logger warning that — once stderr is folded
    into stdout by the Zabbix externalscript handler — contaminates the
    JSON envelope.

    We assert three things, so a future maintainer who drops
    `cache_dir=None` (by any path) gets a failing test:
      1. Structural: tldextract's `DiskCache.enabled` is False.
      2. Behavioural / logger: no records emitted on `tldextract.cache`
         (caplog intercepts before the lastResort handler routes to
         stderr — so this is the assertion that catches the warning
         under pytest).
      3. Behavioural / stream: nothing on stdout or stderr (catches a
         hypothetical future regression that prints directly).
    """
    # Reset the lazy singleton so the assertion exercises construction.
    monkeypatch.setattr(web_check_module, "_PSL_EXTRACTOR", None)

    # Deliberately-unwritable XDG cache location: if tldextract resolves
    # the default cache_dir under it, `DiskCache.set` will try to write
    # and the warning will fire. With cache_dir=None, the resolution
    # never happens.
    monkeypatch.setenv("XDG_CACHE_HOME", "/proc/1")  # not a writable dir

    with caplog.at_level("WARNING", logger="tldextract.cache"):
        apex = web_check_module.registered_apex("foo.example.com")
    captured = capfd.readouterr()

    assert apex == "example.com"
    assert captured.out == "", f"unexpected stdout: {captured.out!r}"
    assert captured.err == "", f"unexpected stderr: {captured.err!r}"
    assert caplog.records == [], (
        f"tldextract.cache emitted {len(caplog.records)} log record(s): {[r.getMessage() for r in caplog.records]}"
    )
    # Structural intent: tldextract's DiskCache must be disabled.
    assert web_check_module._PSL_EXTRACTOR is not None
    assert web_check_module._PSL_EXTRACTOR._cache.enabled is False
