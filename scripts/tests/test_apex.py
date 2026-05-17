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
