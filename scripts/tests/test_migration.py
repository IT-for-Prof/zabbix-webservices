"""Tests for scripts/migrate-from-itmicus.py.

Focused on the pure-Python pieces (URL → host derivation, IDN handling) that
don't require a live Zabbix API. The plan-build + apply paths talk to the
API and are exercised manually during rollouts; no point mocking the whole
JSON-RPC client here.
"""

from __future__ import annotations

import importlib.util
import pathlib

import pytest


@pytest.fixture(scope="module")
def migrate_mod():
    """Load migrate-from-itmicus.py as a module (its filename has dashes)."""
    p = pathlib.Path(__file__).resolve().parent.parent / "migrate-from-itmicus.py"
    spec = importlib.util.spec_from_file_location("migrate_from_itmicus", p)
    assert spec and spec.loader, f"could not load spec from {p}"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        # Plain ASCII
        ("https://example.com", "example.com"),
        ("http://www.example.com/path", "www.example.com"),
        ("https://mon.itforprof.com:443/healthz", "mon.itforprof.com"),
        # Without scheme — derive_host_macro prepends https://
        ("example.com", "example.com"),
        # IDN U-label → must be encoded to A-label for Zabbix net.tcp.service.perf
        ("http://тамбурато.рф", "xn--80aac7bmkkfg.xn--p1ai"),
        ("https://мобильнаямебель.рф/", "xn--80abbpbovebeji9ph3b.xn--p1ai"),
        # Case-insensitive
        ("https://EXAMPLE.COM", "example.com"),
    ],
)
def test_derive_host_macro(migrate_mod, url, expected):
    assert migrate_mod.derive_host_macro(url) == expected


def test_derive_host_macro_unparseable(migrate_mod):
    # Empty / no hostname → None
    assert migrate_mod.derive_host_macro("") is None
    assert migrate_mod.derive_host_macro("https://") is None


def test_macro_map_complete(migrate_mod):
    """Every legacy macro the script knows about maps to the new namespace."""
    assert "{$WEBSITE_METRICS_URL}" in migrate_mod.MACRO_MAP
    assert "{$WEBSITE_METRICS_PHRASE}" in migrate_mod.MACRO_MAP
    assert "{$WEBSITE_METRICS_TIMEOUT}" in migrate_mod.MACRO_MAP
    # Every value maps into the {$WEB_SERVICE.*} namespace
    assert all(v.startswith("{$WEB_SERVICE.") for v in migrate_mod.MACRO_MAP.values())


def test_old_template_name_is_host_field(migrate_mod):
    # The legacy template's `host` field is "Template Website metrics"
    # (without the "(itmicus.ru)" suffix that's on its `name` field).
    # `find_template` filters by `host`, so the constant must match host.
    assert migrate_mod.OLD_TEMPLATE_NAME == "Template Website metrics"
