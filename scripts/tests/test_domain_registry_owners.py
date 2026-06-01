"""Tests for scripts/sync-domain-registry-owners.py."""

from __future__ import annotations

import importlib.util
import pathlib
import sys

import pytest


@pytest.fixture(scope="module")
def registry_mod():
    p = pathlib.Path(__file__).resolve().parent.parent / "sync-domain-registry-owners.py"
    spec = importlib.util.spec_from_file_location("sync_domain_registry_owners", p)
    assert spec and spec.loader, f"could not load spec from {p}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _host(registry_mod, hostid, host, url, *, status="0"):
    return registry_mod.RegistryHost(
        hostid=str(hostid),
        host=host,
        name=host,
        status=str(status),
        url=url,
        apex=registry_mod.registered_apex_from_url(url),
    )


def _item_inventory(registry_mod, hostid, *, status):
    keys = [f'{registry_mod.WHOIS_MASTER_KEY_PREFIX},"url"]'] + sorted(registry_mod.WHOIS_DEPENDENT_KEYS)
    return [
        {"itemid": f"{hostid}{idx:02d}", "key_": key, "status": status}
        for idx, key in enumerate(keys, start=1)
    ]


def _trigger_inventory(registry_mod, hostid, *, status):
    return [
        {
            "triggerid": f"{hostid}{idx:02d}",
            "description": name,
            "status": status,
        }
        for idx, name in enumerate(sorted(registry_mod.WHOIS_TRIGGER_NAMES), start=1)
    ]


def test_owner_selection_prefers_enabled_exact_apex(registry_mod):
    hosts = [
        _host(registry_mod, 12, "cloud.searegion.com", "https://cloud.searegion.com"),
        _host(registry_mod, 10, "searegion.com", "https://searegion.com"),
        _host(registry_mod, 9, "www.searegion.com", "https://www.searegion.com"),
    ]

    group = registry_mod.build_owner_group("searegion.com", hosts)

    assert group.owner.host == "searegion.com"
    assert {h.host for h in group.duplicates} == {"cloud.searegion.com", "www.searegion.com"}


def test_owner_selection_uses_shortest_enabled_hostname_then_lowest_hostid(registry_mod):
    hosts = [
        _host(registry_mod, 20, "docs.hss.center", "https://docs.hss.center"),
        _host(registry_mod, 10, "api.hss.center", "https://api.hss.center"),
        _host(registry_mod, 30, "very.long.hss.center", "https://very.long.hss.center"),
    ]

    group = registry_mod.build_owner_group("hss.center", hosts)

    assert group.owner.host == "api.hss.center"


def test_owner_selection_tiebreaks_equal_length_hostname_by_lowest_hostid(registry_mod):
    hosts = [
        _host(registry_mod, 20, "aaa.example.com", "https://aaa.example.com"),
        _host(registry_mod, 10, "zzz.example.com", "https://zzz.example.com"),
    ]

    group = registry_mod.build_owner_group("example.com", hosts)

    assert group.owner.host == "zzz.example.com"


def test_owner_selection_ignores_disabled_hosts(registry_mod):
    hosts = [
        _host(registry_mod, 1, "example.com", "https://example.com", status="1"),
        _host(registry_mod, 2, "www.example.com", "https://www.example.com"),
    ]

    group = registry_mod.build_owner_group("example.com", hosts)

    assert group.owner.host == "www.example.com"
    assert group.duplicates == []


def test_plan_marks_owner_enabled_and_duplicates_disabled(registry_mod):
    hosts = [
        _host(registry_mod, 1, "example.com", "https://example.com"),
        _host(registry_mod, 2, "www.example.com", "https://www.example.com"),
    ]
    groups = [registry_mod.build_owner_group("example.com", hosts)]
    item_state = {
        "1": _item_inventory(registry_mod, 1, status=registry_mod.ZABBIX_STATUS_DISABLED),
        "2": _item_inventory(registry_mod, 2, status=registry_mod.ZABBIX_STATUS_ENABLED),
    }
    trigger_state = {
        "1": _trigger_inventory(registry_mod, 3, status=registry_mod.ZABBIX_STATUS_DISABLED),
        "2": _trigger_inventory(registry_mod, 4, status=registry_mod.ZABBIX_STATUS_ENABLED),
    }

    actions = registry_mod.plan_actions(groups, item_state=item_state, trigger_state=trigger_state, macro_state={})

    assert [a.method for a in actions] == [
        "item.update",
        "trigger.update",
        "usermacro.create",
        "usermacro.create",
        "usermacro.create",
        "item.update",
        "trigger.update",
        "usermacro.create",
        "usermacro.create",
        "usermacro.create",
    ]
    assert actions[0].params["status"] == registry_mod.ZABBIX_STATUS_ENABLED
    assert actions[0].params["itemids"] == [item["itemid"] for item in item_state["1"]]
    assert actions[1].params["status"] == registry_mod.ZABBIX_STATUS_ENABLED
    assert actions[1].params["triggerids"] == [trigger["triggerid"] for trigger in trigger_state["1"]]
    assert actions[5].params["status"] == registry_mod.ZABBIX_STATUS_DISABLED
    assert actions[5].params["itemids"] == [item["itemid"] for item in item_state["2"]]
    assert actions[6].params["status"] == registry_mod.ZABBIX_STATUS_DISABLED
    assert actions[6].params["triggerids"] == [trigger["triggerid"] for trigger in trigger_state["2"]]
    assert {a.params["macro"]: a.params["value"] for a in actions[2:5]} == {
        "{$WEB_SERVICE.REGISTRY.APEX}": "example.com",
        "{$WEB_SERVICE.REGISTRY.OWNER}": "example.com",
        "{$WEB_SERVICE.REGISTRY.ROLE}": "owner",
    }
    assert {a.params["macro"]: a.params["value"] for a in actions[7:10]} == {
        "{$WEB_SERVICE.REGISTRY.APEX}": "example.com",
        "{$WEB_SERVICE.REGISTRY.OWNER}": "example.com",
        "{$WEB_SERVICE.REGISTRY.ROLE}": "duplicate",
    }


def test_plan_rejects_missing_item_or_trigger_inventory(registry_mod):
    hosts = [_host(registry_mod, 1, "example.com", "https://example.com")]
    groups = [registry_mod.build_owner_group("example.com", hosts)]

    with pytest.raises(RuntimeError, match="missing WHOIS/RDAP item inventory"):
        registry_mod.plan_actions(groups, item_state={}, trigger_state={"1": []}, macro_state={})

    with pytest.raises(RuntimeError, match="incomplete WHOIS/RDAP item inventory"):
        registry_mod.plan_actions(
            groups,
            item_state={"1": [{"itemid": "101", "key_": "web_check.whois.ok", "status": registry_mod.ZABBIX_STATUS_ENABLED}]},
            trigger_state={"1": _trigger_inventory(registry_mod, 1, status=registry_mod.ZABBIX_STATUS_ENABLED)},
            macro_state={},
        )

    with pytest.raises(RuntimeError, match="missing domain registry trigger inventory"):
        registry_mod.plan_actions(
            groups,
            item_state={"1": _item_inventory(registry_mod, 1, status=registry_mod.ZABBIX_STATUS_ENABLED)},
            trigger_state={},
            macro_state={},
        )

    with pytest.raises(RuntimeError, match="incomplete domain registry trigger inventory"):
        registry_mod.plan_actions(
            groups,
            item_state={"1": _item_inventory(registry_mod, 1, status=registry_mod.ZABBIX_STATUS_ENABLED)},
            trigger_state={"1": [{"triggerid": "101", "description": "WHOIS check failing", "status": registry_mod.ZABBIX_STATUS_ENABLED}]},
            macro_state={},
        )


def test_dry_run_does_not_call_mutating_api_methods(registry_mod):
    class FakeZabbix:
        def __init__(self):
            self.calls = []

        def call(self, method, params=None):
            self.calls.append((method, params or {}))
            if method in registry_mod.MUTATING_METHODS:
                raise AssertionError(f"unexpected mutation during dry-run: {method}")
            return {}

    zbx = FakeZabbix()
    actions = [
        registry_mod.Action("item.update", {"itemid": "1", "status": registry_mod.ZABBIX_STATUS_ENABLED})
    ]

    registry_mod.apply_actions(zbx, actions, apply=False)

    assert zbx.calls == []
