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


class _RecordingZabbix:
    """Fake client that records calls and returns canned per-method payloads."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def call(self, method, params=None):
        self.calls.append((method, params if params is not None else {}))
        return self.responses.get(method, [])


def test_fetch_trigger_state_requests_expanded_expressions_and_filters_whois(registry_mod):
    # The readable ("expanded") form is what expandExpression=True returns; the
    # web_check.whois substring guard only works against this form.
    triggers = [
        {"triggerid": "1", "description": "Domain expired", "status": "0",
         "expression": "last(/T/web_check.whois.ok)=1 and last(/T/web_check.whois.days_to_expire)<0",
         "hosts": [{"hostid": "10"}]},
        {"triggerid": "2", "description": "Cert expired", "status": "0",
         "expression": "last(/T/web_check.cert.days_to_expire)<0",  # non-whois -> dropped
         "hosts": [{"hostid": "10"}]},
        {"triggerid": "3", "description": "WHOIS check failing", "status": "0",
         "expression": "last(/T/web_check.whois.ok)=0", "hosts": [{"hostid": "10"}]},
    ]
    zbx = _RecordingZabbix({"trigger.get": triggers})

    state = registry_mod.fetch_trigger_state(zbx, ["10"])

    method, params = zbx.calls[0]
    assert method == "trigger.get"
    # Regression guard for the shipped bug: without this the server returns
    # {functionid}-form expressions and the substring filter matches nothing.
    assert params.get("expandExpression") is True
    assert {t["description"] for t in state["10"]} == {"Domain expired", "WHOIS check failing"}


def test_fetch_trigger_state_drops_unexpanded_functionid_expressions(registry_mod):
    # If a server ever returns {functionid}-form, the filter must yield nothing
    # so the downstream inventory guard fails closed (rather than silently
    # planning a partial change).
    triggers = [
        {"triggerid": "1", "description": "Domain expired", "status": "0",
         "expression": "{12345}=1 and {12346}<0", "hosts": [{"hostid": "10"}]},
    ]
    zbx = _RecordingZabbix({"trigger.get": triggers})

    assert registry_mod.fetch_trigger_state(zbx, ["10"]) == {}


def test_fetch_item_state_filters_to_whois_master_and_dependents(registry_mod):
    master_key = registry_mod.WHOIS_MASTER_KEY_PREFIX + ',"url"]'
    items = [
        {"itemid": "1", "hostid": "10", "key_": master_key, "status": "0"},
        {"itemid": "2", "hostid": "10", "key_": "web_check.whois.ok", "status": "0"},
        {"itemid": "3", "hostid": "10", "key_": "web_check.cert.ok", "status": "0"},  # dropped
    ]
    zbx = _RecordingZabbix({"item.get": items})

    state = registry_mod.fetch_item_state(zbx, ["10"])

    keys = {i["key_"] for i in state["10"]}
    assert master_key in keys
    assert "web_check.whois.ok" in keys
    assert "web_check.cert.ok" not in keys


def test_fetch_macro_state_indexes_by_host_then_macro(registry_mod):
    macros = [
        {"hostmacroid": "1", "hostid": "10", "macro": "{$WEB_SERVICE.REGISTRY.APEX}", "value": "x.com"},
    ]
    zbx = _RecordingZabbix({"usermacro.get": macros})

    state = registry_mod.fetch_macro_state(zbx, ["10"])

    assert state["10"]["{$WEB_SERVICE.REGISTRY.APEX}"]["value"] == "x.com"


def test_apply_batches_item_and_trigger_updates_into_one_call_each(registry_mod):
    zbx = _RecordingZabbix({})
    disabled = registry_mod.ZABBIX_STATUS_DISABLED
    actions = [
        registry_mod.Action("item.update", {"hostid": "2", "itemids": ["a", "b"], "status": disabled}, "items"),
        registry_mod.Action("trigger.update", {"hostid": "2", "triggerids": ["t1", "t2"], "status": disabled}, "triggers"),
    ]

    registry_mod.apply_actions(zbx, actions, apply=True)

    assert [m for m, _ in zbx.calls] == ["item.update", "trigger.update"]
    assert zbx.calls[0][1] == [{"itemid": "a", "status": disabled}, {"itemid": "b", "status": disabled}]
    assert zbx.calls[1][1] == [{"triggerid": "t1", "status": disabled}, {"triggerid": "t2", "status": disabled}]
