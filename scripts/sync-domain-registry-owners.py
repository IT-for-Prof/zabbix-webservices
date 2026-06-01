#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Konstantin Tyutyunnik <https://itforprof.com>
"""Enable WHOIS/RDAP checks on one deterministic owner host per apex.

Default mode is dry-run. Use --apply to write host-level item/trigger states
and transparency macros.

ENV (or scripts/.env): ZABBIX_URL, ZABBIX_TOKEN.
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from _zabbix_client import Zabbix, load_env

EXTERNALSCRIPTS_DIR = Path(__file__).resolve().parent / "externalscripts"
sys.path.insert(0, str(EXTERNALSCRIPTS_DIR))

from web_check import registered_apex, url_host  # noqa: E402

TEMPLATE_NAME = "Web service by itforprof.com"
URL_MACRO = "{$WEB_SERVICE.URL}"
REGISTRY_APEX_MACRO = "{$WEB_SERVICE.REGISTRY.APEX}"
REGISTRY_OWNER_MACRO = "{$WEB_SERVICE.REGISTRY.OWNER}"
REGISTRY_ROLE_MACRO = "{$WEB_SERVICE.REGISTRY.ROLE}"

ZABBIX_HOST_ENABLED = "0"
ZABBIX_STATUS_ENABLED = "0"
ZABBIX_STATUS_DISABLED = "1"

MUTATING_METHODS = {"item.update", "trigger.update", "usermacro.create", "usermacro.update"}

WHOIS_MASTER_KEY_PREFIX = 'web_check.py["whois"'
WHOIS_DEPENDENT_KEYS = {
    "web_check.whois.source",
    "web_check.whois.apex",
    "web_check.whois.registrar",
    "web_check.whois.name_servers",
    "web_check.whois.dnssec",
    "web_check.whois.expires_at",
    "web_check.whois.days_to_expire",
    "web_check.whois.provider_no_expiry",
    "web_check.whois.cache_age_seconds",
    "web_check.whois.error_code",
    "web_check.whois.error_message",
    "web_check.whois.ok",
}
WHOIS_TRIGGER_NAMES = {
    "WHOIS externalscript no data received",
    "Domain expired",
    "Domain expires within {$WEB_SERVICE.WHOIS.CRIT_DAYS} day(s)",
    "Domain expires within {$WEB_SERVICE.WHOIS.NOTICE_DAYS} days",
    "Domain expires within {$WEB_SERVICE.WHOIS.WARN_DAYS} days",
    "Domain registrar changed",
    "Domain name servers changed",
    "Domain DNSSEC removed",
    "WHOIS check failing",
}


@dataclass(frozen=True)
class RegistryHost:
    hostid: str
    host: str
    name: str
    status: str
    url: str
    apex: str

    @property
    def enabled(self) -> bool:
        return self.status == ZABBIX_HOST_ENABLED

    @property
    def url_hostname(self) -> str:
        host, _ = url_host(self.url)
        return host or self.host.lower()


@dataclass(frozen=True)
class OwnerGroup:
    apex: str
    owner: RegistryHost
    duplicates: list[RegistryHost]
    skipped_disabled: list[RegistryHost]


@dataclass(frozen=True)
class Action:
    method: str
    params: dict
    label: str = ""


def registered_apex_from_url(url: str) -> str:
    host, _ = url_host(url)
    if not host:
        return ""
    try:
        return registered_apex(host) or ""
    except ImportError as e:
        raise SystemExit(f"ERROR: tldextract dependency is missing: {e}") from e


def find_template(zbx: Zabbix, name: str) -> dict | None:
    result = zbx.call(
        "template.get",
        {
            "filter": {"host": name},
            "output": ["templateid", "host", "name"],
        },
    )
    return result[0] if result else None


def host_macro_value(host: dict, macro: str) -> str:
    for item in host.get("macros", []) or []:
        if item.get("macro") == macro:
            return item.get("value", "")
    return ""


def fetch_registry_hosts(zbx: Zabbix, templateid: str) -> list[RegistryHost]:
    hosts = zbx.call(
        "host.get",
        {
            "templateids": [templateid],
            "output": ["hostid", "host", "name", "status"],
            "selectMacros": ["hostmacroid", "macro", "value", "description"],
        },
    )
    out: list[RegistryHost] = []
    for h in hosts:
        url = host_macro_value(h, URL_MACRO)
        if not url:
            continue
        apex = registered_apex_from_url(url)
        if not apex:
            continue
        out.append(
            RegistryHost(
                hostid=str(h["hostid"]),
                host=h["host"],
                name=h.get("name") or h["host"],
                status=str(h.get("status", ZABBIX_HOST_ENABLED)),
                url=url,
                apex=apex,
            )
        )
    return out


def build_owner_group(apex: str, hosts: list[RegistryHost]) -> OwnerGroup:
    enabled = [h for h in hosts if h.enabled]
    if not enabled:
        raise ValueError(f"apex {apex!r} has no enabled hosts")

    exact = [h for h in enabled if h.url_hostname == apex]
    candidates = exact or enabled
    owner = sorted(candidates, key=lambda h: (len(h.url_hostname), int(h.hostid)))[0]
    duplicates = sorted([h for h in enabled if h.hostid != owner.hostid], key=lambda h: int(h.hostid))
    skipped_disabled = sorted([h for h in hosts if not h.enabled], key=lambda h: int(h.hostid))
    return OwnerGroup(apex=apex, owner=owner, duplicates=duplicates, skipped_disabled=skipped_disabled)


def build_owner_groups(hosts: list[RegistryHost], *, only_apex: str | None = None) -> list[OwnerGroup]:
    by_apex: dict[str, list[RegistryHost]] = defaultdict(list)
    for h in hosts:
        if only_apex and h.apex != only_apex:
            continue
        by_apex[h.apex].append(h)

    groups: list[OwnerGroup] = []
    for apex in sorted(by_apex):
        enabled = [h for h in by_apex[apex] if h.enabled]
        if enabled:
            groups.append(build_owner_group(apex, by_apex[apex]))
    return groups


def fetch_item_state(zbx: Zabbix, hostids: list[str]) -> dict[str, list[dict]]:
    items = zbx.call(
        "item.get",
        {
            "hostids": hostids,
            "output": ["itemid", "hostid", "key_", "status", "name"],
        },
    )
    out: dict[str, list[dict]] = defaultdict(list)
    for item in items:
        key = item.get("key_", "")
        if key.startswith(WHOIS_MASTER_KEY_PREFIX) or key in WHOIS_DEPENDENT_KEYS:
            out[str(item["hostid"])].append(item)
    return out


def fetch_trigger_state(zbx: Zabbix, hostids: list[str]) -> dict[str, list[dict]]:
    triggers = zbx.call(
        "trigger.get",
        {
            "hostids": hostids,
            "output": ["triggerid", "description", "status", "expression"],
            "selectHosts": ["hostid"],
            # trigger.get returns expressions in {functionid} form unless expanded;
            # the web_check.whois key-substring guard below needs the readable form.
            "expandExpression": True,
        },
    )
    out: dict[str, list[dict]] = defaultdict(list)
    for trigger in triggers:
        expression = trigger.get("expression", "")
        if trigger.get("description") not in WHOIS_TRIGGER_NAMES:
            continue
        if "web_check.whois" not in expression and WHOIS_MASTER_KEY_PREFIX not in expression:
            continue
        for h in trigger.get("hosts", []) or []:
            out[str(h["hostid"])].append(trigger)
    return out


def fetch_macro_state(zbx: Zabbix, hostids: list[str]) -> dict[str, dict[str, dict]]:
    macros = zbx.call(
        "usermacro.get",
        {
            "hostids": hostids,
            "output": ["hostmacroid", "hostid", "macro", "value", "description"],
        },
    )
    out: dict[str, dict[str, dict]] = defaultdict(dict)
    for macro in macros:
        out[str(macro["hostid"])][macro["macro"]] = macro
    return out


def _item_action(host: RegistryHost, status: str, item_state: dict[str, list[dict]]) -> Action | None:
    if host.hostid not in item_state or not item_state[host.hostid]:
        raise RuntimeError(f"{host.host}: missing WHOIS/RDAP item inventory; refusing to plan partial changes")
    keys = {item.get("key_", "") for item in item_state[host.hostid]}
    has_master = any(key.startswith(WHOIS_MASTER_KEY_PREFIX) for key in keys)
    missing = sorted(WHOIS_DEPENDENT_KEYS - keys)
    if not has_master or missing:
        detail = ["master item"] if not has_master else []
        detail.extend(missing)
        raise RuntimeError(
            f"{host.host}: incomplete WHOIS/RDAP item inventory ({', '.join(detail)}); refusing to plan partial changes"
        )
    itemids = [item["itemid"] for item in item_state.get(host.hostid, []) if item.get("status") != status]
    if not itemids:
        return None
    return Action(
        "item.update",
        {"hostid": host.hostid, "itemids": itemids, "status": status},
        f"{host.host}: set WHOIS/RDAP items status={status}",
    )


def _trigger_action(host: RegistryHost, status: str, trigger_state: dict[str, list[dict]]) -> Action | None:
    if host.hostid not in trigger_state or not trigger_state[host.hostid]:
        raise RuntimeError(f"{host.host}: missing domain registry trigger inventory; refusing to plan partial changes")
    names = {trigger.get("description", "") for trigger in trigger_state[host.hostid]}
    missing = sorted(WHOIS_TRIGGER_NAMES - names)
    if missing:
        missing_names = ", ".join(missing)
        raise RuntimeError(
            f"{host.host}: incomplete domain registry trigger inventory ({missing_names}); "
            "refusing to plan partial changes"
        )
    triggerids = [
        trigger["triggerid"] for trigger in trigger_state.get(host.hostid, []) if trigger.get("status") != status
    ]
    if not triggerids:
        return None
    return Action(
        "trigger.update",
        {"hostid": host.hostid, "triggerids": triggerids, "status": status},
        f"{host.host}: set domain registry triggers status={status}",
    )


def _macro_actions(
    host: RegistryHost,
    apex: str,
    owner_host: str,
    role: str,
    macro_state: dict[str, dict[str, dict]],
) -> list[Action]:
    desired = {
        REGISTRY_APEX_MACRO: apex,
        REGISTRY_OWNER_MACRO: owner_host,
        REGISTRY_ROLE_MACRO: role,
    }
    existing = macro_state.get(host.hostid, {})
    actions: list[Action] = []
    for macro, value in desired.items():
        current = existing.get(macro)
        if current and current.get("value") == value:
            continue
        method = "usermacro.update" if current else "usermacro.create"
        params = {
            "hostid": host.hostid,
            "macro": macro,
            "value": value,
            "description": "Domain registry dedup ownership metadata.",
        }
        if current:
            params["hostmacroid"] = current["hostmacroid"]
        actions.append(Action(method, params, f"{host.host}: set {macro}={value!r}"))
    return actions


def plan_actions(
    groups: list[OwnerGroup],
    *,
    item_state: dict[str, list[dict]],
    trigger_state: dict[str, list[dict]],
    macro_state: dict[str, dict[str, dict]],
) -> list[Action]:
    actions: list[Action] = []
    for group in groups:
        owner = group.owner
        for host, status, role in [(owner, ZABBIX_STATUS_ENABLED, "owner")] + [
            (h, ZABBIX_STATUS_DISABLED, "duplicate") for h in group.duplicates
        ]:
            item_action = _item_action(host, status, item_state)
            if item_action:
                actions.append(item_action)
            trigger_action = _trigger_action(host, status, trigger_state)
            if trigger_action:
                actions.append(trigger_action)
            actions.extend(_macro_actions(host, group.apex, owner.host, role, macro_state))
    return actions


def apply_actions(zbx: Zabbix, actions: list[Action], *, apply: bool) -> None:
    """Apply planned actions in order, printing progress so a mid-run failure
    shows exactly how far it got.

    There is no cross-host transaction in the Zabbix API; a re-run converges
    because every action is idempotent (already-correct status/macros are
    skipped at plan time). Item and trigger status changes are batched into one
    array call per host to shrink the failure window.
    """
    if not apply:
        return
    total = len(actions)
    for idx, action in enumerate(actions, start=1):
        print(f"  [{idx}/{total}] {action.label}", flush=True)
        if action.method == "item.update":
            itemids = action.params.get("itemids", [])
            if itemids:
                zbx.call("item.update", [{"itemid": i, "status": action.params["status"]} for i in itemids])
        elif action.method == "trigger.update":
            triggerids = action.params.get("triggerids", [])
            if triggerids:
                zbx.call("trigger.update", [{"triggerid": t, "status": action.params["status"]} for t in triggerids])
        elif action.method == "usermacro.create":
            zbx.call("usermacro.create", action.params)
        elif action.method == "usermacro.update":
            zbx.call(
                "usermacro.update",
                {
                    "hostmacroid": action.params["hostmacroid"],
                    "value": action.params["value"],
                    "description": action.params["description"],
                },
            )
        else:
            raise RuntimeError(f"unsupported action method: {action.method}")
    print(f"  applied {total} action(s).", flush=True)


def print_plan(groups: list[OwnerGroup], actions: list[Action], *, apply: bool) -> None:
    action_count_by_host: dict[str, int] = defaultdict(int)
    for action in actions:
        hostid = str(action.params.get("hostid", ""))
        action_count_by_host[hostid] += 1

    for group in groups:
        duplicate_names = ", ".join(h.host for h in group.duplicates) or "-"
        disabled_names = ", ".join(h.host for h in group.skipped_disabled) or "-"
        print(f"{group.apex}: owner={group.owner.host}; duplicates={duplicate_names}; disabled={disabled_names}")
        for host in [group.owner] + group.duplicates:
            role = "owner" if host.hostid == group.owner.hostid else "duplicate"
            print(f"  {host.host:45s} role={role:9s} planned_actions={action_count_by_host[host.hostid]}")

    if actions:
        print()
        for action in actions:
            print(f"  {action.method:16s} {action.label}")
    print("\n(apply mode)" if apply else "\n(dry-run; pass --apply to write changes)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only-apex", help="Only process one registered apex, e.g. searegion.com.")
    parser.add_argument("--apply", action="store_true", help="Actually write changes. Default is dry-run.")
    args = parser.parse_args()
    if args.only_apex:
        args.only_apex = registered_apex_from_url(args.only_apex) or args.only_apex.lower()
    return args


def main() -> None:
    args = parse_args()
    url, token = load_env()
    zbx = Zabbix(url, token)

    template = find_template(zbx, TEMPLATE_NAME)
    if not template:
        raise SystemExit(f"ERROR: template {TEMPLATE_NAME!r} not found")

    hosts = fetch_registry_hosts(zbx, template["templateid"])
    groups = build_owner_groups(hosts, only_apex=args.only_apex)
    hostids = [h.hostid for group in groups for h in [group.owner] + group.duplicates]
    item_state = fetch_item_state(zbx, hostids) if hostids else {}
    trigger_state = fetch_trigger_state(zbx, hostids) if hostids else {}
    macro_state = fetch_macro_state(zbx, hostids) if hostids else {}
    actions = plan_actions(groups, item_state=item_state, trigger_state=trigger_state, macro_state=macro_state)

    print_plan(groups, actions, apply=args.apply)
    apply_actions(zbx, actions, apply=args.apply)


if __name__ == "__main__":
    main()
