#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Konstantin Tyutyunnik <https://itforprof.com>
"""
migrate-from-itmicus.py — Move hosts from `Template Website metrics` to
`Web service by itforprof.com` (full 5-layer template: HTTP + cert + WHOIS +
network diagnostics + daily TLS scan).

For each host linked to the legacy template, this script:

  1. Links `Web service by itforprof.com` (if not already linked).
  2. Translates host-level macros:
       {$WEBSITE_METRICS_URL}     -> {$WEB_SERVICE.URL}
       {$WEBSITE_METRICS_PHRASE}  -> {$WEB_SERVICE.PHRASE}
       {$WEBSITE_METRICS_TIMEOUT} -> {$WEB_SERVICE.TIMEOUT}
     Also derives {$WEB_SERVICE.HOST} from the URL hostname (required by
     Layer 4 diagnostic simple checks — no default in the template).
     Only sets a new macro if it isn't already defined on the host.
  3. Unlinks the legacy template (--keep-old to leave it attached for a
     parallel-run validation period).

Does NOT delete the legacy template itself or the legacy script files.

Idempotent — re-running converges to the desired state. Use --apply to
actually write; default is dry-run.

ENV (or scripts/.env): ZABBIX_URL, ZABBIX_TOKEN.
"""

import argparse
import sys
from urllib.parse import urlparse

from _zabbix_client import Zabbix, load_env

OLD_TEMPLATE_NAME = "Template Website metrics"
NEW_TEMPLATE_NAME = "Web service by itforprof.com"

# 1:1 macro renames. Old value is copied verbatim to the new name.
MACRO_MAP = {
    "{$WEBSITE_METRICS_URL}": "{$WEB_SERVICE.URL}",
    "{$WEBSITE_METRICS_PHRASE}": "{$WEB_SERVICE.PHRASE}",
    "{$WEBSITE_METRICS_TIMEOUT}": "{$WEB_SERVICE.TIMEOUT}",
}


def derive_host_macro(url: str) -> str | None:
    """Extract hostname from a URL for {$WEB_SERVICE.HOST}.

    Returns the A-label (Punycode ASCII) form for IDN hosts so the value
    works with `net.tcp.service.perf` and other Zabbix simple checks
    regardless of resolver/glibc IDNA behavior. E.g.
    `http://тамбурато.рф` → `xn--80aac7bmkkfg.xn--p1ai`. Plain ASCII
    hostnames are unchanged. Returns None if unparsable.
    """
    if "://" not in url:
        url = "https://" + url
    p = urlparse(url)
    if not p.hostname:
        return None
    host = p.hostname
    try:
        # IDNA-2003 ASCII (A-label) form; harmless on pure-ASCII hosts.
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        # Pathological U-label that can't IDNA-encode — return as-is, lowercased.
        return host.lower()


def find_template(zbx, name):
    # Filter by `host` (the technical name), not `name` (the display name).
    # The legacy template's host is "Template Website metrics" but its name
    # is "Template Website metrics (itmicus.ru)" — they differ.
    r = zbx.call(
        "template.get",
        {
            "filter": {"host": name},
            "output": ["templateid", "host", "name"],
        },
    )
    return r[0] if r else None


def get_host_macros(zbx, hostid):
    r = zbx.call(
        "usermacro.get",
        {
            "hostids": [hostid],
            "output": ["hostmacroid", "macro", "value", "description", "type"],
        },
    )
    return r


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--only", action="append", metavar="HOSTNAME", help="Only process this host technical name (repeatable)."
    )
    ap.add_argument("--apply", action="store_true", help="Actually write. Without this flag, dry-run only.")
    ap.add_argument(
        "--keep-old", action="store_true", help="Do NOT unlink the legacy template; useful for parallel-run validation."
    )
    ap.add_argument("--list", action="store_true", help="List planned actions without writing and exit.")
    args = ap.parse_args()

    url, token = load_env()
    zbx = Zabbix(url, token)

    old = find_template(zbx, OLD_TEMPLATE_NAME)
    if not old:
        sys.exit(f"ERROR: legacy template '{OLD_TEMPLATE_NAME}' not found - nothing to migrate.")
    new = find_template(zbx, NEW_TEMPLATE_NAME)
    if not new:
        sys.exit(
            f"ERROR: new template '{NEW_TEMPLATE_NAME}' not found.\n"
            f"Import templates/web-service-by-itforprof/template_web_service_by_itforprof_com.yaml first."
        )
    print(f"  legacy templateid={old['templateid']}, new templateid={new['templateid']}")

    # Hosts currently linked to the legacy template
    hosts = zbx.call(
        "host.get",
        {
            "templateids": [old["templateid"]],
            "output": ["hostid", "host", "name", "status"],
            "selectParentTemplates": ["templateid", "name"],
            "selectMacros": ["hostmacroid", "macro", "value", "description"],
        },
    )
    if args.only:
        wanted = set(args.only)
        hosts = [h for h in hosts if h["host"] in wanted]

    print(f"  found {len(hosts)} host(s) linked to legacy template")

    plan = []
    for h in hosts:
        linked_ids = {t["templateid"] for t in h.get("parentTemplates", [])}
        already_new = new["templateid"] in linked_ids
        by_macro = {m["macro"]: m for m in h.get("macros", [])}

        macro_actions = []
        divergence_warnings: list[str] = []
        for old_m, new_m in MACRO_MAP.items():
            if old_m in by_macro and new_m not in by_macro:
                macro_actions.append((new_m, by_macro[old_m]["value"], by_macro[old_m].get("description", "")))
            elif old_m in by_macro and new_m in by_macro:
                old_val = by_macro[old_m].get("value", "")
                new_val = by_macro[new_m].get("value", "")
                if old_val != new_val:
                    divergence_warnings.append(
                        f"WARN: {h['host']}: {old_m}={old_val!r} but {new_m}={new_val!r} "
                        f"is already set — keeping new value (override applied manually)."
                    )

        # Derive {$WEB_SERVICE.HOST} from the URL — required by Layer 4 diag items.
        host_macro = "{$WEB_SERVICE.HOST}"
        url_macro = "{$WEBSITE_METRICS_URL}"
        if host_macro not in by_macro and url_macro in by_macro:
            derived = derive_host_macro(by_macro[url_macro]["value"])
            if derived:
                macro_actions.append((host_macro, derived, "Derived from URL hostname for Layer 4 diag checks."))

        plan.append(
            {
                "host": h,
                "link_new": not already_new,
                "macro_actions": macro_actions,
                "unlink_old": not args.keep_old,
                "divergence_warnings": divergence_warnings,
            }
        )

    # Surface any divergence warnings up-front so the operator sees them
    # before the per-host action plan.
    all_warns = [w for p in plan for w in p.get("divergence_warnings", [])]
    if all_warns:
        print()
        for w in all_warns:
            print(f"  {w}")
        print()

    # Show plan
    for p in plan:
        h = p["host"]
        actions = []
        if p["link_new"]:
            actions.append(f"link({NEW_TEMPLATE_NAME})")
        for nm, val, _desc in p["macro_actions"]:
            v = val if len(val) <= 40 else val[:37] + "..."
            actions.append(f"set {nm}={v!r}")
        if p["unlink_old"]:
            actions.append(f"unlink({OLD_TEMPLATE_NAME})")
        if not actions:
            actions = ["(no-op, already migrated)"]
        print(f"  {h['host']:45s} -> {', '.join(actions)}")

    if args.list or not args.apply:
        if not args.apply:
            print("\n(dry-run; pass --apply to actually migrate)")
        return

    # Apply
    print()
    changed = 0
    for p in plan:
        h = p["host"]
        try:
            if p["link_new"]:
                zbx.call(
                    "host.update",
                    {
                        "hostid": h["hostid"],
                        "templates": [{"templateid": t["templateid"]} for t in h.get("parentTemplates", [])]
                        + [{"templateid": new["templateid"]}],
                    },
                )
                print(f"  {h['host']}: linked {NEW_TEMPLATE_NAME}")
            for new_m, val, desc in p["macro_actions"]:
                zbx.call(
                    "usermacro.create",
                    {
                        "hostid": h["hostid"],
                        "macro": new_m,
                        "value": val,
                        "description": desc or f"Migrated from {next(k for k, v in MACRO_MAP.items() if v == new_m)}",
                    },
                )
                print(f"  {h['host']}: set {new_m}")
            if p["unlink_old"]:
                # template.update with templates_clear preserves history; use templates parameter excluding old
                remaining = [
                    {"templateid": t["templateid"]}
                    for t in h.get("parentTemplates", [])
                    if t["templateid"] != old["templateid"]
                ]
                # Ensure new template is in the remaining list if we linked it earlier
                if p["link_new"] and not any(t["templateid"] == new["templateid"] for t in remaining):
                    remaining.append({"templateid": new["templateid"]})
                zbx.call(
                    "host.update",
                    {
                        "hostid": h["hostid"],
                        "templates_clear": [{"templateid": old["templateid"]}],
                    },
                )
                print(f"  {h['host']}: unlinked {OLD_TEMPLATE_NAME}")
            changed += 1
        except RuntimeError as e:
            print(f"  {h['host']}: FAILED - {e}")

    print(f"\nDone. Migrated {changed} host(s).")


if __name__ == "__main__":
    main()
