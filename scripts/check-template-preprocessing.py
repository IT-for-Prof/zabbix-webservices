#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Konstantin Tyutyunnik <https://itforprof.com>
"""Compare template preprocessing in Zabbix with the template YAML files.

Zabbix 7.0 import updates preprocessing steps by position and keeps fields the
new step omits (e.g. a DISCARD_VALUE step inherits the old step's
error_handler_params). The export hides them, item.get shows them. Run this
after every template import.

Default mode reports and exits 1 on any mismatch. --apply rewrites mismatched
template objects with every step field explicit; re-run without flags to
confirm. Hosts inherit the fix.

ENV (or scripts/.env): ZABBIX_URL, ZABBIX_TOKEN.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from _zabbix_client import Zabbix, load_env

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates" / "web-service-by-itforprof"
DEFAULT_FILES = [
    TEMPLATE_DIR / "template_web_service_by_itforprof_com.yaml",
    TEMPLATE_DIR / "template_web_service_by_itforprof_com_tls.yaml",
]

STEP_TYPES = {
    "MULTIPLIER": "1",
    "RTRIM": "2",
    "LTRIM": "3",
    "TRIM": "4",
    "REGEX": "5",
    "BOOL_TO_DECIMAL": "6",
    "OCTAL_TO_DECIMAL": "7",
    "HEX_TO_DECIMAL": "8",
    "SIMPLE_CHANGE": "9",
    "CHANGE_PER_SECOND": "10",
    "XMLPATH": "11",
    "JSONPATH": "12",
    "IN_RANGE": "13",
    "MATCHES_REGEX": "14",
    "NOT_MATCHES_REGEX": "15",
    "CHECK_JSON_ERROR": "16",
    "CHECK_XML_ERROR": "17",
    "CHECK_REGEX_ERROR": "18",
    "DISCARD_UNCHANGED": "19",
    "DISCARD_UNCHANGED_HEARTBEAT": "20",
    "JAVASCRIPT": "21",
    "PROMETHEUS_PATTERN": "22",
    "PROMETHEUS_TO_JSON": "23",
    "CSV_TO_JSON": "24",
    "STR_REPLACE": "25",
    "CHECK_NOT_SUPPORTED": "26",
    "XML_TO_JSON": "27",
    "SNMP_WALK_VALUE": "28",
    "SNMP_WALK_TO_JSON": "29",
    "SNMP_GET_VALUE": "30",
}
ERROR_HANDLERS = {"ORIGINAL_ERROR": "0", "DISCARD_VALUE": "1", "CUSTOM_VALUE": "2", "CUSTOM_ERROR": "3"}
STEP_FIELDS = ("type", "params", "error_handler", "error_handler_params")
# Object kind = API method prefix; all three use `itemid`.
KINDS = ("item", "discoveryrule", "itemprototype")


def expected_steps(steps: list[dict] | None) -> list[dict]:
    """Steps from the YAML file in API form, every field present as a string."""
    return [
        {
            "type": STEP_TYPES[s["type"]],
            "params": "\n".join(s.get("parameters") or []),
            "error_handler": ERROR_HANDLERS[s.get("error_handler", "ORIGINAL_ERROR")],
            "error_handler_params": s.get("error_handler_params", ""),
        }
        for s in steps or []
    ]


def file_objects(template: dict) -> dict[tuple[str, str], list[dict]]:
    """(kind, key) → expected steps for one template from the YAML export."""
    want = {("item", i["key"]): expected_steps(i.get("preprocessing")) for i in template.get("items") or []}
    for rule in template.get("discovery_rules") or []:
        want["discoveryrule", rule["key"]] = expected_steps(rule.get("preprocessing"))
        for proto in rule.get("item_prototypes") or []:
            want["itemprototype", proto["key"]] = expected_steps(proto.get("preprocessing"))
    return want


def server_objects(zbx: Zabbix, templateid: str) -> dict[tuple[str, str], tuple[str, list[dict]]]:
    """(kind, key) → (itemid, steps) for one template on the server."""
    got = {}
    for kind in KINDS:
        rows = zbx.call(
            f"{kind}.get", {"templateids": [templateid], "output": ["itemid", "key_"], "selectPreprocessing": "extend"}
        )
        for row in rows:
            steps = [{f: p[f] for f in STEP_FIELDS} for p in row["preprocessing"]]
            got[kind, row["key_"]] = (row["itemid"], steps)
    return got


def check_template(zbx: Zabbix, path: Path, *, apply: bool) -> bool | None:
    """Report one template file; True = clean, False = problem, None = not on this server."""
    template = yaml.safe_load(path.read_text())["zabbix_export"]["templates"][0]
    name, version = template["template"], template["vendor"]["version"]
    found = zbx.call("template.get", {"filter": {"host": [name]}, "output": ["templateid", "vendor_version"]})
    if not found:
        print(f"{name}: not on this server, skipped")
        return None
    templateid, server_version = found[0]["templateid"], found[0]["vendor_version"]
    print(f"{name}: server {server_version}, file {version} ({path.name})")
    if server_version != version:
        print("  version mismatch: import this file first or check out the matching branch; not compared")
        return False

    want, got = file_objects(template), server_objects(zbx, templateid)
    clean = True
    for kind, key in sorted(want):
        if (kind, key) not in got:
            print(f"  MISSING {kind} {key}")
            clean = False
            continue
        itemid, steps = got[kind, key]
        if steps == want[kind, key]:
            continue
        clean = False
        print(f"  MISMATCH {kind} {key}")
        for n in range(max(len(steps), len(want[kind, key]))):
            w = want[kind, key][n] if n < len(want[kind, key]) else None
            g = steps[n] if n < len(steps) else None
            if w != g:
                print(f"    step {n + 1} file: {w}\n    step {n + 1} db:   {g}")
        if apply:
            zbx.call(f"{kind}.update", {"itemid": itemid, "preprocessing": want[kind, key]})
            print("    rewritten")
    for kind, key in sorted(set(got) - set(want)):
        print(f"  only on server (not an error): {kind} {key}")
    return clean


def main(argv: list[str] | None = None, zbx: Zabbix | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="*", type=Path, default=DEFAULT_FILES, help="template YAML files")
    ap.add_argument("--apply", action="store_true", help="rewrite mismatched preprocessing on the server")
    args = ap.parse_args(argv)
    if zbx is None:
        url, token = load_env()
        zbx = Zabbix(url, token)
    print(f"server: {zbx.url}")

    results = [check_template(zbx, path, apply=args.apply) for path in args.files]
    if all(r is None for r in results):
        print("ERROR: none of the templates is on this server")
        return 1
    if False in results:
        print("problems found")
        return 1
    print("preprocessing matches the files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
