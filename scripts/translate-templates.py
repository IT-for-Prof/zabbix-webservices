#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Konstantin Tyutyunnik <https://itforprof.com>
"""Build the Russian templates from the English ones and the i18n/ru.yaml catalog.

The English YAML is the source of truth. The Russian file is generated: same
UUIDs, keys, expressions, macros and tags, only display text translated. Hosts
switch language by importing the other file over the same template; Zabbix
matches objects by UUID and renames them in place.

    translate-templates.py            write *_ru.yaml next to each English file
    translate-templates.py --check    exit 1 if a *_ru.yaml is stale, a string is
                                      untranslated, a catalog entry is unused or a
                                      translation dropped a {macro}
    translate-templates.py --missing  print untranslated strings as a catalog stub
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any

import yaml

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates" / "web-service-by-itforprof"
CATALOG = TEMPLATE_DIR / "i18n" / "ru.yaml"
SOURCES = [
    TEMPLATE_DIR / "template_web_service_by_itforprof_com.yaml",
    TEMPLATE_DIR / "template_web_service_by_itforprof_com_tls.yaml",
]

FIELDS = {"name", "description", "event_name", "opdata", "newvalue"}
# Names under these parents are identifiers, not display text: groups and value
# maps are referenced by name, and web scenario/step names are part of item keys.
KEEP_UNDER = {"template_groups", "groups", "vendor", "valuemap", "valuemaps", "httptests", "steps"}
MACRO_RE = re.compile(r"\{\?[^{}]+\}|\{[^{}\s]+\}")  # {?expression} macros contain spaces


def ru_path(source: Path) -> Path:
    return source.with_name(source.stem + "_ru.yaml")


def _walk(node: Any, parent: str, visit: Any) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, str) and key in FIELDS and parent not in KEEP_UNDER:
                node[key] = visit(value)
            else:
                _walk(value, key, visit)
    elif isinstance(node, list):
        for item in node:
            _walk(item, parent, visit)


def strings(doc: dict[str, Any]) -> list[str]:
    found: list[str] = []
    _walk(doc, "", lambda s: found.append(s) or s)
    return found


def translate(doc: dict[str, Any], catalog: dict[str, str]) -> dict[str, Any]:
    _walk(doc, "", lambda s: catalog.get(s, s))
    return doc


class _Dumper(yaml.SafeDumper):
    pass


def _str(dumper: yaml.SafeDumper, value: str) -> yaml.ScalarNode:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


_Dumper.add_representer(str, _str)


def render(source: Path, catalog: dict[str, str]) -> str:
    doc = translate(yaml.safe_load(source.read_text(encoding="utf-8")), catalog)
    header = (
        f"# GENERATED from {source.name} + i18n/{CATALOG.name} by scripts/translate-templates.py.\n"
        "# Do not edit: change the English template or the catalog and rerun the script.\n"
    )
    body = yaml.dump(doc, Dumper=_Dumper, allow_unicode=True, sort_keys=False, width=10**6)
    return header + body


def load_catalog() -> dict[str, str]:
    data = yaml.safe_load(CATALOG.read_text(encoding="utf-8")) or {}
    return {str(k): str(v) for k, v in data.items()}


def problems(catalog: dict[str, str]) -> list[str]:
    out: list[str] = []
    used: set[str] = set()
    for source in SOURCES:
        for s in strings(yaml.safe_load(source.read_text(encoding="utf-8"))):
            used.add(s)
            if s not in catalog:
                out.append(f"untranslated in {source.name}: {s[:80]!r}")
            elif sorted(MACRO_RE.findall(s)) != sorted(MACRO_RE.findall(catalog[s])):
                out.append(f"macros differ: {s[:80]!r}")
        if not ru_path(source).exists() or ru_path(source).read_text(encoding="utf-8") != render(source, catalog):
            out.append(f"stale: {ru_path(source).name} (rerun scripts/translate-templates.py)")
    out += [f"unused catalog entry: {s[:80]!r}" for s in catalog if s not in used]
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="verify only, write nothing")
    mode.add_argument("--missing", action="store_true", help="print untranslated strings as a YAML stub")
    args = ap.parse_args()
    catalog = load_catalog() if CATALOG.exists() else {}

    if args.missing:
        missing = {s: "" for source in SOURCES for s in strings(yaml.safe_load(source.read_text(encoding="utf-8")))}
        stub = {s: v for s, v in missing.items() if s not in catalog}
        print(yaml.dump(stub, Dumper=_Dumper, allow_unicode=True, sort_keys=False, width=10**6), end="")
        return 0
    if not args.check:
        for source in SOURCES:
            ru_path(source).write_text(render(source, catalog), encoding="utf-8")
    found = problems(catalog)
    for p in found:
        print(p, file=sys.stderr)
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
