"""The Russian templates stay a pure translation of the English ones.

Same UUIDs, keys, expressions, macros and tags are what let a host switch
language by importing the other file over the same template.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys
from typing import Any

import pytest
import yaml


@pytest.fixture(scope="module")
def i18n():
    p = pathlib.Path(__file__).resolve().parent.parent / "translate-templates.py"
    spec = importlib.util.spec_from_file_location("translate_templates", p)
    assert spec and spec.loader, f"could not load spec from {p}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load(path: pathlib.Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_russian_templates_are_in_sync_with_english_and_catalog(i18n):
    """Fails when the English template changed without a translation, or *_ru.yaml was not regenerated."""
    assert i18n.problems(i18n.load_catalog()) == []


def test_identifiers_stay_english(i18n):
    """Technical names, web scenario/step names and value map names are identifiers, not display text."""
    for source in i18n.SOURCES:
        en, ru = (
            _load(source)["zabbix_export"]["templates"][0],
            _load(i18n.ru_path(source))["zabbix_export"]["templates"][0],
        )
        assert ru["uuid"] == en["uuid"]
        assert ru["template"] == en["template"]
        assert ru["name"] != en["name"], "visible name is translated so the language is visible in the UI"
        assert [h["name"] for h in ru.get("httptests", [])] == [h["name"] for h in en.get("httptests", [])]
        assert [v["name"] for v in ru.get("valuemaps", [])] == [v["name"] for v in en.get("valuemaps", [])]


def test_russian_trigger_dependencies_resolve(i18n):
    """Dependencies name the target trigger, so translated names must stay consistent."""
    for source in i18n.SOURCES:
        ru = _load(i18n.ru_path(source))["zabbix_export"]["templates"][0]
        triggers = [t for item in ru["items"] for t in item.get("triggers", []) or []]
        by_name = {t["name"]: t["expression"] for t in triggers}
        assert len(by_name) == len(triggers), "translated trigger names must stay unique"
        for trigger in triggers:
            for dep in trigger.get("dependencies", []) or []:
                assert by_name.get(dep["name"]) == dep["expression"], (source.name, dep["name"])
