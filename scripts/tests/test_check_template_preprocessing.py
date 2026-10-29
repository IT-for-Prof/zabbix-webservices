"""Tests for scripts/check-template-preprocessing.py."""

from __future__ import annotations

import importlib.util
import pathlib
import sys

import pytest
import yaml


@pytest.fixture(scope="module")
def pp():
    p = pathlib.Path(__file__).resolve().parent.parent / "check-template-preprocessing.py"
    spec = importlib.util.spec_from_file_location("check_template_preprocessing", p)
    assert spec and spec.loader, f"could not load spec from {p}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


TEMPLATE = {
    "template": "Test template",
    "vendor": {"version": "7.0-1.0.0"},
    "items": [
        {
            "key": "flag",
            "preprocessing": [
                {
                    "type": "NOT_MATCHES_REGEX",
                    "parameters": ['"ok":false'],
                    "error_handler": "DISCARD_VALUE",
                },
                {"type": "BOOL_TO_DECIMAL", "parameters": [""]},
            ],
        },
        {"key": "gone"},
    ],
}
CLEAN_FLAG = [
    {"type": "15", "params": '"ok":false', "error_handler": "1", "error_handler_params": ""},
    {"type": "6", "params": "", "error_handler": "0", "error_handler_params": ""},
]


class FakeZabbix:
    url = "https://zabbix.example/api_jsonrpc.php"

    def __init__(self, *, version="7.0-1.0.0", items=None, templates=True, rows=None):
        self.version = version
        self.items = items if items is not None else []
        self.templates = templates
        self.rows = rows or {}  # e.g. {"discoveryrule.get": [...]}
        self.calls = []

    def call(self, method, params=None):
        self.calls.append((method, params))
        if method == "template.get":
            return [{"templateid": "1", "vendor_version": self.version}] if self.templates else []
        if method == "item.get":
            return self.items
        if method in self.rows:
            return self.rows[method]
        if method.endswith(".get"):
            return []
        return {}

    def updates(self):
        return [params for method, params in self.calls if method.endswith(".update")]


def _write(tmp_path, template=TEMPLATE):
    path = tmp_path / "t.yaml"
    path.write_text(yaml.safe_dump({"zabbix_export": {"templates": [template]}}))
    return path


def _row(itemid, key, steps):
    return {"itemid": itemid, "key_": key, "preprocessing": [dict(s, sortorder="0") for s in steps]}


def test_expected_steps_fill_every_field(pp):
    assert pp.expected_steps(TEMPLATE["items"][0]["preprocessing"]) == CLEAN_FLAG
    assert pp.expected_steps(None) == []


def test_stale_fields_are_a_mismatch_and_apply_rewrites_them(pp, tmp_path):
    stale = [dict(CLEAN_FLAG[0], error_handler_params="old text"), dict(CLEAN_FLAG[1], params="1h")]
    zbx = FakeZabbix(items=[_row("10", "flag", stale), _row("11", "gone", [])])

    assert pp.main([str(_write(tmp_path)), "--apply"], zbx) == 1
    assert zbx.updates() == [{"itemid": "10", "preprocessing": CLEAN_FLAG}]


def test_clean_template_passes(pp, tmp_path):
    zbx = FakeZabbix(items=[_row("10", "flag", CLEAN_FLAG), _row("11", "gone", []), _row("12", "extra", [])])

    assert pp.main([str(_write(tmp_path))], zbx) == 0
    assert zbx.updates() == []


def test_object_missing_on_server_is_a_mismatch(pp, tmp_path):
    zbx = FakeZabbix(items=[_row("10", "flag", CLEAN_FLAG)])

    assert pp.main([str(_write(tmp_path)), "--apply"], zbx) == 1
    assert zbx.updates() == []


def test_version_mismatch_compares_and_writes_nothing(pp, tmp_path):
    zbx = FakeZabbix(version="7.0-0.9.0", items=[_row("10", "flag", [])])

    assert pp.main([str(_write(tmp_path)), "--apply"], zbx) == 1
    assert [m for m, _ in zbx.calls] == ["template.get"]


def test_lld_rule_and_prototype_are_compared_and_rewritten(pp, tmp_path):
    lld = {
        "key": "lld",
        "preprocessing": TEMPLATE["items"][0]["preprocessing"],
        "item_prototypes": [{"key": "p[{#X}]"}],
    }
    stale = [dict(CLEAN_FLAG[0], error_handler_params="old text")]
    zbx = FakeZabbix(
        rows={
            "discoveryrule.get": [_row("20", "lld", stale + CLEAN_FLAG[1:])],
            "itemprototype.get": [_row("21", "p[{#X}]", stale)],
        }
    )

    assert pp.main([str(_write(tmp_path, dict(TEMPLATE, items=[], discovery_rules=[lld]))), "--apply"], zbx) == 1
    assert [(m, p) for m, p in zbx.calls if m.endswith(".update")] == [
        ("discoveryrule.update", {"itemid": "20", "preprocessing": CLEAN_FLAG}),
        ("itemprototype.update", {"itemid": "21", "preprocessing": []}),
    ]


def test_no_template_on_server_fails(pp, tmp_path):
    assert pp.main([str(_write(tmp_path))], FakeZabbix(templates=False)) == 1


def _objects(pp, path):
    return pp.file_objects(yaml.safe_load(path.read_text())["zabbix_export"]["templates"][0])


def test_project_templates_use_known_step_types(pp):
    for path in pp.DEFAULT_FILES:
        assert _objects(pp, path), path


def test_russian_templates_have_the_same_steps(pp):
    # The servers run the _ru files; the default English files must be a valid reference for --apply.
    for path in pp.DEFAULT_FILES:
        assert _objects(pp, path.with_name(f"{path.stem}_ru.yaml")) == _objects(pp, path), path
