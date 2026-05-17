"""End-to-end smoke: `web_check.py self-test` returns ok=true when deps are present."""

from __future__ import annotations

import json


def test_self_test_emits_valid_json(monkeypatch, capsys, web_check_module):
    monkeypatch.setattr(web_check_module, "emit", lambda payload: print(json.dumps(payload)))
    web_check_module.cmd_self_test(None)
    out = capsys.readouterr().out.strip()
    data = json.loads(out)
    assert data["version"] == web_check_module.__version__
    assert data["schema_version"] == web_check_module.SCHEMA_VERSION
    # cache-roundtrip must always pass; the imports may fail on a bare env
    assert any("cache roundtrip: ok" in f for f in data["findings"])
