"""Shared pytest fixtures for the web_check test suite.

The script under test is `scripts/externalscripts/web_check.py`. It is not a
package; we add its directory to `sys.path` so tests can `import web_check`
directly.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts" / "externalscripts"
# `scripts/` itself is needed for tests that load `migrate-from-itmicus.py`
# (which imports `_zabbix_client` at module level). `python -m pytest` adds
# CWD to sys.path implicitly, but the bare `pytest` invocation used in CI
# does not — be explicit here so both modes work the same.
sys.path.insert(0, str(REPO_ROOT / "scripts"))
sys.path.insert(0, str(SCRIPTS_DIR))


@pytest.fixture()
def tmp_cache(tmp_path, monkeypatch):
    """Isolated WhoisCache pointed at tmp_path/cache."""
    import web_check

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    monkeypatch.setattr(web_check, "CACHE_DIR", cache_dir)
    return web_check.WhoisCache(root=cache_dir)


@pytest.fixture()
def web_check_module():
    """Importable module reference (path injected by sys.path above)."""
    import web_check  # noqa: PLC0415  — module-not-package, intentional path import

    return web_check
