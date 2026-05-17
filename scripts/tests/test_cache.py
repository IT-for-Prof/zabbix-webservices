"""WhoisCache roundtrip + freshness + atomicity tests (validation D group)."""

from __future__ import annotations

import time


def test_roundtrip(tmp_cache):
    tmp_cache.write("example.com", {"ok": True, "registrar": "Test"}, ttl=60)
    hit = tmp_cache.read("example.com")
    assert hit is not None
    assert hit.payload == {"ok": True, "registrar": "Test"}
    assert hit.fresh()
    assert hit.age_seconds() < 5


def test_miss_returns_none(tmp_cache):
    assert tmp_cache.read("nope.invalid") is None


def test_stale_after_ttl(tmp_cache):
    tmp_cache.write("example.com", {"ok": True}, ttl=1)
    time.sleep(1.2)
    hit = tmp_cache.read("example.com")
    assert hit is not None
    assert not hit.fresh()


def test_lock_non_blocking_yields_when_contended(tmp_cache):
    """flock(LOCK_EX|LOCK_NB) — second acquirer gets None, doesn't block."""
    with tmp_cache.lock("example.com") as a:
        assert a is not None
        with tmp_cache.lock("example.com") as b:
            assert b is None


def _writer(cache_root, apex, value, started, done):
    """Helper for the stampede test — writes from a child process."""
    import sys

    sys.path.insert(0, str(cache_root.parent.parent / "scripts" / "externalscripts"))
    import web_check  # noqa: PLC0415

    cache = web_check.WhoisCache(root=cache_root)
    started.set()
    with cache.lock(apex, blocking=True) as fh:
        assert fh is not None
        # simulate a slow upstream
        time.sleep(0.4)
        cache.write(apex, {"value": value}, ttl=60)
    done.set()


def test_atomic_write_no_partials(tmp_cache):
    """Repeated rapid writes leave the cache file always JSON-parseable."""
    import json

    for i in range(50):
        tmp_cache.write("apex.test", {"i": i, "padding": "X" * 200}, ttl=60)
    # File present and parseable
    p = tmp_cache._path("apex.test")
    raw = json.loads(p.read_text(encoding="utf-8"))
    assert raw["payload"]["i"] == 49
