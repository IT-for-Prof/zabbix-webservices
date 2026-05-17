"""Layer 6 — HTTP/3 probe tests.

Network-isolated: we mock the two leaf helpers (`_alt_svc_advertises_h3` and
`_quic_handshake`) and exercise the orchestration in `run_http3_check`.
"""

from __future__ import annotations

import pytest

pytest.importorskip("aioquic")


def test_http3_skipped_when_alt_svc_missing(monkeypatch, web_check_module):
    """No Alt-Svc h3 advertisement → no UDP probe, no error, advertised=False."""
    monkeypatch.setattr(web_check_module, "_alt_svc_advertises_h3", lambda *a, **kw: False)

    # Make sure `_quic_handshake` is NOT called.
    called = {"udp": False}

    async def fake_handshake(*a, **kw):
        called["udp"] = True
        return {}

    monkeypatch.setattr(web_check_module, "_quic_handshake", fake_handshake)

    result = web_check_module.run_http3_check("https://example.com", timeout=1.0)
    assert result["ok"] is True
    assert result["alt_svc_advertised"] is False
    assert result["h3_reachable"] is False
    assert result["error_code"] == ""
    assert called["udp"] is False, "must not run QUIC probe when h3 isn't advertised"


def test_http3_happy_path(monkeypatch, web_check_module):
    """Advertised + QUIC handshake succeeds → reachable=True with handshake metrics."""
    monkeypatch.setattr(web_check_module, "_alt_svc_advertises_h3", lambda *a, **kw: True)

    async def fake_handshake(host, port, timeout):
        return {
            "h3_reachable": True,
            "handshake_ms": 42.0,
            "alpn": "h3",
            "quic_version": "0x00000001",
        }

    monkeypatch.setattr(web_check_module, "_quic_handshake", fake_handshake)

    result = web_check_module.run_http3_check("https://example.com", timeout=2.0)
    assert result["ok"] is True
    assert result["alt_svc_advertised"] is True
    assert result["h3_reachable"] is True
    assert result["handshake_ms"] == 42.0
    assert result["alpn"] == "h3"
    assert result["quic_version"] == "0x00000001"
    assert result["error_code"] == ""


def test_http3_advertised_but_unreachable_timeout(monkeypatch, web_check_module):
    """Advertised + UDP probe times out → h3_unreachable / h3_timeout error code."""
    monkeypatch.setattr(web_check_module, "_alt_svc_advertises_h3", lambda *a, **kw: True)

    async def hang(*a, **kw):
        import asyncio

        await asyncio.sleep(5.0)

    monkeypatch.setattr(web_check_module, "_quic_handshake", hang)

    result = web_check_module.run_http3_check("https://example.com", timeout=0.2)
    assert result["ok"] is True
    assert result["alt_svc_advertised"] is True
    assert result["h3_reachable"] is False
    assert result["error_code"] == "h3_timeout"
    assert "0.2" in result["error_message"]


def test_http3_advertised_but_unreachable_oserror(monkeypatch, web_check_module):
    """Advertised + UDP probe raises OSError → h3_unreachable code."""
    monkeypatch.setattr(web_check_module, "_alt_svc_advertises_h3", lambda *a, **kw: True)

    async def boom(*a, **kw):
        raise ConnectionRefusedError("nope")

    monkeypatch.setattr(web_check_module, "_quic_handshake", boom)

    result = web_check_module.run_http3_check("https://example.com", timeout=1.0)
    assert result["ok"] is True
    assert result["alt_svc_advertised"] is True
    assert result["h3_reachable"] is False
    assert result["error_code"] == "h3_unreachable"
    assert "nope" in result["error_message"]


def test_http3_bad_url(monkeypatch, web_check_module):
    monkeypatch.setattr(web_check_module, "url_host", lambda u, **kw: (None, 443))
    result = web_check_module.run_http3_check("https://", timeout=1.0)
    assert result["ok"] is False
    assert result["error_code"] == "bad_url"


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ('h3=":443"; ma=86400', True),
        ('h3=":443"; ma=86400, h3-29=":443"', True),
        ('h3-29=":443"', True),
        ('H3=":443"', True),  # case-insensitive
        ('h2=":443"', False),
        ("", False),
        ("clear", False),
    ],
)
def test_alt_svc_regex(web_check_module, header, expected):
    """`ALT_SVC_H3_RE` correctly matches the h3 / h3-NN protocol tokens."""
    assert bool(web_check_module.ALT_SVC_H3_RE.search(header)) is expected


def test_cli_http3_emits_object(monkeypatch, capsys, web_check_module):
    import argparse
    import json

    monkeypatch.setattr(
        web_check_module,
        "run_http3_check",
        lambda url, timeout=8.0: {"ok": True, "url": url, "h3_reachable": True, "handshake_ms": 33.5},
    )
    monkeypatch.setattr(web_check_module, "emit", lambda payload: print(json.dumps(payload)))
    ns = argparse.Namespace(url="https://example.com", timeout="8")
    web_check_module.cmd_http3(ns)
    out = capsys.readouterr().out.strip()
    data = json.loads(out)
    assert data["ok"] is True
    assert data["handshake_ms"] == 33.5
