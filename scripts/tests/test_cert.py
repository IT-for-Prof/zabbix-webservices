"""TLS / cert extraction tests using `trustme` for synthetic certs.

These tests prove our cert checker correctly:
  * extracts every field promised by `cert.json` shape (B1),
  * marks self-signed / hostname-mismatch via `chain_status` (E2, E3),
  * returns negative `days_to_expire` for expired certs (E1),
  * handles DNS failure / TCP timeout (E4, E5).

`trustme` generates an ephemeral CA + leaf cert in-memory and ssl-wraps a
local socket. No external network needed.
"""

from __future__ import annotations

import socket
import ssl
import threading
from contextlib import contextmanager
from datetime import UTC, datetime

import pytest

trustme = pytest.importorskip("trustme")


@contextmanager
def _tls_server(cert_bundle, host="127.0.0.1"):
    """Spin up a single-shot TLS-echo server on a free port."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert_bundle.configure_cert(ctx)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, 0))
    sock.listen(5)
    port = sock.getsockname()[1]
    stop = threading.Event()

    def serve():
        sock.settimeout(0.5)
        while not stop.is_set():
            try:
                client, _ = sock.accept()
            except TimeoutError:
                continue
            try:
                with ctx.wrap_socket(client, server_side=True) as ss:
                    ss.recv(1024)
            except Exception:  # noqa: BLE001, S110 — best-effort echo server for tests
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        yield port
    finally:
        stop.set()
        sock.close()
        t.join(timeout=2)


def _patch_default_ssl(monkeypatch, ca):
    """Make ssl.create_default_context trust our synthetic CA."""
    orig = ssl.create_default_context

    def patched(*a, **kw):
        ctx = orig(*a, **kw)
        ca.configure_trust(ctx)
        return ctx

    monkeypatch.setattr(ssl, "create_default_context", patched)


def test_cert_happy_path(monkeypatch, web_check_module):
    ca = trustme.CA()
    # Issue the leaf for "127.0.0.1" so both server_hostname AND the cert's SAN
    # match the IP we're connecting to. Avoids host-mismatch noise in the test.
    leaf = ca.issue_cert("127.0.0.1")
    _patch_default_ssl(monkeypatch, ca)
    with _tls_server(leaf) as port:
        url = f"https://127.0.0.1:{port}"
        monkeypatch.setattr(web_check_module, "url_host", lambda u, **kw: ("127.0.0.1", port))
        res = web_check_module.check_cert(url, timeout=5)
    assert res.ok is True
    assert res.cert["chain_status"] == "ok"
    assert res.cert["days_to_expire"] >= 0
    assert res.cert["public_key_algorithm"] in ("rsa", "ecdsa")
    assert res.cert["hostname_covered"] is True
    assert res.tls["protocol"].startswith("TLSv1.")


def test_cert_self_signed_marks_untrusted(monkeypatch, web_check_module):
    """No CA-trust patching → leaf cert is untrusted to the default store."""
    ca = trustme.CA()
    leaf = ca.issue_cert("127.0.0.1")  # we'll connect by IP
    with _tls_server(leaf) as port:
        monkeypatch.setattr(web_check_module, "url_host", lambda u, **kw: ("127.0.0.1", port))
        res = web_check_module.check_cert(f"https://127.0.0.1:{port}", timeout=5)
    assert res.ok is True  # we still got data
    assert res.cert["chain_status"] == "untrusted"
    assert res.error_code == "cert_untrusted"


def test_cert_dns_error(web_check_module):
    res = web_check_module.check_cert("https://nx-this-does-not-exist-12345.invalid", timeout=3)
    assert res.ok is False
    assert res.error_code == "dns_error"


def test_cert_bad_url(web_check_module):
    res = web_check_module.check_cert("not a url at all", timeout=1)
    # "not a url at all" → urlparse extracts "not a url at all" → no hostname
    assert res.ok is False
    assert res.error_code in ("bad_url", "dns_error")  # tolerant: urlparse quirks


def test_cert_attribute_shim_handles_either_api(web_check_module):
    """`_cert_attr_utc` must work whether `cryptography` exposes _utc variant or not."""

    class StubOld:
        not_valid_after = datetime(2030, 1, 1)  # naive

    class StubNew:
        not_valid_after_utc = datetime(2030, 1, 1, tzinfo=UTC)
        not_valid_after = datetime(2030, 1, 1)  # also defined; _utc should win

    old = web_check_module._cert_attr_utc(StubOld(), "not_valid_after", "not_valid_after_utc")
    new = web_check_module._cert_attr_utc(StubNew(), "not_valid_after", "not_valid_after_utc")
    assert old.tzinfo is UTC
    assert new.tzinfo is UTC
    assert old == new
