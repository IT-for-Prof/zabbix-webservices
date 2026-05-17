"""TLS deep-scan (Layer 5) tests.

We spin up an in-process TLS server using `trustme` and exercise the scanner
end to end. Assertions are kept structural (not exact-value) because OpenSSL
build flags vary across distros — what matters is that the scanner correctly
*classifies* what it sees: supported protocols populated, weak-finding shape
honoured, LLD translation preserves cardinality.
"""

from __future__ import annotations

import socket
import ssl
import threading
from contextlib import contextmanager

import pytest

trustme = pytest.importorskip("trustme")


@contextmanager
def _tls_server(cert_bundle, host="127.0.0.1"):
    """Single-port TLS server accepting one or more handshakes per test."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    cert_bundle.configure_cert(ctx)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, 0))
    sock.listen(16)
    port = sock.getsockname()[1]
    stop = threading.Event()

    def serve():
        sock.settimeout(0.25)
        while not stop.is_set():
            try:
                client, _ = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                # Listener closed by the main thread during shutdown.
                return
            try:
                with ctx.wrap_socket(client, server_side=True) as ss:
                    # Drain anything the client wants to send and close.
                    ss.recv(1)
            except Exception:  # noqa: BLE001, S110 — best-effort echo
                pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        yield port
    finally:
        stop.set()
        # Let the serve loop exit its current accept() cycle before closing the
        # underlying fd — avoids a Bad-file-descriptor traceback in test logs.
        t.join(timeout=2)
        sock.close()


def _scan(monkeypatch, web_check_module, port, url="https://127.0.0.1"):
    monkeypatch.setattr(web_check_module, "url_host", lambda u, **kw: ("127.0.0.1", port))
    return web_check_module.run_tls_scan(url, timeout=4.0)


def test_tls_scan_happy_path_modern_server(monkeypatch, web_check_module):
    """A modern TLS server (Python default = TLS 1.2/1.3) gets correctly classified."""
    ca = trustme.CA()
    leaf = ca.issue_cert("127.0.0.1")
    with _tls_server(leaf) as port:
        scan = _scan(monkeypatch, web_check_module, port)

    assert scan["ok"] is True
    assert scan["host"] == "127.0.0.1"
    assert scan["port"] == port
    # Default Python SSLContext supports at minimum TLS 1.2; usually 1.3 too.
    assert any(p in scan["supported_protocols"] for p in ("TLSv1.2", "TLSv1.3"))
    # We never list a protocol we couldn't negotiate.
    assert all(p in {"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"} for p in scan["supported_protocols"])
    # negotiated_ciphers keys are a subset of supported_protocols.
    assert set(scan["negotiated_ciphers"]).issubset(set(scan["supported_protocols"]))
    # Trustme spawns a contemporary server — no weak cipher families should accept.
    assert all(f["category"] in {"protocol", "cipher"} for f in scan["weak_findings"])
    assert scan["weak_count"] == len(scan["weak_findings"])


def test_tls_scan_bad_url_returns_envelope(monkeypatch, web_check_module):
    # Force url_host to fail — simulates URLs whose hostname can't be parsed.
    monkeypatch.setattr(web_check_module, "url_host", lambda u, **kw: (None, 443))
    scan = web_check_module.run_tls_scan("https://", timeout=1.0)
    assert scan["ok"] is False
    assert scan["error_code"] == "bad_url"


def test_tls_scan_unreachable_returns_envelope(monkeypatch, web_check_module):
    # Bind a socket so we have a known free port; close before the scan.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    monkeypatch.setattr(web_check_module, "url_host", lambda u, **kw: ("127.0.0.1", port))
    scan = web_check_module.run_tls_scan("https://127.0.0.1", timeout=1.0)
    # Nothing negotiable → tls_error envelope.
    assert scan["ok"] is False
    assert scan["error_code"] == "tls_error"
    assert scan["supported_protocols"] == []


def test_tls_scan_records_weak_cipher_when_family_negotiates(monkeypatch, web_check_module):
    """If `_try_weak_cipher_family` reports a hit, the scan must surface it as a finding."""
    # Pretend the server supports TLS 1.2 (so the cipher-probe stage runs) but
    # not 1.3, so we know the probe loop executed. Stub both probe helpers so
    # the test is deterministic and offline.
    monkeypatch.setattr(
        web_check_module,
        "_try_protocol",
        lambda host, port, version, timeout: (version == ssl.TLSVersion.TLSv1_2, "ECDHE-RSA-AES128-SHA"),
    )
    fake_hits = {"RC4": "RC4-SHA", "3DES": "DES-CBC3-SHA"}
    monkeypatch.setattr(
        web_check_module,
        "_try_weak_cipher_family",
        lambda host, port, family, timeout: fake_hits.get(family),
    )
    monkeypatch.setattr(web_check_module, "url_host", lambda u, **kw: ("127.0.0.1", 4443))

    scan = web_check_module.run_tls_scan("https://x", timeout=1.0)

    assert scan["ok"] is True
    assert scan["supported_protocols"] == ["TLSv1.2"]
    weak_names = {f["name"] for f in scan["weak_findings"]}
    assert {"RC4-SHA", "DES-CBC3-SHA"}.issubset(weak_names)
    assert all(f["category"] == "cipher" for f in scan["weak_findings"])
    assert scan["weak_count"] == len(scan["weak_findings"])


def test_tls_scan_skips_cipher_probes_when_only_tls13(monkeypatch, web_check_module):
    """TLS 1.3-only servers should never enter the weak-cipher probe loop."""
    monkeypatch.setattr(
        web_check_module,
        "_try_protocol",
        lambda host, port, version, timeout: (version == ssl.TLSVersion.TLSv1_3, "TLS_AES_256_GCM_SHA384"),
    )
    calls: list[str] = []

    def fake_probe(host, port, family, timeout):
        calls.append(family)
        return None

    monkeypatch.setattr(web_check_module, "_try_weak_cipher_family", fake_probe)
    monkeypatch.setattr(web_check_module, "url_host", lambda u, **kw: ("127.0.0.1", 4443))

    scan = web_check_module.run_tls_scan("https://x", timeout=1.0)
    assert scan["supported_protocols"] == ["TLSv1.3"]
    assert calls == [], "cipher probes should be skipped when TLS 1.3 is the only protocol"
    assert scan["weak_findings"] == []


def test_tls_scan_to_lld_shape(web_check_module):
    scan = {
        "weak_findings": [
            {"category": "protocol", "name": "TLSv1.0", "severity": "WARNING"},
            {"category": "cipher", "name": "RC4-MD5", "severity": "WARNING"},
        ],
    }
    lld = web_check_module.tls_scan_to_lld(scan)
    assert isinstance(lld, list)
    assert len(lld) == 2
    assert lld[0] == {
        "{#TLS_FINDING}": "TLSv1.0",
        "{#TLS_FINDING.CATEGORY}": "protocol",
        "{#TLS_FINDING.SEVERITY}": "WARNING",
    }
    assert lld[1]["{#TLS_FINDING}"] == "RC4-MD5"
    assert lld[1]["{#TLS_FINDING.CATEGORY}"] == "cipher"


def test_tls_scan_to_lld_empty(web_check_module):
    assert web_check_module.tls_scan_to_lld({}) == []
    assert web_check_module.tls_scan_to_lld({"weak_findings": []}) == []


def test_cli_discover_tls_emits_array(monkeypatch, capsys, web_check_module):
    """`discover-tls` must emit a bare JSON array (Zabbix LLD ≥4.2)."""
    import argparse
    import json

    monkeypatch.setattr(
        web_check_module,
        "run_tls_scan",
        lambda url, timeout=10.0: {
            "ok": True,
            "weak_findings": [
                {"category": "protocol", "name": "TLSv1.1", "severity": "WARNING"},
            ],
        },
    )
    monkeypatch.setattr(web_check_module, "emit", lambda payload: print(json.dumps(payload)))
    ns = argparse.Namespace(url="https://example.com", timeout="10")
    web_check_module.cmd_discover_tls(ns)
    out = capsys.readouterr().out.strip()
    data = json.loads(out)
    assert isinstance(data, list)
    assert data[0]["{#TLS_FINDING}"] == "TLSv1.1"


def test_cli_tls_scan_emits_object(monkeypatch, capsys, web_check_module):
    import argparse
    import json

    monkeypatch.setattr(
        web_check_module, "run_tls_scan", lambda url, timeout=10.0: {"ok": True, "url": url, "weak_findings": []}
    )
    monkeypatch.setattr(web_check_module, "emit", lambda payload: print(json.dumps(payload)))
    ns = argparse.Namespace(url="https://example.com", timeout="10")
    web_check_module.cmd_tls_scan(ns)
    out = capsys.readouterr().out.strip()
    data = json.loads(out)
    assert data["ok"] is True
    assert data["url"] == "https://example.com"
