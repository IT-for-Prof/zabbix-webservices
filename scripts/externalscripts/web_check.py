#!/opt/web_check/venv/bin/python
# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Konstantin Tyutyunnik <https://itforprof.com>
"""web_check — Zabbix externalscript for TLS/cert + apex-deduped WHOIS + TLS deep scan.

Designed to be invoked by zabbix_server or zabbix_proxy as an EXTERNAL item
type. Each subcommand emits a single JSON object to stdout that Zabbix
stores as the master item value; dependent items extract fields via
JSONPath preprocessing. Exit code is always 0 — errors are encoded as
`{"ok": false, "error_code": "...", "error_message": "..."}`.

Subcommands:
  cert URL          — Layer 2: TLS handshake metrics + cert fields (5m delay)
  whois URL         — Layer 3: WHOIS/RDAP via asyncwhois, apex-keyed FS cache
  tls-scan URL      — Layer 5: daily protocol/cipher matrix
  discover-tls URL  — LLD JSON of weak findings from the tls-scan matrix
  http3 URL         — Layer 6: HTTP/3 advertise + QUIC handshake (aioquic, 5m delay)
  self-test         — smoke check on bundled fixtures, no network
  --version         — semver

Design and rationale: see docs/architecture.md.
Validation log:     see docs/validation.md.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import fcntl
import hashlib
import json
import os
import re
import socket
import ssl
import sys
import time
import warnings
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# Zabbix externalscripts capture stdout AND stderr into the item value, so any
# DeprecationWarning leaking from probing `ssl.TLSVersion.TLSv1` / `TLSv1_1`
# during `tls-scan` corrupts the JSON. Silence them — narrowly, by `module=`
# pattern, so genuine deprecation warnings from dependencies (asyncwhois,
# aioquic, cryptography future-removals) STILL surface during `self-test` and
# in CI, but TLSv1.0/1.1 probing in this module stays quiet at run time.
warnings.filterwarnings(
    "ignore",
    category=DeprecationWarning,
    module=r"web_check.*",
)

__version__ = "2.1.4"
SCHEMA_VERSION = 1

# Layout assumed when deployed via scripts/deploy/install.sh.
HOME = Path(os.environ.get("WEB_CHECK_HOME", "/opt/web_check"))
CACHE_DIR = HOME / "data" / "cache"

# Default WHOIS cache TTLs (overridable via env / Zabbix macros at scheduling layer).
WHOIS_CACHE_TTL = int(os.environ.get("WEB_CHECK_WHOIS_CACHE_TTL", 86400))  # 24h
WHOIS_NEGATIVE_TTL = int(os.environ.get("WEB_CHECK_WHOIS_NEG_TTL", 3600))  # 1h on provider_no_expiry / failures

# Per-registry rate hints (see architecture.md "Registry rate-limit policy").
# TCI is strictest in practice — keep that lane skinny.
TCI_TLDS = {"ru", "su", "xn--p1ai"}  # .ru .su .рф
HU_TLDS = {"hu"}  # registry omits expiration entirely
NO_EXPIRY_TLDS = HU_TLDS  # extend if other registries join the club


# =============================================================================
# Output envelope
# =============================================================================


def now_iso() -> str:
    """Current UTC time as RFC3339-ish string with second precision."""
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def emit(payload: dict[str, Any] | list[dict[str, Any]]) -> None:
    """Print compact JSON to stdout and exit success. Always exits 0.

    Accepts a dict (typical master-item payload) or a list (LLD output for
    Zabbix ≥4.2, which expects a bare JSON array, not `{"data": …}`).
    """
    print(json.dumps(payload, separators=(",", ":"), default=str))
    raise SystemExit(0)


def error_envelope(error_code: str, message: str, **extra: Any) -> dict[str, Any]:
    """Build the {ok: false, …} envelope."""
    out = {
        "ok": False,
        "schema_version": SCHEMA_VERSION,
        "checked_at": now_iso(),
        "error_code": error_code,
        "error_message": message[:300],  # bound for sane Zabbix display
    }
    out.update(extra)
    return out


# =============================================================================
# Apex extraction (tldextract)
# =============================================================================


def url_host(url: str, *, force_tls: bool = False) -> tuple[str | None, int]:
    """Parse a URL and return (lowercase hostname, port).

    When `force_tls=True`, callers that need a TLS endpoint (cert / tls-scan)
    get port 443 regardless of the URL's scheme. Sites are commonly monitored
    over plain http:// (the web scenario) yet still serve TLS for users; the
    cert check should still probe the canonical HTTPS endpoint.
    """
    if "://" not in url:
        url = "https://" + url
    p = urlparse(url)
    host = p.hostname.lower() if p.hostname else None
    if force_tls:
        port = p.port if (p.port and p.scheme == "https") else 443
    elif p.port:
        port = p.port
    elif p.scheme == "http":
        port = 80
    else:
        port = 443
    return host, port


# Module-level (lazy-init) tldextract instance, configured for OFFLINE-only
# lookup. Two separate hazards in tldextract's defaults trip up the
# zabbix:zabbix externalscript runtime; both must be neutralised:
#
#   1. Network fetch. By default tldextract pulls the Public Suffix List
#      from publicsuffix.org on first use. `suffix_list_urls=()` plus
#      `fallback_to_snapshot=True` forces use of the snapshot bundled in
#      the tldextract wheel — no network. Refresh the snapshot quarterly
#      by bumping tldextract in requirements.in.
#
#   2. Cache write. Even with the network disabled, tldextract's
#      `DiskCache` still writes the parsed PSL into
#      `$XDG_CACHE_HOME/python-tldextract/` (defaulting to
#      `$HOME/.cache/python-tldextract/`). The zabbix user's `$HOME` is
#      typically `/var/lib/zabbix/`, which is owned by root and lacks a
#      writable `.cache/`. The write fails and tldextract emits a
#      `[Errno 13] Permission denied` record via stdlib `logging` (logger
#      `tldextract.cache`, default destination stderr). In our Zabbix
#      deployment the externalscript handler captures stderr alongside
#      stdout into the master item's lastvalue — every dependent
#      JSONPath-preprocessed item then fails to parse the
#      warning-prefixed envelope. `cache_dir=None` disables the cache
#      entirely (`DiskCache.enabled = bool(cache_dir)` ⇒ False); the
#      bundled PSL snapshot is loaded in-memory from the wheel on the
#      first call and memoised on the extractor for the lifetime of the
#      process — fine for a short-lived per-call externalscript.
_PSL_EXTRACTOR: Any = None  # lazy-init; set on first call


def registered_apex(host: str) -> str | None:
    """Extract the registered apex (e.g. mon.itforprof.com → itforprof.com).

    Uses tldextract's bundled snapshot — never makes network calls.
    Returns None if the host has no PSL apex (e.g. unparseable, raw IP,
    or a TLD not in the snapshot). Raises ImportError if tldextract is
    not installed — callers should distinguish "missing dependency" from
    "unresolved apex" envelopes.
    """
    global _PSL_EXTRACTOR
    if _PSL_EXTRACTOR is None:
        import tldextract  # raises ImportError if missing — caller handles

        _PSL_EXTRACTOR = tldextract.TLDExtract(
            suffix_list_urls=(),
            fallback_to_snapshot=True,
            cache_dir=None,
        )
    parts = _PSL_EXTRACTOR(host)
    if not parts.domain or not parts.suffix:
        return None
    return f"{parts.domain}.{parts.suffix}".lower()


def tld_of(apex: str) -> str:
    """Last label of an apex (e.g. itforprof.com → com, *.xn--p1ai → xn--p1ai)."""
    return apex.rsplit(".", 1)[-1] if "." in apex else apex


# =============================================================================
# FS cache (apex-keyed, atomic, stampede-safe)
# =============================================================================


@dataclass
class CacheEntry:
    """Single cache record. `data` holds the JSON payload as-emitted."""

    payload: dict[str, Any]
    written_at: float
    ttl: int

    def fresh(self) -> bool:
        return (time.time() - self.written_at) < self.ttl

    def age_seconds(self) -> int:
        return int(time.time() - self.written_at)


class WhoisCache:
    """Local FS cache keyed by sha256(apex)."""

    def __init__(self, root: Path = CACHE_DIR) -> None:
        self.root = root
        # Lazy mkdir — install.sh creates this with proper owner+mode, but
        # don't fail if it's missing (cache is best-effort).
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, apex: str) -> Path:
        digest = hashlib.sha256(apex.encode("utf-8")).hexdigest()
        return self.root / f"whois_{digest}.json"

    def _lock_path(self, apex: str) -> Path:
        return self._path(apex).with_suffix(".lock")

    def read(self, apex: str) -> CacheEntry | None:
        p = self._path(apex)
        if not p.is_file():
            return None
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
            return CacheEntry(
                payload=raw["payload"],
                written_at=float(raw["written_at"]),
                ttl=int(raw["ttl"]),
            )
        except (OSError, ValueError, KeyError):
            return None

    def write(self, apex: str, payload: dict[str, Any], ttl: int) -> None:
        """Atomic write via tmpfile + os.replace. Returns silently on permission errors."""
        record = {
            "schema_version": SCHEMA_VERSION,
            "apex": apex,
            "payload": payload,
            "written_at": time.time(),
            "ttl": ttl,
        }
        p = self._path(apex)
        tmp = p.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(record, default=str), encoding="utf-8")
            os.replace(tmp, p)
        except OSError:
            # Best-effort. If cache disk is full or unwritable, fall through.
            with contextlib.suppress(OSError):
                tmp.unlink()

    @contextlib.contextmanager
    def lock(self, apex: str, blocking: bool = False) -> Iterator[Any]:
        """Yield exclusive flock on a per-apex lock file. Stampede protection.

        If non-blocking and contended, yields None — caller decides.
        """
        lp = self._lock_path(apex)
        with contextlib.suppress(OSError):
            lp.touch(mode=0o600, exist_ok=True)
        with open(lp, "w") as fh:
            try:
                if blocking:
                    fcntl.flock(fh, fcntl.LOCK_EX)
                    yield fh
                else:
                    try:
                        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        yield fh
                    except BlockingIOError:
                        yield None
            finally:
                with contextlib.suppress(OSError):
                    fcntl.flock(fh, fcntl.LOCK_UN)


# =============================================================================
# Layer 2 — cert + TLS metrics
# =============================================================================


@dataclass
class CertResult:
    ok: bool = True
    schema_version: int = SCHEMA_VERSION
    checked_at: str = field(default_factory=now_iso)
    url: str = ""
    host: str = ""
    port: int = 443
    tls: dict[str, Any] = field(default_factory=dict)
    cert: dict[str, Any] = field(default_factory=dict)
    error_code: str = ""
    error_message: str = ""


def _cert_attr_utc(cert: Any, name_a: str, name_utc: str) -> datetime:
    """cryptography 41 → not_valid_after, 42+ → not_valid_after_utc. Shim."""
    if hasattr(cert, name_utc):
        val_utc: datetime = getattr(cert, name_utc)
        return val_utc
    val: datetime = getattr(cert, name_a)
    if val.tzinfo is None:
        return val.replace(tzinfo=UTC)
    return val


def check_cert(url: str, timeout: float = 15.0) -> CertResult:  # noqa: C901, PLR0912, PLR0915 — single linear flow, splitting hurts readability
    """Layer 2: TLS handshake + X.509 parse → CertResult.

    Always probes the TLS endpoint (port 443 by default) even if the
    monitored URL is http://. Hosts monitored over plain HTTP still typically
    serve TLS for end users.
    """
    res = CertResult(url=url)
    host, port = url_host(url, force_tls=True)
    if not host:
        return CertResult(
            ok=False,
            url=url,
            error_code="bad_url",
            error_message=f"cannot parse URL: {url!r}",
        )
    res.host, res.port = host, port

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from cryptography.x509.oid import (
            AuthorityInformationAccessOID,
            ExtensionOID,
            NameOID,
        )
    except ImportError as e:
        return CertResult(
            ok=False,
            url=url,
            host=host,
            port=port,
            error_code="missing_dependency",
            error_message=f"cryptography lib not importable: {e}",
        )

    ctx = ssl.create_default_context()
    t0 = time.monotonic()
    chain_status = "ok"
    chain: list[Any] = []
    leaf_der: bytes
    tls_version = ""
    cipher_name = ""
    alpn = None

    # Attempt 1 — strict verification. Captures most healthy cases.
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                handshake_ms = (time.monotonic() - t0) * 1000.0
                leaf_der = ss.getpeercert(binary_form=True) or b""
                tls_version = ss.version() or ""
                ci = ss.cipher()
                cipher_name = ci[0] if ci else ""
                alpn = ss.selected_alpn_protocol()
                # Chain (Python ≥3.10 private but stable enough)
                sslobj = ss._sslobj  # type: ignore[attr-defined]
                if hasattr(sslobj, "get_verified_chain"):
                    try:
                        chain = sslobj.get_verified_chain() or []
                    except Exception:
                        chain = []
    except ssl.SSLCertVerificationError as e:
        # Re-handshake without verification to still extract cert details for diagnostics
        chain_status = "untrusted"
        msg = str(e)[:200]
        try:
            ctx_no = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx_no.check_hostname = False
            ctx_no.verify_mode = ssl.CERT_NONE
            t0 = time.monotonic()
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx_no.wrap_socket(sock, server_hostname=host) as ss:
                    handshake_ms = (time.monotonic() - t0) * 1000.0
                    leaf_der = ss.getpeercert(binary_form=True) or b""
                    tls_version = ss.version() or ""
                    ci = ss.cipher()
                    cipher_name = ci[0] if ci else ""
                    alpn = ss.selected_alpn_protocol()
            res.error_message = msg
        except Exception as e2:
            return CertResult(
                ok=False,
                url=url,
                host=host,
                port=port,
                error_code="tls_error",
                error_message=f"verify failed and unverified retry failed: {e2}",
            )
    except socket.gaierror as e:
        return CertResult(
            ok=False,
            url=url,
            host=host,
            port=port,
            error_code="dns_error",
            error_message=str(e),
        )
    except TimeoutError:
        return CertResult(
            ok=False,
            url=url,
            host=host,
            port=port,
            error_code="tcp_timeout",
            error_message=f"timeout after {timeout}s",
        )
    except OSError as e:
        return CertResult(
            ok=False,
            url=url,
            host=host,
            port=port,
            error_code="tcp_error",
            error_message=str(e),
        )
    except ssl.SSLError as e:
        return CertResult(
            ok=False,
            url=url,
            host=host,
            port=port,
            error_code="tls_error",
            error_message=str(e),
        )

    # Parse leaf
    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
    except Exception as e:
        return CertResult(
            ok=False,
            url=url,
            host=host,
            port=port,
            error_code="cert_parse",
            error_message=str(e),
        )

    def _first(attrs: Any, oid: Any) -> Any:
        try:
            return attrs.get_attributes_for_oid(oid)[0].value
        except (IndexError, AttributeError):
            return None

    nb = _cert_attr_utc(leaf, "not_valid_before", "not_valid_before_utc")
    na = _cert_attr_utc(leaf, "not_valid_after", "not_valid_after_utc")
    dte = (na - datetime.now(UTC)).days

    sans: list[str] = []
    try:
        ext = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        # DNSName values are strs; IPAddress values are IPv4Address / IPv6Address.
        # Stringify both so callers (and the hostname-coverage check) treat them uniformly.
        sans = [str(n.value) for n in ext.value]  # type: ignore[attr-defined]
    except x509.ExtensionNotFound:
        pass

    ocsp_uri = ca_issuers_uri = None
    try:
        aia = leaf.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
        ).value
        for d in aia:  # type: ignore[attr-defined]
            if d.access_method == AuthorityInformationAccessOID.OCSP and ocsp_uri is None:
                ocsp_uri = d.access_location.value
            elif d.access_method == AuthorityInformationAccessOID.CA_ISSUERS and ca_issuers_uri is None:
                ca_issuers_uri = d.access_location.value
    except x509.ExtensionNotFound:
        pass

    pub = leaf.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pk_alg, pk_bits = "rsa", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pk_alg, pk_bits = "ecdsa", pub.curve.key_size
    else:
        pk_alg, pk_bits = type(pub).__name__.lower(), 0

    # Hostname coverage: SAN match or CN fallback
    subject_cn = _first(leaf.subject, NameOID.COMMON_NAME)
    hostname_covered = _hostname_covered(host, sans or ([subject_cn] if subject_cn else []))

    res.cert = {
        "subject_cn": subject_cn,
        "subject_dn": leaf.subject.rfc4514_string(),
        "issuer_cn": _first(leaf.issuer, NameOID.COMMON_NAME),
        "issuer_dn": leaf.issuer.rfc4514_string(),
        "issuer_org": _first(leaf.issuer, NameOID.ORGANIZATION_NAME),
        "serial": format(leaf.serial_number, "x").upper(),
        "not_before": nb.isoformat(),
        "not_after": na.isoformat(),
        "days_to_expire": dte,
        "sans": sans,
        "hostname_covered": hostname_covered,
        "signature_algorithm": leaf.signature_algorithm_oid._name,
        "public_key_algorithm": pk_alg,
        "public_key_bits": pk_bits,
        "fingerprint_sha256": leaf.fingerprint(hashes.SHA256()).hex().upper(),
        # SHA1 fingerprint is published as an *identifier*, not crypto — many
        # ops dashboards / certificate-store comparisons still index by it.
        "fingerprint_sha1": leaf.fingerprint(hashes.SHA1()).hex().upper(),  # noqa: S303
        "ocsp_uri": ocsp_uri,
        "ca_issuers_uri": ca_issuers_uri,
        "chain_status": chain_status,
        "chain_length": len(chain) or 1,
    }
    res.tls = {
        "protocol": tls_version,
        "cipher": cipher_name,
        "alpn": alpn,
        "forward_secrecy": _is_fs_cipher(cipher_name),
        "handshake_ms": round(handshake_ms, 1),
    }
    if res.error_message and not res.error_code:
        # Untrusted-but-parsed: we got cert metadata via an unverified
        # retry handshake, so dependent items have data — but the chain
        # didn't verify against the system trust store. We intentionally
        # leave res.ok=True (not False) so:
        #   - `web_check.cert.ok` stays 1 → "Cert check failing" does NOT
        #      fire (this isn't a script-level failure)
        #   - `cert.chain_status="untrusted"` is what fires the proper
        #      HIGH-severity "Cert chain untrusted" trigger
        # The error_code surfaces the condition in the master JSON for
        # dashboards / audit, without double-alerting.
        res.error_code = "cert_untrusted"
    return res


def _hostname_covered(host: str, names: list[str]) -> bool:
    """Wildcard-aware host vs SAN/CN matching."""
    host = host.lower()
    for n in names:
        if not n:
            continue
        n = n.lower()
        if n == host:
            return True
        if n.startswith("*."):
            tail = n[2:]
            # Wildcard matches only one label level
            if host.endswith("." + tail) and host.count(".") == tail.count(".") + 1:
                return True
    return False


def _is_fs_cipher(cipher: str) -> bool:
    """Cheap forward-secrecy heuristic from cipher name."""
    if not cipher:
        return False
    up = cipher.upper()
    return "ECDHE" in up or "DHE" in up or up.startswith("TLS_AES") or up.startswith("TLS_CHACHA20")


# =============================================================================
# Layer 5 — Deep TLS scan (daily): protocol matrix + weak-cipher probes
# =============================================================================

# Protocols flagged as weak. SSLv3 / TLSv1.0 / TLSv1.1 are well past EOL; even
# negotiating them is a finding. Modern OpenSSL builds may refuse them at
# SECLEVEL=0 — in that case `_try_protocol` returns ok=False, which we treat as
# "not supported (or our client can't probe it)". From a posture-monitoring POV
# this is acceptable: the bound is what a typical client could negotiate.
_TLS_WEAK_PROTOCOLS: frozenset[str] = frozenset({"SSLv3", "TLSv1", "TLSv1.0", "TLSv1.1"})

# Cipher families we explicitly probe for (one connection per family). Most are
# already gone in modern OpenSSL even with SECLEVEL=0; we still ask, and only
# *successful* negotiations are reported. The OpenSSL cipher-string keyword
# selects everything in that family.
_TLS_WEAK_CIPHER_FAMILIES: tuple[str, ...] = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "ADH", "AECDH", "PSK")


# Map protocol label → (min_version, max_version) for SSLContext. Built lazily
# because some symbols (TLSv1, TLSv1_1) may be removed from `ssl.TLSVersion` in
# future Python releases; we tolerate missing ones.
def _tls_protocol_matrix() -> list[tuple[str, ssl.TLSVersion]]:
    matrix: list[tuple[str, ssl.TLSVersion]] = []
    for label, attr in (("TLSv1", "TLSv1"), ("TLSv1.1", "TLSv1_1"), ("TLSv1.2", "TLSv1_2"), ("TLSv1.3", "TLSv1_3")):
        ver = getattr(ssl.TLSVersion, attr, None)
        if ver is not None:
            matrix.append((label, ver))
    return matrix


def _seclevel0(ctx: ssl.SSLContext) -> None:
    """Lower OpenSSL security level so legacy protocols/ciphers can negotiate."""
    with contextlib.suppress(ssl.SSLError):
        ctx.set_ciphers("ALL:@SECLEVEL=0")


def _try_protocol(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> tuple[bool, str]:
    """Attempt a handshake pinning min=max=version. Returns (ok, negotiated_cipher)."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version
        _seclevel0(ctx)
    except (ssl.SSLError, ValueError):
        return False, ""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                ci = ss.cipher()
                return True, (ci[0] if ci else "")
    except (ssl.SSLError, OSError, ValueError):
        return False, ""


def _try_weak_cipher_family(host: str, port: int, family: str, timeout: float) -> str | None:
    """Negotiate against a single weak cipher keyword. Returns the cipher
    name if the server accepted, else None.
    """
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Cap below TLS 1.3 — TLS 1.3 has a fixed cipher suite list that
        # never contains these legacy families, so probing it is wasted.
        with contextlib.suppress(ValueError):
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers(f"{family}:@SECLEVEL=0")
    except (ssl.SSLError, ValueError):
        return None
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                ci = ss.cipher()
                return ci[0] if ci else None
    except (ssl.SSLError, OSError, ValueError):
        return None


def run_tls_scan(url: str, *, timeout: float = 10.0) -> dict[str, Any]:
    """Layer 5: enumerate negotiable TLS protocols and weak cipher families.

    Like `check_cert`, always probes port 443 (or the URL's explicit https
    port) regardless of scheme — see `url_host(force_tls=True)`.
    """
    host, port = url_host(url, force_tls=True)
    if not host:
        return error_envelope("bad_url", f"cannot parse URL: {url!r}")

    supported: list[str] = []
    negotiated: dict[str, str] = {}
    weak: list[dict[str, str]] = []

    matrix = _tls_protocol_matrix()
    for label, ver in matrix:
        ok, cipher = _try_protocol(host, port, ver, timeout)
        if not ok:
            continue
        supported.append(label)
        if cipher:
            negotiated[label] = cipher
        if label in _TLS_WEAK_PROTOCOLS:
            weak.append({"category": "protocol", "name": label, "severity": "WARNING"})

    # Weak-cipher probes only make sense if TLS 1.2 or lower is even reachable.
    pre_tls13 = {p for p in supported if p != "TLSv1.3"}
    if pre_tls13:
        for fam in _TLS_WEAK_CIPHER_FAMILIES:
            weak_cipher = _try_weak_cipher_family(host, port, fam, timeout)
            if weak_cipher:
                weak.append({"category": "cipher", "name": weak_cipher, "severity": "WARNING"})

    if not supported:
        return error_envelope(
            "tls_error",
            f"no TLS protocol negotiable to {host}:{port}",
            url=url,
            host=host,
            port=port,
            supported_protocols=[],
            negotiated_ciphers={},
            weak_findings=[],
            weak_count=0,
        )

    return {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "checked_at": now_iso(),
        "url": url,
        "host": host,
        "port": port,
        "supported_protocols": supported,
        "negotiated_ciphers": negotiated,
        "weak_findings": weak,
        "weak_count": len(weak),
    }


def tls_scan_to_lld(scan: dict[str, Any]) -> list[dict[str, str]]:
    """Translate a tls-scan result into a Zabbix LLD array.

    LLD macros (per finding):
      {#TLS_FINDING}          — protocol label or cipher name
      {#TLS_FINDING.CATEGORY} — "protocol" | "cipher"
      {#TLS_FINDING.SEVERITY} — Zabbix severity label
    """
    findings = scan.get("weak_findings", []) or []
    return [
        {
            "{#TLS_FINDING}": str(f.get("name", "")),
            "{#TLS_FINDING.CATEGORY}": str(f.get("category", "")),
            "{#TLS_FINDING.SEVERITY}": str(f.get("severity", "WARNING")),
        }
        for f in findings
    ]


# =============================================================================
# Layer 6 — HTTP/3 (aioquic) — advertise + reachability + handshake metrics
# =============================================================================

# Two-step probe:
#   1. HEAD over TCP-TLS to read Alt-Svc. If h3 is not advertised, stop here
#      (return advertised=False, no false positive on hosts that don't serve
#      h3 — which is the common case for stock nginx).
#   2. QUIC handshake to UDP/port using aioquic + ALPN h3. Record handshake_ms,
#      negotiated ALPN, QUIC version.
#
# `cmd_http3` writes JSON to stdout exactly once and exits 0. aioquic + asyncio
# can emit `StreamWriter.__del__` "Exception ignored" and "Future exception was
# never retrieved" noise to stderr; Zabbix externalscripts capture both streams
# into the item value, so we install a custom event-loop exception handler and
# redirect any residual stderr writes to /dev/null inside `cmd_http3`.

ALT_SVC_H3_RE = re.compile(r"\bh3(?:-\d+)?\s*=", re.IGNORECASE)


def _alt_svc_advertises_h3(host: str, port: int, timeout: float) -> bool:
    """Open an HTTPS HEAD to / and check whether Alt-Svc lists h3."""
    import http.client

    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    try:
        conn.request("HEAD", "/", headers={"User-Agent": f"web_check/{__version__} (alt-svc-probe)"})
        resp = conn.getresponse()
        alt_svc = resp.getheader("alt-svc", "") or ""
    except (OSError, ssl.SSLError, http.client.HTTPException):
        return False
    finally:
        # Always close — protects against fd leak if request() raises
        # mid-handshake (refactor-safety: keeps the contract clean if this
        # function is ever called more than once per process).
        with contextlib.suppress(Exception):
            conn.close()
    return bool(ALT_SVC_H3_RE.search(alt_svc))


async def _quic_handshake(host: str, port: int, timeout: float) -> dict[str, Any]:
    """Open a QUIC connection with ALPN=h3. Return handshake metrics."""
    from aioquic.asyncio.client import connect
    from aioquic.h3.connection import H3_ALPN
    from aioquic.quic.configuration import QuicConfiguration

    cfg = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_REQUIRED)
    cfg.server_name = host
    t0 = time.monotonic()
    async with connect(host, port, configuration=cfg, wait_connected=True) as conn:
        dt_ms = (time.monotonic() - t0) * 1000.0
        tls = conn._quic.tls
        version_int = conn._quic._version  # noqa: SLF001 — stable enough across aioquic 1.x
        return {
            "h3_reachable": True,
            "handshake_ms": round(dt_ms, 1),
            "alpn": tls.alpn_negotiated,
            "quic_version": f"0x{version_int:08x}",
        }


def run_http3_check(url: str, *, timeout: float = 8.0) -> dict[str, Any]:
    """Layer 6 master probe. Always returns a dict; never raises."""
    host, port = url_host(url, force_tls=True)
    if not host:
        return error_envelope("bad_url", f"cannot parse URL: {url!r}")

    advertised = _alt_svc_advertises_h3(host, port, timeout)
    result: dict[str, Any] = {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "checked_at": now_iso(),
        "url": url,
        "host": host,
        "port": port,
        "alt_svc_advertised": advertised,
        "h3_reachable": False,
        "handshake_ms": 0.0,
        "alpn": None,
        "quic_version": None,
        "error_code": "",
        "error_message": "",
    }
    if not advertised:
        # No Alt-Svc h3 advertisement → skip the UDP probe entirely. Silent.
        return result

    # Run the QUIC handshake on a fresh, isolated event loop so we can install a
    # custom exception handler that suppresses aioquic's "Future exception was
    # never retrieved" / StreamWriter __del__ noise without disturbing the rest
    # of the script.
    loop = asyncio.new_event_loop()
    loop.set_exception_handler(lambda _loop, _ctx: None)
    try:
        h3 = loop.run_until_complete(asyncio.wait_for(_quic_handshake(host, port, timeout), timeout=timeout))
        result.update(h3)
    except TimeoutError:
        result["error_code"] = "h3_timeout"
        result["error_message"] = f"QUIC handshake timeout after {timeout}s"
    except (OSError, ConnectionError) as e:
        result["error_code"] = "h3_unreachable"
        result["error_message"] = str(e)[:300]
    except Exception as e:  # noqa: BLE001 — aioquic surfaces many internal errors
        result["error_code"] = "h3_error"
        result["error_message"] = f"{type(e).__name__}: {e}"[:300]
    finally:
        with contextlib.suppress(Exception):
            loop.close()
    return result


# =============================================================================
# Layer 3 — WHOIS (asyncwhois) with apex-deduped cache
# =============================================================================


def check_whois(
    url: str, *, cache: WhoisCache | None = None, ttl: int = WHOIS_CACHE_TTL, neg_ttl: int = WHOIS_NEGATIVE_TTL
) -> dict[str, Any]:
    """Layer 3: apex-deduped WHOIS via asyncwhois."""
    host, _ = url_host(url)
    if not host:
        return error_envelope("bad_url", f"cannot parse URL: {url!r}")
    try:
        apex = registered_apex(host)
    except ImportError as e:
        return error_envelope("missing_dependency", f"tldextract not importable: {e}", host=host)
    if not apex:
        return error_envelope("apex_unresolved", f"no PSL apex for {host!r}", host=host)

    cache = cache or WhoisCache()
    hit = cache.read(apex)
    if hit and hit.fresh():
        out = dict(hit.payload)
        out["cache_age_seconds"] = hit.age_seconds()
        return out

    # Cache miss → query upstream. flock to coalesce concurrent first-writers.
    with cache.lock(apex) as lk:
        if lk is None:
            # Someone else is querying. Best-effort: return stale cache or empty.
            if hit:
                out = dict(hit.payload)
                out["cache_age_seconds"] = hit.age_seconds()
                out["stale_due_to_lock"] = True
                return out
            return error_envelope("whois_locked", f"concurrent query in progress for apex {apex!r}", apex=apex)
        # Re-check cache inside the lock (another process may have just written).
        hit = cache.read(apex)
        if hit and hit.fresh():
            out = dict(hit.payload)
            out["cache_age_seconds"] = hit.age_seconds()
            return out

        result = _query_whois(apex)

    cache.write(apex, result, ttl if result.get("ok") and not result.get("provider_no_expiry") else neg_ttl)
    return result


def _query_whois(apex: str) -> dict[str, Any]:
    """One-shot WHOIS/RDAP via asyncwhois with retries and a wall-time cap.

    Zabbix kills externalscripts after their `Timeout` setting (typically
    3-30 s), so unbounded retries with multi-minute back-offs would just get
    SIGKILLed mid-sleep and we'd never write a negative-cache entry. Cap
    total wall-time to 10 s and skip the final post-failure sleep.
    """
    try:
        import asyncwhois
    except ImportError as e:
        return error_envelope("missing_dependency", f"asyncwhois not importable: {e}", apex=apex)

    tld = tld_of(apex)
    deadline = time.monotonic() + 10.0  # hard cap, total budget
    backoffs = [0.5, 1.5]  # only between retries; no sleep after last attempt
    raw: str = ""
    parsed: dict[str, Any] = {}
    last_err = ""
    for attempt in range(3):
        if time.monotonic() >= deadline:
            return error_envelope("whois_timeout", f"deadline exceeded after {attempt} attempts: {last_err}", apex=apex)
        try:
            raw, parsed = asyncwhois.whois(apex)
            break
        except Exception as e:  # noqa: BLE001 — asyncwhois surfaces a wide error variety
            last_err = f"{type(e).__name__}: {e}"
            if attempt < len(backoffs):
                # Only sleep if we have budget left AND another attempt remains
                remaining = deadline - time.monotonic()
                sleep_for = min(backoffs[attempt], max(0.0, remaining - 0.5))
                if sleep_for > 0:
                    time.sleep(sleep_for)
    else:
        return error_envelope("whois_unreachable", last_err, apex=apex)

    # Normalize: asyncwhois returns slightly different keys per registry/parser.
    norm = _normalize_whois(parsed or {}, raw or "", tld)
    norm.update(
        {
            "ok": True,
            "schema_version": SCHEMA_VERSION,
            "checked_at": now_iso(),
            "apex": apex,
            "cache_age_seconds": 0,
        }
    )
    return norm


def _normalize_whois(parsed: dict[str, Any], raw: str, tld: str) -> dict[str, Any]:  # noqa: C901 — flat dict shaping, not a real branchy function
    """Convert asyncwhois `parsed` (per-TLD shape) into our stable envelope."""

    def iso(v: Any) -> str | None:
        if isinstance(v, datetime):
            if v.tzinfo is None:
                v = v.replace(tzinfo=UTC)
            return v.astimezone(UTC).isoformat()
        if isinstance(v, str):
            return v
        return None

    expires = parsed.get("expires") or parsed.get("expiration_date")
    created = parsed.get("created") or parsed.get("creation_date")
    updated = parsed.get("updated") or parsed.get("last_updated")
    registrar = parsed.get("registrar") or None
    ns = parsed.get("name_servers") or []
    statuses = parsed.get("status") or []
    if isinstance(statuses, str):
        statuses = [statuses]
    if isinstance(ns, str):
        ns = [ns]
    dnssec = parsed.get("dnssec")
    dnssec_b = dnssec.lower() not in ("unsigned", "", "none", "no") if isinstance(dnssec, str) else bool(dnssec)

    # Augmenters for TLDs where asyncwhois parser has gaps.
    if expires is None and tld in TCI_TLDS:
        expires, created2, ns2 = _augment_tci_raw(raw)
        created = created or created2
        if not ns and ns2:
            ns = ns2

    no_expiry = tld in NO_EXPIRY_TLDS or (expires is None and not raw_has_expiry(raw))
    dte = None
    if expires:
        try:
            dt = expires if isinstance(expires, datetime) else datetime.fromisoformat(expires.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            dte = (dt - datetime.now(UTC)).days
        except Exception:
            dte = None

    return {
        "source": "asyncwhois",
        "registrar": registrar,
        "registrar_iana_id": parsed.get("registrar_iana_id"),
        "registered_at": iso(created),
        "last_updated": iso(updated),
        "expires_at": iso(expires),
        "days_to_expire": dte,
        "statuses": statuses,
        "name_servers": [n.rstrip(".").lower() for n in ns if n],
        "dnssec": dnssec_b,
        "abuse_email": parsed.get("registrar_abuse_email"),
        "provider_no_expiry": no_expiry,
    }


def raw_has_expiry(raw: str) -> bool:
    """Cheap check: does the raw text contain SOME expiry-ish keyword?"""
    if not raw:
        return False
    low = raw.lower()
    return any(k in low for k in ("paid-till", "expir", "renewal date", "validity"))


_RE_TCI_PAID_TILL = None
_RE_TCI_CREATED = None
_RE_TCI_NS = None


def _augment_tci_raw(raw: str) -> tuple[datetime | None, datetime | None, list[str]]:
    """Extract paid-till / created / nserver from a TCI port-43 response (.ru/.рф/.su).

    Format excerpt (.рф via whois.tcinet.ru):
        domain:        XN--80AAC7BMKKFG.XN--P1AI
        nserver:       ns1.reg.ru.
        nserver:       ns2.reg.ru.
        state:         REGISTERED, DELEGATED, UNVERIFIED
        registrar:     REGRU-RF
        created:       2013-07-19T08:16:15Z
        paid-till:     2026-07-19T09:16:15Z
    """
    global _RE_TCI_PAID_TILL, _RE_TCI_CREATED, _RE_TCI_NS
    import re

    if _RE_TCI_PAID_TILL is None:
        _RE_TCI_PAID_TILL = re.compile(r"^paid-till:\s*(\S+)", re.MULTILINE)
        _RE_TCI_CREATED = re.compile(r"^created:\s*(\S+)", re.MULTILINE)
        _RE_TCI_NS = re.compile(r"^nserver:\s*(\S+)", re.MULTILINE)

    def parse_dt(s: str) -> datetime | None:
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None

    paid_m = _RE_TCI_PAID_TILL.search(raw)
    created_m = _RE_TCI_CREATED.search(raw)
    ns_matches = _RE_TCI_NS.findall(raw)
    return (
        parse_dt(paid_m.group(1)) if paid_m else None,
        parse_dt(created_m.group(1)) if created_m else None,
        ns_matches,
    )


# =============================================================================
# Subcommand handlers
# =============================================================================


def cmd_cert(args: argparse.Namespace) -> None:
    res = check_cert(args.url, timeout=float(args.timeout))
    payload = asdict(res)
    # On failure paths the dataclass holds tls={} cert={} — flatten to error envelope
    if not payload["ok"]:
        emit(
            error_envelope(
                payload["error_code"] or "unknown",
                payload["error_message"] or "",
                url=payload["url"],
                host=payload["host"],
                port=payload["port"],
            )
        )
    emit(payload)


def cmd_whois(args: argparse.Namespace) -> None:
    out = check_whois(args.url, ttl=int(args.ttl), neg_ttl=int(args.neg_ttl))
    emit(out)


def cmd_tls_scan(args: argparse.Namespace) -> None:
    emit(run_tls_scan(args.url, timeout=float(args.timeout)))


def cmd_discover_tls(args: argparse.Namespace) -> None:
    # LLD output format: bare array, not wrapped in {"data": …} (Zabbix ≥4.2+).
    scan = run_tls_scan(args.url, timeout=float(args.timeout))
    emit(tls_scan_to_lld(scan))


def cmd_http3(args: argparse.Namespace) -> None:
    # aioquic + asyncio cleanup can write to stderr. Zabbix captures stderr
    # alongside stdout into the item value, so swallow any residual stderr
    # writes for the duration of the run. The script's only "real" output is
    # the single JSON line emitted by emit().
    with contextlib.redirect_stderr(open(os.devnull, "w")):  # noqa: SIM115 — short-lived, dies with the process
        emit(run_http3_check(args.url, timeout=float(args.timeout)))


def cmd_self_test(_: argparse.Namespace) -> None:
    """No-network smoke check. Verifies modules import and cache dir is usable."""
    findings: list[str] = []

    # Import critical deps
    for mod in ("cryptography", "asyncwhois", "tldextract", "aioquic"):
        try:
            __import__(mod)
        except ImportError as e:
            findings.append(f"import {mod}: FAIL ({e})")
        else:
            findings.append(f"import {mod}: ok")

    # PSL roundtrip
    try:
        apex = registered_apex("mail.itforprof.com")
    except ImportError:
        apex = None
    if apex == "itforprof.com":
        findings.append("psl apex resolution: ok")
    else:
        findings.append(f"psl apex resolution: FAIL (got {apex!r})")

    # Cache write/read
    import tempfile

    tmp_root = Path(tempfile.mkdtemp(prefix="web_check_selftest_"))
    try:
        cache = WhoisCache(root=tmp_root)
        cache.write("self.test", {"ok": True, "ping": "pong"}, ttl=30)
        hit = cache.read("self.test")
        ok = hit and hit.payload.get("ping") == "pong"
        findings.append(f"cache roundtrip: {'ok' if ok else 'FAIL'}")
    except Exception as e:  # noqa: BLE001 — self-test must not crash
        findings.append(f"cache roundtrip: FAIL ({e})")
    finally:
        # cleanup
        for p in tmp_root.iterdir() if tmp_root.is_dir() else []:
            with contextlib.suppress(OSError):
                p.unlink()
        with contextlib.suppress(OSError):
            tmp_root.rmdir()

    failed = any("FAIL" in f for f in findings)
    emit(
        {
            "ok": not failed,
            "schema_version": SCHEMA_VERSION,
            "checked_at": now_iso(),
            "version": __version__,
            "findings": findings,
        }
    )


# =============================================================================
# CLI plumbing
# =============================================================================


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="web_check",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("cert", help="TLS handshake + cert JSON (Layer 2)")
    pc.add_argument("url", help="Full URL, e.g. https://example.com")
    pc.add_argument("--timeout", default="15", help="Socket timeout in seconds (default 15)")
    pc.set_defaults(func=cmd_cert)

    pw = sub.add_parser("whois", help="Apex-deduped WHOIS JSON (Layer 3)")
    pw.add_argument("url", help="Full URL or bare hostname")
    pw.add_argument(
        "--ttl", default=str(WHOIS_CACHE_TTL), help=f"Positive-cache TTL in seconds (default {WHOIS_CACHE_TTL})"
    )
    pw.add_argument(
        "--neg-ttl",
        default=str(WHOIS_NEGATIVE_TTL),
        help=f"Negative-cache TTL in seconds (default {WHOIS_NEGATIVE_TTL})",
    )
    pw.set_defaults(func=cmd_whois)

    pts = sub.add_parser("tls-scan", help="Daily TLS protocol/cipher matrix (Layer 5)")
    pts.add_argument("url")
    pts.add_argument("--timeout", default="10", help="Per-handshake socket timeout in seconds (default 10)")
    pts.set_defaults(func=cmd_tls_scan)

    pds = sub.add_parser("discover-tls", help="LLD JSON for tls-scan findings")
    pds.add_argument("url")
    pds.add_argument("--timeout", default="10", help="Per-handshake socket timeout in seconds (default 10)")
    pds.set_defaults(func=cmd_discover_tls)

    p3 = sub.add_parser("http3", help="HTTP/3 advertise + QUIC handshake probe (Layer 6)")
    p3.add_argument("url")
    p3.add_argument("--timeout", default="8", help="Combined HEAD + QUIC timeout in seconds (default 8)")
    p3.set_defaults(func=cmd_http3)

    pst = sub.add_parser("self-test", help="Offline smoke check")
    pst.set_defaults(func=cmd_self_test)
    return p


def main(argv: list[str] | None = None) -> int:  # noqa: C901 — argparse dispatch + safety net
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001 — last-resort guard, must never crash the externalscript
        emit(error_envelope("internal_error", f"{type(e).__name__}: {e}"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
