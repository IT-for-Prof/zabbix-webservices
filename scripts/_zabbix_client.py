# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Konstantin Tyutyunnik <https://itforprof.com>
"""Shared Zabbix JSON-RPC client and .env loader for migration scripts.

Internal module (leading underscore) — used by sibling CLI scripts only.
"""

import json
import os
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse


def load_env():
    """Read scripts/.env (if present) and return (ZABBIX_URL, ZABBIX_TOKEN).

    The URL is restricted to http/https — ruff S310 (and bandit) flag
    urllib.request.urlopen on arbitrary schemes; validating here makes the
    `urlopen` calls in Zabbix.call safe in practice.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    envfile = os.path.join(here, ".env")
    if os.path.exists(envfile):
        with open(envfile) as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                os.environ.setdefault(k, v.strip())
    url = os.environ.get("ZABBIX_URL")
    token = os.environ.get("ZABBIX_TOKEN")
    if not url or not token:
        sys.exit("ERROR: set ZABBIX_URL and ZABBIX_TOKEN in env or scripts/.env")
    if urlparse(url).scheme not in ("http", "https"):
        sys.exit(f"ERROR: ZABBIX_URL must be http(s), got: {url}")
    return url, token


class Zabbix:
    """Minimal Zabbix 7.0 JSON-RPC client (bearer-token auth)."""

    def __init__(self, url, token):
        self.url = url
        self.token = token

    def call(self, method, params=None):
        body = json.dumps({"jsonrpc": "2.0", "method": method, "params": params or {}, "id": 1}).encode()
        req = urllib.request.Request(  # noqa: S310 — scheme validated in load_env
            self.url,
            data=body,
            headers={
                "Content-Type": "application/json-rpc",
                "Authorization": f"Bearer {self.token}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                r = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            sys.exit(f"HTTP {e.code} on {method}: {e.read().decode()[:200]}")
        if "error" in r:
            raise RuntimeError(f"{method} failed: {r['error']}")
        return r["result"]
