# Scripts

| Script | Purpose | Idempotent | Has `--dry-run` |
|--------|---------|:---:|:---:|
| [`externalscripts/web_check.py`](externalscripts/web_check.py) | Externalscript for cert / WHOIS / TLS-scan / discover-tls / HTTP3 / self-test. Single-file, deployed to the configured Zabbix `ExternalScripts` directory via [`deploy/install.sh`](deploy/install.sh). Always emits valid JSON, exits 0; errors encoded as `{"ok": false, "error_code": …}`. | ✓ | n/a |
| [`_zabbix_client.py`](_zabbix_client.py) | API token auth and env loading. Imported by `sync-domain-registry-owners.py`. | — | — |

| [`sync-domain-registry-owners.py`](sync-domain-registry-owners.py) | Enable WHOIS on one owner per registered domain; rerun after Full template imports. Runs on the administration node. | ✓ | ✓ (default; `--apply` to write) |

## Deploy `web_check.py` to a monitor node

One-liner (run on each Zabbix server/proxy that monitors hosts using the template):

```
curl -fsSL https://raw.githubusercontent.com/IT-for-Prof/zabbix-webservices/main/scripts/deploy/install.sh | sudo sh
```

Installs a Python 3.12 venv at `/opt/web_check/venv` (uv-managed, pinned via
[`deploy/requirements.lock`](deploy/requirements.lock); host Python untouched)
and drops the script into the configured Zabbix `ExternalScripts` directory
owned `zabbix:zabbix`, mode `0750`. Use
`ZABBIX_CONF=/custom/zabbix_server.conf` for a non-standard config path, or
override with `EXTERNAL_DIR=/real/path` if auto-detection cannot find the right
directory.

Smoke test: `sudo -u zabbix /path/from/ExternalScripts/web_check.py self-test`.

## Configuration (for the WHOIS owner sync)

Reads Zabbix API credentials from environment (or a `.env` file here, see
[`.env.example`](.env.example)):

```
ZABBIX_URL=https://mon.itforprof.com/api_jsonrpc.php
ZABBIX_TOKEN=<API token with read+write on hosts and templates>
```

## Tests

`pytest -q` from this directory. Tests cover cert (`trustme` fixtures),
WHOIS normalisation, cache stampede + atomic write, apex extraction, TLS
scan (mocked weak ciphers), and CLI plumbing. Lint/typecheck via
[`pyproject.toml`](pyproject.toml).
