#!/bin/sh
# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Konstantin Tyutyunnik <https://itforprof.com>
# install.sh — one-shot deploy for web_check.
#
# Usage (recommended pinned to a release tag):
#   curl -fsSL https://raw.githubusercontent.com/IT-for-Prof/zabbix-webservices/v2.0.0/scripts/deploy/install.sh | sudo sh
# or rolling-main:
#   curl -fsSL https://raw.githubusercontent.com/IT-for-Prof/zabbix-webservices/main/scripts/deploy/install.sh | sudo sh
#
# What this does:
#   1. Bootstraps `uv` (Astral) if absent.
#   2. uv-managed Python 3.12 in /opt/web_check/python/ (no dep on distro python).
#   3. venv in /opt/web_check/venv/, pinned deps from requirements.lock.
#   4. Drops web_check.py into the configured Zabbix ExternalScripts directory.
#   5. Creates /opt/web_check/data/cache/ (apex WHOIS cache).
#   6. Runs `web_check.py self-test` as a smoke check.
#
# Idempotent. Re-running upgrades to the latest release pinned in REF.
# Must be run as root (sudo).

set -eu

# ----- configurable -----
INSTALL_ROOT="${INSTALL_ROOT:-/opt/web_check}"
REPO_RAW="${REPO_RAW:-https://raw.githubusercontent.com/IT-for-Prof/zabbix-webservices}"
REF="${REF:-main}"                          # git ref: tag (v2.0.0), branch, or commit sha
PYTHON_VERSION="${PYTHON_VERSION:-3.12}"
ZBX_USER="${ZBX_USER:-zabbix}"
ZBX_GROUP="${ZBX_GROUP:-zabbix}"
# ------------------------

# ----- externalscripts detection helpers -----
detect_external_dir() {
    if [ "${EXTERNAL_DIR+x}" = x ] && [ -n "$EXTERNAL_DIR" ]; then
        printf '%s\t%s\n' "$EXTERNAL_DIR" "EXTERNAL_DIR"
        return 0
    fi

    config_paths=""
    if [ "${ZABBIX_CONF+x}" = x ] && [ -n "$ZABBIX_CONF" ]; then
        config_paths="$ZABBIX_CONF"
    fi
    config_paths="${config_paths}${config_paths:+
}/etc/zabbix/zabbix_server.conf
/etc/zabbix/zabbix_proxy.conf"

    for config_path in $config_paths; do
        if [ -r "$config_path" ]; then
            detected_dir="$(
                awk '
                    /^[[:space:]]*#/ { next }
                    /^[[:space:]]*ExternalScripts[[:space:]]*=/ {
                        sub(/^[^=]*=/, "")
                        gsub(/^[[:space:]]+|[[:space:]]+$/, "")
                        if ($0 != "") {
                            print
                            exit
                        }
                    }
                ' "$config_path"
            )"
            if [ -n "$detected_dir" ]; then
                printf '%s\t%s\n' "$detected_dir" "$config_path"
                return 0
            fi
            break
        fi
    done

    fallback_dirs="${EXTERNAL_FALLBACK_DIRS:-/usr/lib/zabbix/externalscripts
/usr/lib64/zabbix/externalscripts
/usr/share/zabbix/externalscripts
/usr/local/share/zabbix/externalscripts}"
    old_ifs="$IFS"
    IFS='
'
    for fallback_dir in $fallback_dirs; do
        [ -n "$fallback_dir" ] || continue
        if [ -d "$fallback_dir" ]; then
            IFS="$old_ifs"
            printf '%s\t%s\n' "$fallback_dir" "fallback"
            return 0
        fi
    done
    IFS="$old_ifs"

    echo "Could not determine Zabbix ExternalScripts directory." >&2
    echo "Set it explicitly and rerun, for example:" >&2
    echo "  EXTERNAL_DIR=/real/path sh install.sh" >&2
    return 2
}
# ----- end externalscripts detection helpers -----

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh must run as root (sudo)." >&2
    exit 2
fi

external_dir_detection="$(detect_external_dir)"
EXTERNAL_DIR="${external_dir_detection%%	*}"
EXTERNAL_DIR_SOURCE="${external_dir_detection#*	}"
echo "+ externalscripts: $EXTERNAL_DIR from $EXTERNAL_DIR_SOURCE"

if [ ! -d "$EXTERNAL_DIR" ]; then
    echo "Zabbix externalscripts directory not found at $EXTERNAL_DIR. Is Zabbix server/proxy installed?" >&2
    echo "Set the path explicitly with EXTERNAL_DIR=/real/path if needed." >&2
    exit 2
fi

URL_BASE="$REPO_RAW/$REF"

# 1. Bootstrap uv (single static binary). Idempotent — won't reinstall if already present.
if ! command -v uv >/dev/null 2>&1; then
    echo "+ installing uv (Astral)"
    curl -LsSf https://astral.sh/uv/install.sh | sh
fi
# uv installs into ~/.local/bin. Under sudo, $HOME is root's. Add it to PATH explicitly.
for d in /root/.local/bin "$HOME/.local/bin"; do
    [ -x "$d/uv" ] && export PATH="$d:$PATH"
done
echo "+ uv $(uv --version)"

# 2. uv-managed Python + venv (under our control, not the distro's)
export UV_PYTHON_INSTALL_DIR="$INSTALL_ROOT/python"
mkdir -p "$INSTALL_ROOT"
uv python install "$PYTHON_VERSION"
# --clear makes idempotent: existing venv (e.g. from an interrupted prior
# install) is replaced rather than aborting.
uv venv --clear --python "$PYTHON_VERSION" "$INSTALL_ROOT/venv"
echo "+ venv $("$INSTALL_ROOT"/venv/bin/python --version)"

# 3. Pinned deps. Use the host's uv but target the venv's python — `uv venv`
# creates the venv structure but does NOT install uv into it.
LOCK_TMP="$(mktemp)"
trap 'rm -f "$LOCK_TMP"' EXIT
curl -fsSL "$URL_BASE/scripts/deploy/requirements.lock" -o "$LOCK_TMP"
uv pip install --quiet --python "$INSTALL_ROOT/venv/bin/python" -r "$LOCK_TMP"
cp "$LOCK_TMP" "$INSTALL_ROOT/requirements.lock"   # for diagnostics later
echo "+ deps installed"

# 4. Script itself
curl -fsSL "$URL_BASE/scripts/externalscripts/web_check.py" -o "$EXTERNAL_DIR/web_check.py"
chown "$ZBX_USER:$ZBX_GROUP" "$EXTERNAL_DIR/web_check.py"
chmod 0750 "$EXTERNAL_DIR/web_check.py"
echo "+ web_check.py deployed to $EXTERNAL_DIR"

# 5. Cache directory
install -d -m 0750 -o "$ZBX_USER" -g "$ZBX_GROUP" "$INSTALL_ROOT/data/cache"

# 6. Smoke
echo "+ self-test"
"$EXTERNAL_DIR/web_check.py" self-test
echo "+ installed web_check $("$EXTERNAL_DIR"/web_check.py --version) [ref: $REF]"
