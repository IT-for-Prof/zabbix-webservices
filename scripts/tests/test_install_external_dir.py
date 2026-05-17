from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
INSTALL_SH = REPO_ROOT / "scripts" / "deploy" / "install.sh"


def _helper_source() -> str:
    text = INSTALL_SH.read_text(encoding="utf-8")
    start_marker = "# ----- externalscripts detection helpers -----"
    end_marker = "# ----- end externalscripts detection helpers -----"
    assert start_marker in text
    assert end_marker in text
    start = text.index(start_marker)
    end = text.index(end_marker, start) + len(end_marker)
    return text[start:end]


def _detect(tmp_path: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    script = tmp_path / "detect.sh"
    script.write_text(f"{_helper_source()}\ndetect_external_dir\n", encoding="utf-8")
    run_env = os.environ.copy()
    run_env.pop("EXTERNAL_DIR", None)
    run_env.pop("ZABBIX_CONF", None)
    run_env.pop("EXTERNAL_FALLBACK_DIRS", None)
    if env:
        run_env.update(env)
    return subprocess.run(["/bin/sh", str(script)], env=run_env, text=True, capture_output=True, check=False)


def test_external_dir_override_wins(tmp_path: Path) -> None:
    result = _detect(tmp_path, {"EXTERNAL_DIR": "/custom/externalscripts"})

    assert result.returncode == 0
    assert result.stdout == "/custom/externalscripts\tEXTERNAL_DIR\n"


def test_zabbix_conf_active_external_scripts_is_used(tmp_path: Path) -> None:
    config = tmp_path / "zabbix_server.conf"
    config.write_text(
        "\n".join(
            [
                "# ExternalScripts=/ignored",
                "LogFile=/var/log/zabbix/zabbix_server.log",
                "ExternalScripts=/usr/share/zabbix/externalscripts",
            ]
        ),
        encoding="utf-8",
    )

    result = _detect(tmp_path, {"ZABBIX_CONF": str(config)})

    assert result.returncode == 0
    assert result.stdout == f"/usr/share/zabbix/externalscripts\t{config}\n"


def test_commented_external_scripts_is_ignored_and_fallback_used(tmp_path: Path) -> None:
    config = tmp_path / "zabbix_server.conf"
    config.write_text("# ExternalScripts=/ignored\n", encoding="utf-8")
    fallback = tmp_path / "fallback"
    fallback.mkdir()

    result = _detect(tmp_path, {"ZABBIX_CONF": str(config), "EXTERNAL_FALLBACK_DIRS": str(fallback)})

    assert result.returncode == 0
    assert result.stdout == f"{fallback}\tfallback\n"


def test_missing_config_falls_back_to_first_existing_known_directory(tmp_path: Path) -> None:
    missing = tmp_path / "missing.conf"
    first = tmp_path / "first"
    second = tmp_path / "second"
    second.mkdir()

    result = _detect(
        tmp_path,
        {
            "ZABBIX_CONF": str(missing),
            "EXTERNAL_FALLBACK_DIRS": f"{first}\n{second}",
        },
    )

    assert result.returncode == 0
    assert result.stdout == f"{second}\tfallback\n"


def test_first_readable_config_without_external_scripts_stops_config_search(tmp_path: Path) -> None:
    server_config = tmp_path / "zabbix_server.conf"
    proxy_config = tmp_path / "zabbix_proxy.conf"
    fallback = tmp_path / "fallback"
    server_config.write_text("# ExternalScripts=/ignored\n", encoding="utf-8")
    proxy_config.write_text("ExternalScripts=/proxy/externalscripts\n", encoding="utf-8")
    fallback.mkdir()

    helper = _helper_source().replace(
        "/etc/zabbix/zabbix_server.conf\n/etc/zabbix/zabbix_proxy.conf",
        f"{server_config}\n{proxy_config}",
    )
    script = tmp_path / "detect.sh"
    script.write_text(f"{helper}\ndetect_external_dir\n", encoding="utf-8")
    run_env = os.environ.copy()
    run_env.pop("EXTERNAL_DIR", None)
    run_env.pop("ZABBIX_CONF", None)
    run_env["EXTERNAL_FALLBACK_DIRS"] = str(fallback)

    result = subprocess.run(["/bin/sh", str(script)], env=run_env, text=True, capture_output=True, check=False)

    assert result.returncode == 0
    assert result.stdout == f"{fallback}\tfallback\n"


def test_no_config_or_fallback_gives_helpful_failure(tmp_path: Path) -> None:
    result = _detect(
        tmp_path,
        {
            "ZABBIX_CONF": str(tmp_path / "missing.conf"),
            "EXTERNAL_FALLBACK_DIRS": str(tmp_path / "missing-fallback"),
        },
    )

    assert result.returncode == 2
    assert result.stdout == ""
    assert "Could not determine Zabbix ExternalScripts directory." in result.stderr
    assert "EXTERNAL_DIR=/real/path" in result.stderr
