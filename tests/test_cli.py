"""Tests for Click CLI commands, staging flags, and log file options in pyacmecli.__main__."""

import json
import os
import subprocess
from unittest.mock import patch

from click.testing import CliRunner
import pytest

from pyacmecli.__main__ import (
    main_command,
    run_renew_command_as_subprocess_command,
)


@pytest.fixture
def runner():
    return CliRunner()


def test_cli_help_options(runner):
    """Verify --staging and --log-file are present in help texts."""
    result = runner.invoke(main_command, ["--help"])
    assert result.exit_code == 0
    assert "--staging" in result.output
    assert "--log-file" in result.output

    new_help = runner.invoke(main_command, ["new", "--help"])
    assert new_help.exit_code == 0
    assert "--staging" in new_help.output
    assert "--log-file" in new_help.output

    cron_help = runner.invoke(main_command, ["cron", "--help"])
    assert cron_help.exit_code == 0
    assert "--staging" in cron_help.output
    assert "--log-file" in cron_help.output


def test_cli_new_staging_subcommand_flag(runner, temp_pyacme_home):
    """Verify pyacme new --staging passes staging=True to helper."""
    with patch(
        "pyacmecli.__main__.get_certificate_for_domains_dns"
    ) as mock_get_cert:
        result = runner.invoke(
            main_command,
            [
                "new",
                "--domain",
                "example.com",
                "--provider",
                "dns",
                "--email",
                "admin@example.com",
                "--renew-command",
                "",
                "--staging",
            ],
        )
        assert result.exit_code == 0
        mock_get_cert.assert_called_once()
        _, kwargs = mock_get_cert.call_args
        assert kwargs.get("staging") is True


def test_cli_new_staging_root_flag(runner, temp_pyacme_home):
    """Verify pyacme --staging new passes staging=True to helper via context."""
    with patch(
        "pyacmecli.__main__.get_certificate_for_domains_dns"
    ) as mock_get_cert:
        result = runner.invoke(
            main_command,
            [
                "--staging",
                "new",
                "--domain",
                "example.com",
                "--provider",
                "dns",
                "--email",
                "admin@example.com",
                "--renew-command",
                "",
            ],
        )
        assert result.exit_code == 0
        mock_get_cert.assert_called_once()
        _, kwargs = mock_get_cert.call_args
        assert kwargs.get("staging") is True


def test_cli_cron_staging_flag(runner, temp_pyacme_home):
    """Verify pyacme cron --staging passes staging=True to renew_certificate."""
    # Create an expiring certificate
    domain_dir = os.path.join(temp_pyacme_home, "expiring.com")
    os.makedirs(domain_dir, exist_ok=True)
    json_path = os.path.join(domain_dir, "certificate.json")
    with open(json_path, "w") as f:
        json.dump(
            {
                "domain": "expiring.com",
                "certificate_path": os.path.join(domain_dir, "cert.pem"),
                "expiry_date": "2026-01-01T00:00:00Z",
                "status": "valid",
                "renew_command": "",
                "last_renewed": "2025-01-01T00:00:00Z",
            },
            f,
        )

    with (
        patch("pyacmecli.__main__.renew_certificate") as mock_renew,
        patch("pyacmecli.__main__.run_renew_command_as_subprocess_command"),
    ):
        result = runner.invoke(
            main_command, ["cron", "--staging", "--force-renewal"]
        )
        assert result.exit_code == 0
        mock_renew.assert_called_once()
        assert mock_renew.call_args[1].get("staging") is True


def test_cli_cron_default_staging_is_none(runner, temp_pyacme_home):
    """Verify running pyacme cron --force-renewal without --staging passes staging=None to renew_certificate."""
    domain_dir = os.path.join(temp_pyacme_home, "expiring.com")
    os.makedirs(domain_dir, exist_ok=True)
    json_path = os.path.join(domain_dir, "certificate.json")
    with open(json_path, "w") as f:
        json.dump(
            {
                "domain": "expiring.com",
                "certificate_path": os.path.join(domain_dir, "cert.pem"),
                "expiry_date": "2026-01-01T00:00:00Z",
                "status": "valid",
                "renew_command": "",
                "last_renewed": "2025-01-01T00:00:00Z",
            },
            f,
        )

    with (
        patch("pyacmecli.__main__.renew_certificate") as mock_renew,
        patch("pyacmecli.__main__.run_renew_command_as_subprocess_command"),
    ):
        result = runner.invoke(main_command, ["cron", "--force-renewal"])
        assert result.exit_code == 0
        mock_renew.assert_called_once()
        assert mock_renew.call_args[1].get("staging") is None


def test_cli_cron_root_staging_flag(runner, temp_pyacme_home):
    """Verify running pyacme --staging cron --force-renewal passes staging=True to renew_certificate."""
    domain_dir = os.path.join(temp_pyacme_home, "expiring.com")
    os.makedirs(domain_dir, exist_ok=True)
    json_path = os.path.join(domain_dir, "certificate.json")
    with open(json_path, "w") as f:
        json.dump(
            {
                "domain": "expiring.com",
                "certificate_path": os.path.join(domain_dir, "cert.pem"),
                "expiry_date": "2026-01-01T00:00:00Z",
                "status": "valid",
                "renew_command": "",
                "last_renewed": "2025-01-01T00:00:00Z",
            },
            f,
        )

    with (
        patch("pyacmecli.__main__.renew_certificate") as mock_renew,
        patch("pyacmecli.__main__.run_renew_command_as_subprocess_command"),
    ):
        result = runner.invoke(
            main_command, ["--staging", "cron", "--force-renewal"]
        )
        assert result.exit_code == 0
        mock_renew.assert_called_once()
        assert mock_renew.call_args[1].get("staging") is True


def test_cli_log_file_option(runner, tmp_path, temp_pyacme_home):
    """Verify --log-file configures file logging and writes entries."""
    log_file = tmp_path / "sub" / "pyacme.log"
    result = runner.invoke(main_command, ["--log-file", str(log_file), "init"])
    assert result.exit_code == 0
    assert os.path.exists(str(log_file))
    with open(str(log_file), "r", encoding="utf-8") as f:
        content = f.read()
    # Should not have ANSI escapes
    assert "\033" not in content
    assert "\x1b" not in content


def test_cli_new_validation_errors(runner):
    """Verify validation for invalid providers and missing access tokens."""
    # Invalid provider
    res = runner.invoke(
        main_command,
        [
            "new",
            "--domain",
            "example.com",
            "--provider",
            "unsupported_provider",
            "--email",
            "admin@example.com",
            "--renew-command",
            "",
        ],
    )
    assert res.exit_code != 0
    assert "Invalid provider" in res.output

    # ArvanCloud without token
    res = runner.invoke(
        main_command,
        [
            "new",
            "--domain",
            "example.com",
            "--provider",
            "arvancloud",
            "--email",
            "admin@example.com",
            "--renew-command",
            "",
        ],
    )
    assert res.exit_code != 0
    assert "--access-token required" in res.output

    # Cloudflare without token
    res = runner.invoke(
        main_command,
        [
            "new",
            "--domain",
            "example.com",
            "--provider",
            "cloudflare",
            "--email",
            "admin@example.com",
            "--renew-command",
            "",
        ],
    )
    assert res.exit_code != 0
    assert "--access-token required" in res.output


def test_cli_init_and_list_command(runner, temp_pyacme_home):
    """Verify init creates directory and list outputs fancy table."""
    init_res = runner.invoke(main_command, ["init"])
    assert init_res.exit_code == 0
    assert os.path.exists(temp_pyacme_home)

    list_res = runner.invoke(main_command, ["list"])
    assert list_res.exit_code == 0
    assert "Domain" in list_res.output
    assert "Status" in list_res.output


def test_run_renew_command_as_subprocess_command():
    """Verify subprocess execution and error resilience."""
    with patch("subprocess.run") as mock_sub:
        run_renew_command_as_subprocess_command(
            "echo hello", env={"PYACME_DOMAIN": "example.com"}
        )
        mock_sub.assert_called_once()
        args, kwargs = mock_sub.call_args
        # Compare only chosen keys: a failing assert_called_with would print
        # the whole inherited environment, secrets included.
        env = kwargs.pop("env")
        assert args == ("echo hello",)
        assert kwargs == {
            "shell": True,
            "check": True,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "timeout": 600,
        }
        assert env["PYACME_DOMAIN"] == "example.com"
        assert "PATH" in env

    # Verify exception is caught and logged
    with patch(
        "subprocess.run",
        side_effect=subprocess.CalledProcessError(
            1, "bad cmd", stderr="Some error"
        ),
    ):
        # Should not raise
        run_renew_command_as_subprocess_command("bad cmd")
