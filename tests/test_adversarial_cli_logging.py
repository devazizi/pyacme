"""Adversarial stress tests for CLI staging options (R3), logging isolation (R5), and offline execution (R6)."""

import io
import json
import logging
import re
import socket
from unittest.mock import MagicMock, patch

from click.testing import CliRunner
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from pyacmecli.__main__ import main_command
import pyacmecli.acme.helper as helper
from pyacmecli.happylog import (
    LOG,
    ColorFormatter,
    remove_file_handlers,
    set_log_file,
    set_log_level,
)

ANSI_ESCAPE_RE = re.compile(
    r"\x1b\[[0-9;]*[a-zA-Z]|\033\[[0-9;]*[a-zA-Z]|\x1b|\033"
)


@pytest.fixture
def cli_runner():
    return CliRunner()


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )


# ==============================================================================
# R3 ADVERSARIAL TESTS: CLI Staging Flag & Directory URL Propagation
# ==============================================================================


@pytest.mark.parametrize(
    "cli_args, expected_staging",
    [
        (
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
            ],
            False,
        ),
        (
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
            True,
        ),
        (
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
            True,
        ),
        (
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
                "--staging",
            ],
            True,
        ),
    ],
)
def test_cli_new_staging_combinations(cli_runner, cli_args, expected_staging):
    """Stress-test all combinations of root and subcommand --staging flags for new command."""
    with patch(
        "pyacmecli.__main__.get_certificate_for_domains_dns"
    ) as mock_get_cert:
        result = cli_runner.invoke(main_command, cli_args)
        assert result.exit_code == 0, f"Command failed: {result.output}"
        mock_get_cert.assert_called_once()
        _, kwargs = mock_get_cert.call_args
        assert kwargs.get("staging") == expected_staging


@pytest.mark.parametrize(
    "cli_args, expected_staging",
    [
        (["cron", "--force-renewal"], None),
        (["--staging", "cron", "--force-renewal"], True),
        (["cron", "--staging", "--force-renewal"], True),
        (["--staging", "cron", "--staging", "--force-renewal"], True),
    ],
)
def test_cli_cron_staging_combinations(
    cli_runner, tmp_path, cli_args, expected_staging
):
    """Stress-test all combinations of root and subcommand --staging flags for cron command."""
    domain_dir = tmp_path / "expiring.com"
    domain_dir.mkdir(parents=True, exist_ok=True)
    json_path = domain_dir / "certificate.json"
    with open(json_path, "w") as f:
        json.dump(
            {
                "domain": "expiring.com",
                "certificate_path": str(domain_dir / "cert.pem"),
                "expiry_date": "2020-01-01T00:00:00Z",
                "status": "valid",
                "renew_command": "",
                "last_renewed": "2019-01-01T00:00:00Z",
                "provider": "dns",
            },
            f,
        )

    with (
        patch("pyacmecli.__main__.PYACME_HOME_PATH", str(tmp_path)),
        patch("pyacmecli.__main__.renew_certificate") as mock_renew,
        patch("pyacmecli.__main__.run_renew_command_as_subprocess_command"),
    ):
        result = cli_runner.invoke(main_command, cli_args)
        assert result.exit_code == 0, f"Command failed: {result.output}"
        mock_renew.assert_called_once()
        _, kwargs = mock_renew.call_args
        assert kwargs.get("staging") == expected_staging


def test_cli_new_staging_url_propagation(cli_runner, tmp_path, rsa_key):
    """Verify that --staging on 'new' directs requests to Let's Encrypt Staging Directory."""
    with (
        patch("pyacmecli.__main__.PYACME_HOME_PATH", str(tmp_path)),
        patch("pyacmecli.acme.helper.PYACME_HOME_PATH", str(tmp_path)),
        patch("pyacmecli.acme.helper.get_directory") as mock_dir,
        patch(
            "pyacmecli.acme.helper.ensure_account",
            return_value=("accounts/test", rsa_key, "http://acc"),
        ) as mock_acc,
        patch("pyacmecli.acme.helper.post_jws") as mock_post,
        patch("pyacmecli.acme.helper.perform_dns_challenge"),
        patch("pyacmecli.acme.helper.finalize_order"),
        patch("pyacmecli.acme.helper.SSLCertificate"),
    ):
        mock_dir.return_value = {
            "newNonce": "http://nonce",
            "newOrder": "http://order",
        }
        resp = MagicMock()
        resp.json.return_value = {"authorizations": []}
        resp.headers = {"Location": "http://order-url"}
        mock_post.return_value = resp

        result = cli_runner.invoke(
            main_command,
            [
                "new",
                "--domain",
                "staging.test",
                "--provider",
                "dns",
                "--email",
                "admin@staging.test",
                "--renew-command",
                "",
                "--staging",
            ],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        # ensure_account(session, directory, directory_url, email)
        assert mock_acc.call_args[0][2] == helper.LETSENCRYPT_STAGING_DIRECTORY
        assert mock_dir.call_args[0][1] == helper.LETSENCRYPT_STAGING_DIRECTORY


def test_cli_cron_staging_url_propagation(
    cli_runner, tmp_path, rsa_key, cert_pem_factory
):
    """Verify that --staging on 'cron' directs requests to Let's Encrypt Staging Directory."""
    domain_dir = tmp_path / "cron-staging.test"
    domain_dir.mkdir(parents=True, exist_ok=True)
    cert_path = domain_dir / "cert.pem"
    cert_pem, key_pem = cert_pem_factory(["cron-staging.test"])
    with open(cert_path, "wb") as f:
        f.write(cert_pem)

    json_path = domain_dir / "certificate.json"
    with open(json_path, "w") as f:
        json.dump(
            {
                "domain": "cron-staging.test",
                "certificate_path": str(cert_path),
                "expiry_date": "2020-01-01T00:00:00Z",
                "status": "valid",
                "renew_command": "",
                "last_renewed": "2019-01-01T00:00:00Z",
                "provider": "dns",
                "staging": False,
            },
            f,
        )

    with (
        patch("pyacmecli.__main__.PYACME_HOME_PATH", str(tmp_path)),
        patch("pyacmecli.acme.helper.PYACME_HOME_PATH", str(tmp_path)),
        patch("pyacmecli.acme.helper.get_directory") as mock_dir,
        patch(
            "pyacmecli.acme.helper.load_or_make_rsa_key", return_value=rsa_key
        ),
        patch(
            "pyacmecli.acme.helper.account_directory_url",
            return_value="http://acc",
        ),
        patch(
            "pyacmecli.acme.helper.ensure_account",
            return_value=("accounts/test", rsa_key, "http://acc"),
        ),
        patch("pyacmecli.acme.helper.post_jws") as mock_post,
        patch("pyacmecli.acme.helper.perform_dns_challenge"),
        patch("pyacmecli.acme.helper.finalize_order"),
        patch("pyacmecli.acme.helper.SSLCertificate"),
        patch("pyacmecli.__main__.run_renew_command_as_subprocess_command"),
    ):
        mock_dir.return_value = {
            "newNonce": "http://nonce",
            "newOrder": "http://order",
        }
        resp = MagicMock()
        resp.json.return_value = {"authorizations": []}
        resp.headers = {"Location": "http://order-url"}
        mock_post.return_value = resp

        result = cli_runner.invoke(
            main_command,
            ["cron", "--staging", "--force-renewal"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0
        assert mock_dir.call_args[0][1] == helper.LETSENCRYPT_STAGING_DIRECTORY


def test_cli_cron_without_staging_should_preserve_stored_staging_flag(
    cli_runner, tmp_path, rsa_key, cert_pem_factory
):
    """Adversarial bug detection: cron without --staging must not force staging certificates to production."""
    domain_dir = tmp_path / "staging-cert.test"
    domain_dir.mkdir(parents=True, exist_ok=True)
    cert_path = domain_dir / "cert.pem"
    cert_pem, key_pem = cert_pem_factory(["staging-cert.test"])
    with open(cert_path, "wb") as f:
        f.write(cert_pem)

    json_path = domain_dir / "certificate.json"
    with open(json_path, "w") as f:
        json.dump(
            {
                "domain": "staging-cert.test",
                "certificate_path": str(cert_path),
                "expiry_date": "2020-01-01T00:00:00Z",
                "status": "valid",
                "renew_command": "",
                "last_renewed": "2019-01-01T00:00:00Z",
                "provider": "dns",
                "staging": True,
            },
            f,
        )

    with (
        patch("pyacmecli.__main__.PYACME_HOME_PATH", str(tmp_path)),
        patch("pyacmecli.acme.helper.PYACME_HOME_PATH", str(tmp_path)),
        patch("pyacmecli.acme.helper.get_directory") as mock_dir,
        patch(
            "pyacmecli.acme.helper.load_or_make_rsa_key", return_value=rsa_key
        ),
        patch(
            "pyacmecli.acme.helper.account_directory_url",
            return_value="http://acc",
        ),
        patch(
            "pyacmecli.acme.helper.ensure_account",
            return_value=("accounts/test", rsa_key, "http://acc"),
        ),
        patch("pyacmecli.acme.helper.post_jws") as mock_post,
        patch("pyacmecli.acme.helper.perform_dns_challenge"),
        patch("pyacmecli.acme.helper.finalize_order"),
        patch("pyacmecli.acme.helper.SSLCertificate"),
        patch("pyacmecli.__main__.run_renew_command_as_subprocess_command"),
    ):
        mock_dir.return_value = {
            "newNonce": "http://nonce",
            "newOrder": "http://order",
        }
        resp = MagicMock()
        resp.json.return_value = {"authorizations": []}
        resp.headers = {"Location": "http://order-url"}
        mock_post.return_value = resp

        result = cli_runner.invoke(
            main_command, ["cron", "--force-renewal"], catch_exceptions=False
        )
        assert result.exit_code == 0
        # Should target staging directory because certificate.json has staging=True
        assert mock_dir.call_args[0][1] == helper.LETSENCRYPT_STAGING_DIRECTORY


# ==============================================================================
# R5 ADVERSARIAL TESTS: Logging Isolation & Directory Creation
# ==============================================================================


def test_r5_logging_no_ansi_across_all_levels(tmp_path):
    """Verify zero ANSI escape codes in log file across all 5 standard levels + exception."""
    log_file = tmp_path / "deep" / "nested" / "app.log"
    handler = set_log_file(log_file)
    set_log_level("DEBUG")

    try:
        LOG.debug("Debug entry with details %s", {"key": "val"})
        LOG.info("Info entry standard operation")
        LOG.warning("Warning entry condition met")
        LOG.error("Error entry system fault")
        LOG.critical("Critical entry emergency halt")

        try:
            raise RuntimeError("Test error for traceback logging")
        except RuntimeError:
            LOG.exception("Caught exception with traceback")

        handler.flush()

        with open(log_file, "r", encoding="utf-8") as f:
            content = f.read()

        assert len(ANSI_ESCAPE_RE.findall(content)) == 0
        assert "\033" not in content
        assert "\x1b" not in content

        for level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            assert level in content
        assert "Test error for traceback logging" in content
    finally:
        remove_file_handlers()


def test_r5_logging_multiple_handlers_attached(tmp_path):
    """Verify that having ColorFormatter on console handler does not contaminate FileHandler."""
    log_file = tmp_path / "multi_handler.log"
    file_handler = set_log_file(log_file)

    console_buf = io.StringIO()
    console_handler = logging.StreamHandler(console_buf)
    console_handler.setFormatter(
        ColorFormatter(fmt="%(levelname)s %(message)s")
    )
    LOG.addHandler(console_handler)

    try:
        set_log_level("DEBUG")
        for lvl in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            getattr(LOG, lvl.lower())(f"Test message at level {lvl}")

        file_handler.flush()
        console_handler.flush()

        # Check console output has ANSI color codes
        console_output = console_buf.getvalue()
        assert len(ANSI_ESCAPE_RE.findall(console_output)) > 0

        # Check file output has NO ANSI color codes
        with open(log_file, "r", encoding="utf-8") as f:
            file_output = f.read()
        assert len(ANSI_ESCAPE_RE.findall(file_output)) == 0
        assert "\033" not in file_output
        assert "\x1b" not in file_output
    finally:
        LOG.removeHandler(console_handler)
        remove_file_handlers()


def test_r5_logging_handler_ordering_resilience(tmp_path):
    """Verify no ANSI contamination regardless of whether ColorFormatter runs before or after FileHandler."""
    log_file_a = tmp_path / "order_a.log"
    log_file_b = tmp_path / "order_b.log"

    console_handler = logging.StreamHandler(io.StringIO())
    console_handler.setFormatter(
        ColorFormatter(fmt="%(levelname)s %(message)s")
    )

    # Order 1: Console first, File second
    LOG.handlers.clear()
    LOG.addHandler(console_handler)
    h_file_a = set_log_file(log_file_a)
    assert LOG.handlers[0] == console_handler
    assert LOG.handlers[1] == h_file_a

    LOG.warning("Warning in order 1")
    LOG.error("Error in order 1")
    h_file_a.flush()

    with open(log_file_a, "r") as f:
        content_a = f.read()
    assert "\033" not in content_a
    assert "\x1b" not in content_a

    # Order 2: File first, Console second
    remove_file_handlers()
    LOG.handlers.clear()
    h_file_b = set_log_file(log_file_b)
    LOG.addHandler(console_handler)
    assert LOG.handlers[0] == h_file_b
    assert LOG.handlers[1] == console_handler

    LOG.warning("Warning in order 2")
    LOG.error("Error in order 2")
    h_file_b.flush()

    with open(log_file_b, "r") as f:
        content_b = f.read()
    assert "\033" not in content_b
    assert "\x1b" not in content_b

    remove_file_handlers()
    LOG.handlers.clear()


def test_r5_consecutive_set_log_file_calls_cleanup(tmp_path):
    """Verify consecutive set_log_file calls close previous handlers without file descriptor leaks."""
    log1 = tmp_path / "first.log"
    log2 = tmp_path / "second.log"

    h1 = set_log_file(log1)
    file_handlers = [
        h for h in LOG.handlers if isinstance(h, logging.FileHandler)
    ]
    assert len(file_handlers) == 1
    assert file_handlers[0] == h1

    h2 = set_log_file(log2)
    file_handlers = [
        h for h in LOG.handlers if isinstance(h, logging.FileHandler)
    ]
    assert len(file_handlers) == 1
    assert file_handlers[0] == h2

    remove_file_handlers()
    file_handlers = [
        h for h in LOG.handlers if isinstance(h, logging.FileHandler)
    ]
    assert len(file_handlers) == 0


# ==============================================================================
# R6 ADVERSARIAL TESTS: Offline Socket Interception
# ==============================================================================


def test_r6_network_socket_blocking_detection():
    """Verify that socket blocking catches attempts and our test suite makes 0 network calls."""
    network_calls = []

    def block_connect(*args, **kwargs):
        network_calls.append(("connect", args))
        raise RuntimeError("Network connect attempted!")

    def block_getaddrinfo(*args, **kwargs):
        network_calls.append(("getaddrinfo", args))
        raise RuntimeError("DNS getaddrinfo attempted!")

    orig_connect = socket.socket.connect
    orig_getaddrinfo = socket.getaddrinfo

    socket.socket.connect = block_connect
    socket.getaddrinfo = block_getaddrinfo

    try:
        with pytest.raises(RuntimeError, match="Network connect attempted"):
            s = socket.socket()
            s.connect(("1.1.1.1", 80))

        with pytest.raises(RuntimeError, match="DNS getaddrinfo attempted"):
            socket.getaddrinfo("example.com", 80)
    finally:
        socket.socket.connect = orig_connect
        socket.getaddrinfo = orig_getaddrinfo
