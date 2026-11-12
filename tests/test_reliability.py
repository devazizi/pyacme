"""Tests for bounded ACME polling and cron failure isolation."""

import json
import os
import subprocess
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from pyacmecli.__main__ import (
    main_command,
    run_renew_command_as_subprocess_command,
)
from pyacmecli.acme import helper


def _authz(status, error=None):
    challenge = {"type": "dns-01", "token": "tok", "url": "https://ca/chal"}
    if error:
        challenge["error"] = error
    resp = MagicMock()
    resp.json.return_value = {
        "status": status,
        "identifier": {"type": "dns", "value": "example.com"},
        "challenges": [challenge],
    }
    return resp


def _run_challenge(responses):
    session = MagicMock()
    session.get.side_effect = responses
    with (
        patch.object(
            helper, "dns_challenge_provider", return_value=MagicMock()
        ),
        patch.object(helper, "wait_for_dns"),
        patch.object(helper, "post_jws"),
    ):
        helper.perform_dns_challenge(
            session,
            privkey=MagicMock(),
            account_url="https://ca/acct/1",
            new_nonce_url="https://ca/nonce",
            authz_url="https://ca/authz/1",
            jwk={"e": "AQAB", "kty": "RSA", "n": "abc"},
            provider_name="cloudflare",
            access_token="dummy",
        )
    return session


def test_challenge_returns_when_authorization_becomes_valid(mock_sleep):
    session = _run_challenge(
        [_authz("pending"), _authz("pending"), _authz("valid")]
    )
    assert session.get.call_count == 3


def test_challenge_raises_on_invalid_authorization(mock_sleep):
    error = {"type": "urn:ietf:params:acme:error:unauthorized"}
    with pytest.raises(RuntimeError, match="is invalid") as excinfo:
        _run_challenge([_authz("pending"), _authz("invalid", error=error)])
    assert "unauthorized" in str(excinfo.value)


def test_challenge_times_out_when_authorization_stays_pending(
    mock_sleep, monkeypatch
):
    monkeypatch.setattr(helper, "ACME_POLL_ATTEMPTS", 3)
    with pytest.raises(TimeoutError, match="still 'pending'"):
        _run_challenge([_authz("pending")] * 4)


def test_finalize_times_out_when_order_stays_processing(
    mock_sleep, monkeypatch, temp_pyacme_home, session_rsa_key
):
    monkeypatch.setattr(helper, "ACME_POLL_ATTEMPTS", 3)
    resp = MagicMock()
    resp.json.return_value = {"status": "processing"}
    session = MagicMock()
    with (
        patch.object(helper, "post_jws", return_value=resp),
        patch.object(
            helper, "load_or_make_rsa_key", return_value=session_rsa_key
        ),
        pytest.raises(TimeoutError, match="still 'processing'"),
    ):
        helper.finalize_order(
            session,
            session_rsa_key,
            "https://ca/acct/1",
            "https://ca/nonce",
            {"finalize": "https://ca/finalize/1"},
            ["example.com"],
            "https://ca/order/1",
        )
    session.get.assert_not_called()


def _write_cert(home, domain):
    domain_dir = os.path.join(home, domain)
    os.makedirs(domain_dir, exist_ok=True)
    with open(os.path.join(domain_dir, "certificate.json"), "w") as f:
        json.dump(
            {
                "domain": domain,
                "certificate_path": os.path.join(domain_dir, "cert.pem"),
                "expiry_date": "2020-01-01T00:00:00Z",
                "status": "valid",
                "renew_command": "reload",
                "last_renewed": "2019-10-01T00:00:00Z",
            },
            f,
        )


def test_cron_continues_after_failure_and_exits_non_zero(temp_pyacme_home):
    for domain in ("a.example.com", "b.example.com", "c.example.com"):
        _write_cert(temp_pyacme_home, domain)

    def renew(cert_json_path, staging=None):
        if "b.example.com" in cert_json_path:
            raise RuntimeError("boom")

    with (
        patch("pyacmecli.__main__.renew_certificate", side_effect=renew) as r,
        patch(
            "pyacmecli.__main__.run_renew_command_as_subprocess_command",
            return_value=True,
        ) as hook,
    ):
        result = CliRunner().invoke(main_command, ["cron"])

    assert r.call_count == 3
    assert hook.call_count == 2  # not run for the failed certificate
    assert result.exit_code != 0
    assert "1 of 3 certificate(s) failed: b.example.com" in result.output


def test_cron_reports_failed_renew_command(temp_pyacme_home):
    _write_cert(temp_pyacme_home, "a.example.com")
    with (
        patch("pyacmecli.__main__.renew_certificate"),
        patch(
            "pyacmecli.__main__.run_renew_command_as_subprocess_command",
            return_value=False,
        ),
    ):
        result = CliRunner().invoke(main_command, ["cron"])
    assert result.exit_code != 0
    assert "a.example.com (renew command)" in result.output


def test_renew_command_return_value():
    assert run_renew_command_as_subprocess_command("") is True
    with patch("subprocess.run"):
        assert run_renew_command_as_subprocess_command("true") is True
    with patch(
        "subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "x", stderr="err"),
    ):
        assert run_renew_command_as_subprocess_command("x") is False
