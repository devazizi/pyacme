"""Shared ACME account and provider credential handling."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from pyacmecli.__main__ import main_command
from pyacmecli.acme import helper


def _issue(domains, cert_pem_factory, fake_acme, **kwargs):
    cert_pem, _ = cert_pem_factory(domains)
    fake = fake_acme(cert_pem)
    with (
        patch.object(
            helper, "dns_challenge_provider", return_value=MagicMock()
        ),
        patch.object(helper, "wait_for_dns"),
    ):
        helper.get_certificate_for_domains_dns(
            domains, "cloudflare", "a@example.com", "cf-token", "true", **kwargs
        )
    return fake


def _meta(home, domain):
    with open(os.path.join(home, domain, "certificate.json")) as f:
        return json.load(f)


def test_certificates_share_one_account_per_ca(
    temp_pyacme_home, cert_pem_factory, fake_acme, mock_sleep
):
    first = _issue(["a.example.com"], cert_pem_factory, fake_acme)
    second = _issue(["b.example.com"], cert_pem_factory, fake_acme)

    assert len(first.payloads("/new-account")) == 1
    assert second.payloads("/new-account") == []
    for domain in ("a.example.com", "b.example.com"):
        assert _meta(temp_pyacme_home, domain)["account"] == (
            "accounts/acme.test_directory"
        )
        assert not os.path.exists(
            os.path.join(temp_pyacme_home, domain, "account.key.pem")
        )


def test_renewal_without_legacy_account_uses_shared_account(
    temp_pyacme_home, cert_pem_factory, fake_acme, mock_sleep
):
    _issue(["a.example.com"], cert_pem_factory, fake_acme)
    json_path = os.path.join(
        temp_pyacme_home, "a.example.com", "certificate.json"
    )
    meta = _meta(temp_pyacme_home, "a.example.com")
    del meta["account"]  # as written by an older version
    with open(json_path, "w") as f:
        json.dump(meta, f)

    cert_pem, _ = cert_pem_factory(["a.example.com"])
    fake = fake_acme(cert_pem)
    with (
        patch.object(
            helper, "dns_challenge_provider", return_value=MagicMock()
        ),
        patch.object(helper, "wait_for_dns"),
    ):
        helper.renew_certificate(json_path)

    # The shared account already exists on disk, so nothing is registered.
    assert fake.payloads("/new-account") == []
    assert _meta(temp_pyacme_home, "a.example.com")["account"] == (
        "accounts/acme.test_directory"
    )


@pytest.mark.parametrize(
    "bad", ["accounts/..", "../x", "accounts/a/b", "/etc", "accounts/."]
)
def test_tampered_account_reference_is_rejected(bad):
    with pytest.raises(RuntimeError, match="Invalid account reference"):
        helper.resolve_account_dir({"account": bad}, "example.com")


def test_token_from_environment_overrides_stored(monkeypatch):
    monkeypatch.setenv("PYACME_CLOUDFLARE_TOKEN", "rotated")
    assert helper.resolve_access_token("cloudflare", "stale") == "rotated"


def test_missing_required_token_names_the_variable(monkeypatch):
    monkeypatch.delenv("PYACME_CLOUDFLARE_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="PYACME_CLOUDFLARE_TOKEN"):
        helper.resolve_access_token("cloudflare", None)
    assert helper.resolve_access_token("route53", None) is None


def test_no_store_token_keeps_credential_out_of_metadata(
    temp_pyacme_home, cert_pem_factory, fake_acme, mock_sleep
):
    _issue(["a.example.com"], cert_pem_factory, fake_acme, store_token=False)
    assert _meta(temp_pyacme_home, "a.example.com")["provider_conf"] is None


def test_new_reads_token_from_environment(temp_pyacme_home):
    with patch("pyacmecli.__main__.get_certificate_for_domains_dns") as issue:
        result = CliRunner(env={"PYACME_CLOUDFLARE_TOKEN": "from-env"}).invoke(
            main_command,
            [
                "new",
                "--domain",
                "example.com",
                "--provider",
                "cloudflare",
                "--email",
                "a@example.com",
                "--renew-command",
                "true",
                "--no-store-token",
            ],
        )
    assert result.exit_code == 0, result.output
    assert issue.call_args.args[3] == "from-env"
    assert issue.call_args.kwargs["store_token"] is False
