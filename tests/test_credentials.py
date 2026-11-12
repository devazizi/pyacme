"""Provider credentials stored outside certificate.json."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from pyacmecli.__main__ import main_command
from pyacmecli.acme import dnscheck, operations, storage


def _issue(domains, cert_pem_factory, fake_acme, token="cf-secret", **kw):
    fake_acme(cert_pem_factory(domains)[0])
    with (
        patch.object(
            operations, "dns_challenge_provider", return_value=MagicMock()
        ),
        patch.object(dnscheck, "wait_for_dns"),
    ):
        operations.get_certificate_for_domains_dns(
            domains, "cloudflare", "a@example.com", token, "true", **kw
        )


def _meta_text(home, domain):
    with open(os.path.join(home, domain, "certificate.json")) as f:
        return f.read()


def _mode(path):
    return os.stat(path).st_mode & 0o777


def test_token_goes_to_a_private_credential_file(
    temp_pyacme_home, cert_pem_factory, fake_acme, mock_sleep
):
    _issue(["a.example.com"], cert_pem_factory, fake_acme)
    _issue(["b.example.com"], cert_pem_factory, fake_acme)

    texts = [
        _meta_text(temp_pyacme_home, d)
        for d in ("a.example.com", "b.example.com")
    ]
    assert all("cf-secret" not in t for t in texts)
    names = {json.loads(t)["credential"] for t in texts}
    assert len(names) == 1  # one file for one token
    (name,) = names
    assert name.startswith("cloudflare-")
    path = storage.credential_path(name)
    assert _mode(path) == 0o600
    assert _mode(storage.credentials_dir()) == 0o700
    assert storage.load_credential(name) == ("cloudflare", "cf-secret")


def test_explicit_credential_name(
    temp_pyacme_home, cert_pem_factory, fake_acme, mock_sleep
):
    _issue(
        ["a.example.com"],
        cert_pem_factory,
        fake_acme,
        credential_name="cf-prod",
    )
    meta = json.loads(_meta_text(temp_pyacme_home, "a.example.com"))
    assert meta["credential"] == "cf-prod"


def test_renewal_moves_inline_token_to_credential_file(
    temp_pyacme_home, cert_pem_factory, fake_acme, mock_sleep
):
    _issue(["a.example.com"], cert_pem_factory, fake_acme, store_token=False)
    json_path = os.path.join(
        temp_pyacme_home, "a.example.com", "certificate.json"
    )
    meta = json.loads(_meta_text(temp_pyacme_home, "a.example.com"))
    meta["provider_conf"] = "legacy-token"  # as written by older versions
    with open(json_path, "w") as f:
        json.dump(meta, f)

    fake_acme(cert_pem_factory(["a.example.com"])[0])
    provider = MagicMock()
    with (
        patch.object(
            operations, "dns_challenge_provider", return_value=provider
        ) as factory,
        patch.object(dnscheck, "wait_for_dns"),
    ):
        operations.renew_certificate(json_path)

    assert factory.call_args.args[2] == "legacy-token"
    renewed = json.loads(_meta_text(temp_pyacme_home, "a.example.com"))
    assert "provider_conf" not in renewed
    assert storage.load_credential(renewed["credential"]) == (
        "cloudflare",
        "legacy-token",
    )


def test_resolution_order(temp_pyacme_home, monkeypatch):
    storage.save_credential("cf", "cloudflare", "from-file")
    monkeypatch.delenv("PYACME_CLOUDFLARE_TOKEN", raising=False)
    assert (
        operations.resolve_access_token("cloudflare", "inline", "cf")
        == "from-file"
    )
    assert operations.resolve_access_token("cloudflare", "inline") == "inline"
    monkeypatch.setenv("PYACME_CLOUDFLARE_TOKEN", "from-env")
    assert (
        operations.resolve_access_token("cloudflare", "inline", "cf")
        == "from-env"
    )

    monkeypatch.delenv("PYACME_CLOUDFLARE_TOKEN")
    with pytest.raises(RuntimeError, match="belongs to 'cloudflare'"):
        operations.resolve_access_token("digitalocean", None, "cf")


@pytest.mark.parametrize(
    "name", ["../x", "a/b", "UPPER", "", ".hidden", "a..b"]
)
def test_unsafe_credential_names_are_rejected(name):
    with pytest.raises(ValueError, match="Invalid credential name"):
        storage.credential_path(name)


def test_credentials_commands_never_print_the_token(temp_pyacme_home):
    runner = CliRunner(env={"PYACME_CLOUDFLARE_TOKEN": "super-secret"})
    result = runner.invoke(
        main_command,
        ["credentials", "set", "cf-prod", "--provider", "cloudflare"],
    )
    assert result.exit_code == 0, result.output

    listed = CliRunner().invoke(main_command, ["credentials", "list"])
    assert listed.exit_code == 0, listed.output
    assert "cf-prod" in listed.output and "cloudflare" in listed.output
    assert "super-secret" not in listed.output + result.output

    deleted = CliRunner().invoke(
        main_command, ["credentials", "delete", "cf-prod", "--yes"]
    )
    assert deleted.exit_code == 0, deleted.output
    assert storage.list_credentials() == []


def test_new_uses_a_stored_credential(temp_pyacme_home, monkeypatch):
    monkeypatch.delenv("PYACME_CLOUDFLARE_TOKEN", raising=False)
    storage.save_credential("cf-prod", "cloudflare", "stored-token")
    args = [
        "new",
        "--domain",
        "example.com",
        "--email",
        "a@example.com",
        "--renew-command",
        "true",
        "--credential",
        "cf-prod",
    ]
    with patch("pyacmecli.__main__.get_certificate_for_domains_dns") as issue:
        ok = CliRunner().invoke(
            main_command, [*args, "--provider", "cloudflare"]
        )
        wrong = CliRunner().invoke(
            main_command, [*args, "--provider", "hetzner"]
        )
    assert ok.exit_code == 0, ok.output
    assert issue.call_args.args[3] == "stored-token"
    assert issue.call_args.kwargs["credential_name"] == "cf-prod"
    assert wrong.exit_code != 0
    assert "is for cloudflare" in wrong.output
