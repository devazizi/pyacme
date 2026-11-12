"""Unit tests for inspect, delete, export, and revoke commands."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from pyacmecli.__main__ import main_command


def test_inspect_command(tmp_path, cert_pem_factory):
    """Test inspect command outputs formatted details."""
    domain = "inspect-test.com"
    domain_dir = tmp_path / domain
    domain_dir.mkdir(parents=True)
    cert_path = domain_dir / "cert.pem"
    key_path = domain_dir / "privkey.pem"
    json_path = domain_dir / "certificate.json"

    cert_pem, key_pem = cert_pem_factory([domain, f"*.{domain}"])
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    json_path.write_text(
        json.dumps(
            {
                "domain": domain,
                "provider": "hetzner",
                "staging": True,
                "status": "valid",
                "renew_command": "echo reloaded",
            }
        )
    )

    runner = CliRunner()
    with patch("pyacmecli.acme.helper.PYACME_HOME_PATH", str(tmp_path)):
        result = runner.invoke(main_command, ["inspect", domain])
        assert result.exit_code == 0
        assert domain in result.output
        assert "inspect-test.com" in result.output
        assert "Issuer" in result.output
        assert "Valid Until" in result.output
        assert "hetzner" in result.output


def test_delete_command(tmp_path):
    """Test delete command removes certificate directory."""
    domain = "delete-test.com"
    domain_dir = tmp_path / domain
    domain_dir.mkdir(parents=True)
    (domain_dir / "cert.pem").write_text("dummy cert")

    runner = CliRunner()
    with patch("pyacmecli.acme.helper.PYACME_HOME_PATH", str(tmp_path)):
        # Test abort on prompt 'n'
        res_abort = runner.invoke(main_command, ["delete", domain], input="n\n")
        assert res_abort.exit_code != 0
        assert domain_dir.exists()

        # Test delete with --yes
        res_yes = runner.invoke(main_command, ["delete", domain, "--yes"])
        assert res_yes.exit_code == 0
        assert not domain_dir.exists()
        assert "Successfully deleted" in res_yes.output


def test_export_command_pem_and_pfx(tmp_path, cert_pem_factory):
    """Test export command creates pem-bundle and pfx files."""
    domain = "export-test.com"
    domain_dir = tmp_path / domain
    domain_dir.mkdir(parents=True)
    cert_path = domain_dir / "cert.pem"
    key_path = domain_dir / "privkey.pem"

    cert_pem, key_pem = cert_pem_factory([domain])
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)

    runner = CliRunner()
    bundle_out = tmp_path / "out-bundle.pem"
    pfx_out = tmp_path / "out.pfx"

    with patch("pyacmecli.acme.helper.PYACME_HOME_PATH", str(tmp_path)):
        # Export pem-bundle
        res_pem = runner.invoke(
            main_command,
            [
                "export",
                domain,
                "--output",
                str(bundle_out),
                "--format",
                "pem-bundle",
            ],
        )
        assert res_pem.exit_code == 0
        assert bundle_out.exists()
        content = bundle_out.read_text()
        assert "-----BEGIN CERTIFICATE-----" in content
        assert (
            "-----BEGIN PRIVATE KEY-----" in content
            or "-----BEGIN RSA PRIVATE KEY-----" in content
        )

        # Export pfx with password
        res_pfx = runner.invoke(
            main_command,
            [
                "export",
                domain,
                "--output",
                str(pfx_out),
                "--format",
                "pfx",
                "--password",
                "secret123",
            ],
        )
        assert res_pfx.exit_code == 0
        assert pfx_out.exists()
        assert pfx_out.stat().st_size > 0


def test_revoke_command(tmp_path, cert_pem_factory, session_rsa_key):
    """Test revoke command contacts ACME directory and marks status as revoked."""
    domain = "revoke-test.com"
    domain_dir = tmp_path / domain
    domain_dir.mkdir(parents=True)
    cert_path = domain_dir / "cert.pem"
    key_path = domain_dir / "privkey.pem"
    json_path = domain_dir / "certificate.json"

    cert_pem, _ = cert_pem_factory([domain])
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(cert_pem)  # dummy
    json_path.write_text(json.dumps({"domain": domain, "status": "valid"}))

    runner = CliRunner()
    with (
        patch("pyacmecli.acme.helper.PYACME_HOME_PATH", str(tmp_path)),
        patch("pyacmecli.acme.helper.get_directory") as mock_dir,
        patch(
            "pyacmecli.acme.helper.load_or_make_rsa_key",
            return_value=session_rsa_key,
        ),
        patch(
            "pyacmecli.acme.helper.account_directory_url",
            return_value="http://acc",
        ),
        patch("pyacmecli.acme.helper.post_jws") as mock_post,
    ):
        mock_dir.return_value = {
            "newNonce": "http://nonce",
            "revokeCert": "http://revoke",
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        result = runner.invoke(
            main_command,
            ["revoke", domain, "--yes", "--reason", "1"],
        )
        assert result.exit_code == 0
        assert "has been revoked" in result.output
        assert mock_post.called

        # Verify json updated
        updated_data = json.loads(json_path.read_text())
        assert updated_data["status"] == "revoked"


@pytest.mark.parametrize("name", ["..", "../..", "/etc", "", ".", "a/b"])
def test_unsafe_domain_names_are_rejected(tmp_path, name):
    """Names that escape the pyacme home must never reach the filesystem."""
    home = tmp_path / ".pyacme"
    (home / "example.com").mkdir(parents=True)
    victim = tmp_path / "victim.txt"
    victim.write_text("keep")

    runner = CliRunner()
    with patch("pyacmecli.acme.helper.PYACME_HOME_PATH", str(home)):
        for args in (
            ["delete", "--yes", "--", name],
            ["inspect", "--", name],
            ["export", "--", name],
            ["revoke", "--yes", "--", name],
        ):
            result = runner.invoke(main_command, args)
            assert result.exit_code != 0, args
            assert "Invalid domain name" in result.output, args

    assert victim.exists()
    assert (home / "example.com").is_dir()


def test_new_rejects_invalid_domain_and_accepts_wildcard():
    runner = CliRunner()
    base = ["--provider", "dns", "--email", "a@example.com"]
    base += ["--renew-command", "true"]
    with patch("pyacmecli.__main__.get_certificate_for_domains_dns") as issue:
        bad = runner.invoke(
            main_command, ["new", "--domain", "not a domain", *base]
        )
        assert bad.exit_code != 0
        assert "Invalid domain name" in bad.output
        issue.assert_not_called()

        good = runner.invoke(
            main_command,
            ["new", "--domain", "example.com", "--domain", "*.example.com"]
            + base,
        )
        assert good.exit_code == 0, good.output
        issue.assert_called_once()


def test_secret_files_are_owner_only(tmp_path, cert_pem_factory):
    """Keys, metadata with the provider token, and exports must be 0600."""
    from pyacmecli.acme.helper import load_or_make_rsa_key
    from pyacmecli.tls.ssl_object import SSLCertificate

    def mode(path):
        return os.stat(path).st_mode & 0o777

    home = tmp_path / ".pyacme"
    domain_dir = home / "example.com"
    domain_dir.mkdir(parents=True)
    cert_pem, key_pem = cert_pem_factory(["example.com"])
    (domain_dir / "cert.pem").write_bytes(cert_pem)
    (domain_dir / "privkey.pem").write_bytes(key_pem)

    with patch("pyacmecli.acme.helper.PYACME_HOME_PATH", str(home)):
        load_or_make_rsa_key("example.com/account.key.pem")
        assert mode(domain_dir / "account.key.pem") == 0o600

        cert = SSLCertificate.from_pem(
            cert_path=str(domain_dir / "cert.pem"),
            key_path=str(domain_dir / "privkey.pem"),
            provider="cloudflare",
            provider_conf="dummy-token",
        )
        # A pre-existing world-readable file must be tightened on rewrite.
        json_path = domain_dir / "certificate.json"
        json_path.write_text("{}")
        os.chmod(json_path, 0o644)
        cert.save(str(json_path))
        assert mode(json_path) == 0o600

        out = tmp_path / "bundle.pem"
        result = CliRunner().invoke(
            main_command, ["export", "example.com", "-o", str(out)]
        )
        assert result.exit_code == 0, result.output
        assert mode(out) == 0o600
