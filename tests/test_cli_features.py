"""CLI features: hook environment, JSON listing, metrics and directory URL."""

import json
import os
import subprocess
from unittest.mock import patch

from click.testing import CliRunner

from pyacmecli.__main__ import (
    main_command,
    run_renew_command_as_subprocess_command,
)
from tests.test_reliability import _write_cert


def test_renew_command_receives_certificate_paths(tmp_path):
    out = tmp_path / "env.txt"
    ok = run_renew_command_as_subprocess_command(
        f'printf "%s %s" "$PYACME_DOMAIN" "$PYACME_KEY_PATH" > {out}',
        env={"PYACME_DOMAIN": "example.com", "PYACME_KEY_PATH": "/k.pem"},
    )
    assert ok
    assert out.read_text() == "example.com /k.pem"


def test_renew_command_timeout_is_a_failure():
    with patch(
        "subprocess.run", side_effect=subprocess.TimeoutExpired("x", 600)
    ):
        assert run_renew_command_as_subprocess_command("sleep 999") is False


def test_cron_passes_certificate_env_to_renew_command(temp_pyacme_home):
    _write_cert(temp_pyacme_home, "a.example.com")
    with (
        patch("pyacmecli.__main__.renew_certificate"),
        patch(
            "pyacmecli.__main__.run_renew_command_as_subprocess_command",
            return_value=True,
        ) as hook,
    ):
        result = CliRunner().invoke(main_command, ["cron"])
    assert result.exit_code == 0, result.output
    env = hook.call_args.kwargs["env"]
    cert_dir = os.path.join(temp_pyacme_home, "a.example.com")
    assert env == {
        "PYACME_DOMAIN": "a.example.com",
        "PYACME_CERT_DIR": cert_dir,
        "PYACME_CERT_PATH": os.path.join(cert_dir, "cert.pem"),
        "PYACME_KEY_PATH": os.path.join(cert_dir, "privkey.pem"),
    }


def test_list_json(temp_pyacme_home):
    _write_cert(temp_pyacme_home, "a.example.com")
    result = CliRunner().invoke(main_command, ["list", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert [d["domain"] for d in data] == ["a.example.com"]
    assert data[0]["expiry_date"] == "2020-01-01T00:00:00Z"


def test_cron_writes_metrics_even_when_a_renewal_fails(
    temp_pyacme_home, tmp_path
):
    _write_cert(temp_pyacme_home, "a.example.com")
    _write_cert(temp_pyacme_home, "b.example.com")
    metrics = tmp_path / "pyacme.prom"

    def renew(path, **kwargs):
        if "b.example.com" in path:
            raise RuntimeError("boom")

    with (
        patch("pyacmecli.__main__.renew_certificate", side_effect=renew),
        patch(
            "pyacmecli.__main__.run_renew_command_as_subprocess_command",
            return_value=True,
        ),
    ):
        result = CliRunner().invoke(
            main_command, ["cron", "--metrics-file", str(metrics)]
        )
    assert result.exit_code != 0
    text = metrics.read_text()
    assert 'pyacme_renewal_failed{domain="a.example.com"} 0' in text
    assert 'pyacme_renewal_failed{domain="b.example.com"} 1' in text
    assert (
        'pyacme_certificate_expiry_timestamp_seconds{domain="a.example.com"} '
        "1577836800" in text
    )
    assert "pyacme_cron_last_run_timestamp_seconds " in text
    assert os.stat(metrics).st_mode & 0o777 == 0o644


def test_directory_url_is_passed_to_new_and_cron(temp_pyacme_home):
    url = "https://ca.internal/acme/directory"
    with patch("pyacmecli.__main__.get_certificate_for_domains_dns") as issue:
        result = CliRunner().invoke(
            main_command,
            [
                "--directory-url",
                url,
                "new",
                "--domain",
                "example.com",
                "--provider",
                "dns",
                "--email",
                "a@example.com",
                "--renew-command",
                "true",
            ],
        )
    assert result.exit_code == 0, result.output
    assert issue.call_args.kwargs["directory_url"] == url

    _write_cert(temp_pyacme_home, "a.example.com")
    with (
        patch("pyacmecli.__main__.renew_certificate") as renew,
        patch(
            "pyacmecli.__main__.run_renew_command_as_subprocess_command",
            return_value=True,
        ),
    ):
        result = CliRunner(env={"PYACME_DIRECTORY_URL": url}).invoke(
            main_command, ["cron"]
        )
    assert result.exit_code == 0, result.output
    assert renew.call_args.kwargs["directory_url"] == url


def test_renewal_reuses_stored_directory_url(
    temp_pyacme_home, cert_pem_factory, fake_acme, mock_sleep, monkeypatch
):
    """A certificate issued from a custom CA is renewed from that CA."""
    from pyacmecli.acme import helper

    domain_dir = os.path.join(temp_pyacme_home, "example.com")
    os.makedirs(domain_dir)
    cert_pem, key_pem = cert_pem_factory(["example.com"])
    for name, data in (
        ("cert.pem", cert_pem),
        ("privkey.pem", key_pem),
        ("account.key.pem", key_pem),
        ("account_url.result", b"https://acme.test/acct/1"),
    ):
        with open(os.path.join(domain_dir, name), "wb") as f:
            f.write(data)
    json_path = os.path.join(domain_dir, "certificate.json")
    with open(json_path, "w") as f:
        json.dump(
            {
                "domain": "example.com",
                "certificate_path": os.path.join(domain_dir, "cert.pem"),
                "provider": "dns",
                "directory_url": "https://acme.test/directory",
            },
            f,
        )

    fake_acme(cert_pem)
    seen = []
    real = helper.get_directory_url
    monkeypatch.setattr(
        helper,
        "get_directory_url",
        lambda staging=False, custom_url=None: seen.append(custom_url)
        or real(staging, custom_url),
    )
    with (
        patch.object(helper, "wait_for_dns"),
        patch("builtins.input", return_value=""),
    ):
        helper.renew_certificate(json_path)
    assert seen == ["https://acme.test/directory"]
