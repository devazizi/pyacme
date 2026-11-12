"""DNS checks against authoritative servers and exact TXT cleanup."""

from unittest.mock import MagicMock, patch

import dns.name
import dns.resolver
import pytest

from pyacmecli.acme import dnscheck, operations
from pyacmecli.acme.helper import find_authoritative_servers  # unpatched
from tests.test_reliability import _authz, _run_challenge


def _txt(value):
    rdata = MagicMock()
    rdata.strings = [value.encode()]
    return [rdata]


def test_wait_for_dns_requires_every_authoritative_server(
    mock_sleep, monkeypatch
):
    answers = {
        "10.0.0.1": [_txt("tok")],
        "10.0.0.2": [dns.resolver.NXDOMAIN(), _txt("tok")],
    }
    queried = []

    class FakeResolver:
        def resolve(self, name, rdtype):
            server = self.nameservers[0]
            queried.append(server)
            result = answers[server].pop(0)
            if isinstance(result, Exception):
                raise result
            return result

    monkeypatch.setattr("dns.resolver.Resolver", FakeResolver)
    dnscheck.wait_for_dns(
        "_acme-challenge.example.com",
        "tok",
        interval=1,
        timeout=60,
        nameservers=["10.0.0.1", "10.0.0.2"],
    )
    # Server 1 matched at once and is not asked again; server 2 lagged.
    assert queried == ["10.0.0.1", "10.0.0.2", "10.0.0.2"]
    assert mock_sleep.call_count == 1


def test_find_authoritative_servers_follows_cname(monkeypatch):
    target = dns.name.from_text("abc.auth.acme-dns.io")
    zone = dns.name.from_text("acme-dns.io")

    def resolve(self, name, rdtype):
        name = str(name)
        if rdtype == "CNAME" and name == "_acme-challenge.example.com.":
            return [MagicMock(target=target)]
        if rdtype == "CNAME":
            raise dns.resolver.NoAnswer()
        if rdtype == "NS":
            assert name == "acme-dns.io."
            return [MagicMock(target=dns.name.from_text("ns1.acme-dns.io"))]
        if rdtype == "A":
            return [MagicMock(address="192.0.2.53")]
        raise AssertionError((name, rdtype))

    monkeypatch.setattr("dns.resolver.Resolver.resolve", resolve)
    with patch("dns.resolver.zone_for_name", return_value=zone) as zfn:
        result = find_authoritative_servers("_acme-challenge.example.com")

    assert zfn.call_args.args[0] == target
    assert result == ("abc.auth.acme-dns.io", ["192.0.2.53"])


def test_find_authoritative_servers_falls_back_on_failure():
    with (
        patch(
            "dns.resolver.zone_for_name",
            side_effect=dns.resolver.NoNameservers(),
        ),
        patch(
            "dns.resolver.Resolver.resolve", side_effect=dns.resolver.NoAnswer()
        ),
    ):
        assert find_authoritative_servers("_acme-challenge.example.com") == (
            "_acme-challenge.example.com",
            None,
        )


def test_txt_record_is_removed_after_failed_validation(mock_sleep):
    error = {"type": "urn:ietf:params:acme:error:unauthorized"}
    with pytest.raises(RuntimeError, match="is invalid"):
        _run_challenge([_authz("invalid", error=error)])
    provider = _run_challenge.provider
    # Once before adding (leftovers) and once after the authz was decided.
    assert provider.delete_txt_record.call_count == 2
    provider.add_txt_record.assert_called_once()


def test_txt_record_is_removed_after_successful_validation(mock_sleep):
    with patch.object(operations, "_cleanup_txt_record") as cleanup:
        _run_challenge([_authz("valid")])
    assert cleanup.call_count == 2


def test_cleanup_failure_is_only_logged():
    provider = MagicMock()
    provider.delete_txt_record.side_effect = RuntimeError("API down")
    operations._cleanup_txt_record(provider, "_acme-challenge.example.com")
