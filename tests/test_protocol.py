"""ACME protocol behaviour: JWS retries, POST-as-GET and full issuance."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from pyacmecli.acme import helper
from tests.conftest import FakeResponse


def _session(responses):
    session = MagicMock()
    session.head.return_value = FakeResponse(
        headers={"Replay-Nonce": "nonce-from-head"}
    )
    session.post.side_effect = responses
    return session


def _nonces(session):
    return [
        json.loads(
            helper.base64.urlsafe_b64decode(
                c.kwargs["json"]["protected"] + "=="
            )
        )["nonce"]
        for c in session.post.call_args_list
    ]


def _problem(status, kind, headers=None):
    return FakeResponse(
        status,
        {"type": f"urn:ietf:params:acme:error:{kind}", "detail": kind},
        headers=headers,
    )


def test_bad_nonce_is_retried_with_the_returned_nonce(session_rsa_key):
    bad = _problem(400, "badNonce", headers={"Replay-Nonce": "fresh-1"})
    session = _session([bad, FakeResponse(200, {"ok": True})])

    resp = helper.post_jws(
        session,
        "https://ca/x",
        {},
        session_rsa_key,
        "https://ca/nonce",
        kid="k",
    )

    assert resp.json() == {"ok": True}
    assert _nonces(session) == ["nonce-from-head", "fresh-1"]
    assert session.head.call_count == 1


def test_other_client_errors_are_not_retried(session_rsa_key):
    session = _session([_problem(400, "malformed")])
    with pytest.raises(helper.AcmeError, match="malformed") as excinfo:
        helper.post_jws(
            session,
            "https://ca/x",
            {},
            session_rsa_key,
            "https://ca/n",
            kid="k",
        )
    assert excinfo.value.status == 400
    assert session.post.call_count == 1


def test_short_retry_after_is_honoured(session_rsa_key, mock_sleep):
    busy = _problem(503, "serverInternal", headers={"Retry-After": "2"})
    session = _session([busy, FakeResponse(200, {})])
    helper.post_jws(
        session, "https://ca/x", {}, session_rsa_key, "https://ca/n", kid="k"
    )
    mock_sleep.assert_called_once_with(2.0)
    assert session.post.call_count == 2


def test_long_rate_limit_fails_fast(session_rsa_key, mock_sleep):
    limited = _problem(429, "rateLimited", headers={"Retry-After": "3600"})
    session = _session([limited])
    with pytest.raises(helper.AcmeError, match="retry after 3600s"):
        helper.post_jws(
            session,
            "https://ca/x",
            {},
            session_rsa_key,
            "https://ca/n",
            kid="k",
        )
    mock_sleep.assert_not_called()
    assert session.post.call_count == 1


def test_issue_wildcard_and_apex_end_to_end(
    temp_pyacme_home, cert_pem_factory, fake_acme, mock_sleep
):
    """Issue example.com + *.example.com against the fake CA.

    FakeAcme fails any plain GET other than the directory, so this also
    proves authz and certificate downloads use POST-as-GET.
    """
    domains = ["example.com", "*.example.com"]
    cert_pem, _ = cert_pem_factory(domains)
    fake = fake_acme(cert_pem)
    provider = MagicMock()

    with (
        patch.object(helper, "dns_challenge_provider", return_value=provider),
        patch.object(helper, "wait_for_dns"),
    ):
        helper.get_certificate_for_domains_dns(
            domains, "cloudflare", "a@example.com", "token", "true"
        )

    cert_dir = os.path.join(temp_pyacme_home, "example.com")
    with open(os.path.join(cert_dir, "cert.pem")) as f:
        assert f.read() == cert_pem.decode()
    with open(os.path.join(cert_dir, "certificate.json")) as f:
        meta = json.load(f)
    assert meta["domains"] == domains
    assert meta["key_type"] == "rsa2048"
    assert len(fake.payloads("/new-order")) == 1
    assert provider.add_txt_record.call_count == 2
