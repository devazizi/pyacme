"""Unit tests for pyacmecli.acme.helper covering R2, R3, R4, crypto, and offline ACME workflows."""

import json
import os
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest
from cryptography import x509

from pyacmecli.acme.helper import (
    LETSENCRYPT_PRODUCTION_DIRECTORY,
    LETSENCRYPT_STAGING_DIRECTORY,
    b64u,
    create_acme_account,
    create_csr,
    extract_domains_for_renewal,
    get_directory_url,
    int_to_b64u,
    jwk_from_privkey,
    renew_certificate,
    thumbprint,
    wait_for_dns,
)


# ============================================================================
# R2: DNS Wait Timeout & Retry Limits
# ============================================================================


def test_wait_for_dns_immediate_success(mock_sleep):
    """Verify wait_for_dns returns immediately when matching TXT record is found."""
    mock_rdata = MagicMock()
    mock_rdata.strings = [b"expected-token-value"]

    with patch("dns.resolver.Resolver.resolve", return_value=[mock_rdata]):
        wait_for_dns(
            "_acme-challenge.example.com",
            "expected-token-value",
            interval=1,
            timeout=10,
        )


def test_wait_for_dns_retries_and_succeeds(mock_sleep):
    """Verify wait_for_dns handles initial NXDOMAIN and recovers on second attempt."""
    mock_rdata = MagicMock()
    mock_rdata.strings = [b"expected-token-value"]

    with patch(
        "dns.resolver.Resolver.resolve",
        side_effect=[dns.resolver.NXDOMAIN(), [mock_rdata]],
    ):
        wait_for_dns(
            "_acme-challenge.example.com",
            "expected-token-value",
            interval=1,
            timeout=10,
        )


def test_wait_for_dns_recovers_from_lifetime_timeout(mock_sleep):
    """Verify wait_for_dns catches dns.exception.Timeout/LifetimeTimeout without crashing."""
    mock_rdata = MagicMock()
    mock_rdata.strings = [b"valid-token"]

    with patch(
        "dns.resolver.Resolver.resolve",
        side_effect=[
            dns.resolver.LifetimeTimeout("Query timed out"),
            [mock_rdata],
        ],
    ):
        wait_for_dns(
            "_acme-challenge.example.com", "valid-token", interval=1, timeout=10
        )


def test_wait_for_dns_timeout_exceeded(mock_sleep):
    """Verify wait_for_dns raises TimeoutError when timeout is reached without hanging indefinitely."""
    with patch(
        "dns.resolver.Resolver.resolve",
        side_effect=dns.resolver.NXDOMAIN(),
    ):
        with pytest.raises(TimeoutError, match="DNS propagation timed out"):
            wait_for_dns(
                "_acme-challenge.example.com",
                "missing-token",
                interval=0.01,
                timeout=0.02,
            )


def test_wait_for_dns_max_retries_exceeded(mock_sleep):
    """Verify wait_for_dns raises TimeoutError when max_retries limit is reached."""
    mock_rdata = MagicMock()
    mock_rdata.strings = [b"other-token"]  # Mismatched value

    with patch("dns.resolver.Resolver.resolve", return_value=[mock_rdata]):
        with pytest.raises(TimeoutError, match="DNS propagation timed out"):
            wait_for_dns(
                "_acme-challenge.example.com",
                "expected-token",
                interval=0.01,
                timeout=10,
                max_retries=2,
            )


# ============================================================================
# R3: Let's Encrypt Staging Environment Support
# ============================================================================


def test_get_directory_url_production():
    """Verify default directory is production Let's Encrypt."""
    assert get_directory_url(staging=False) == LETSENCRYPT_PRODUCTION_DIRECTORY


def test_get_directory_url_staging():
    """Verify staging=True selects Let's Encrypt Staging directory."""
    assert get_directory_url(staging=True) == LETSENCRYPT_STAGING_DIRECTORY


def test_get_directory_url_custom_override():
    """Verify custom_url takes precedence over staging flag."""
    custom = "https://acme.internal.net/directory"
    assert get_directory_url(staging=True, custom_url=custom) == custom


# ============================================================================
# Crypto, CSR, and JWS Utilities
# ============================================================================


def test_b64u_and_int_to_b64u():
    """Verify URL-safe base64 encoding without padding."""
    assert b64u(b"hello world") == "aGVsbG8gd29ybGQ"
    assert int_to_b64u(65537) == "AQAB"


def test_jwk_from_privkey_and_thumbprint(session_rsa_key):
    """Verify JWK extraction and thumbprint computation."""
    jwk = jwk_from_privkey(session_rsa_key)
    assert jwk["kty"] == "RSA"
    assert "n" in jwk
    assert jwk["e"] == "AQAB"

    t = thumbprint(jwk)
    assert isinstance(t, str)
    assert len(t) == 43  # SHA-256 base64url length


def test_create_csr(session_rsa_key):
    """Verify create_csr encodes CN and SubjectAlternativeName extension properly."""
    domains = ["example.com", "sub.example.com"]
    csr_der = create_csr(session_rsa_key, domains)
    csr = x509.load_der_x509_csr(csr_der)

    assert csr.is_signature_valid
    san_ext = csr.extensions.get_extension_for_oid(
        x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    )
    names = san_ext.value.get_values_for_type(x509.DNSName)
    assert names == ["example.com", "sub.example.com"]


# ============================================================================
# Offline Account Creation & JWS
# ============================================================================


def test_create_acme_account_offline(temp_pyacme_home, monkeypatch):
    """Verify offline account creation writes account_url.result inside PYACME_HOME_PATH."""
    mock_session = MagicMock()

    # Directory response
    dir_resp = MagicMock()
    dir_resp.json.return_value = {
        "newNonce": "https://acme.org/newNonce",
        "newAccount": "https://acme.org/newAccount",
    }
    dir_resp.raise_for_status = MagicMock()

    # Nonce head response
    nonce_resp = MagicMock()
    nonce_resp.headers = {"Replay-Nonce": "test-nonce-1"}

    # Account creation response
    acct_resp = MagicMock()
    acct_resp.status_code = 201
    acct_resp.headers = {"Location": "https://acme.org/acct/98765"}

    mock_session.get.return_value = dir_resp
    mock_session.head.return_value = nonce_resp
    mock_session.post.return_value = acct_resp

    with patch("requests.Session", return_value=mock_session):
        acct_url = create_acme_account(
            email="admin@example.com", domain="example.com", staging=False
        )

    assert acct_url == "https://acme.org/acct/98765"
    result_path = os.path.join(
        temp_pyacme_home, "example.com", "account_url.result"
    )
    assert os.path.exists(result_path)
    with open(result_path, "r") as f:
        assert f.read().strip() == "https://acme.org/acct/98765"


# ============================================================================
# R4: Multi-Domain Certificate Renewal Logic
# ============================================================================


def test_extract_domains_for_renewal_from_stored_domains():
    """Verify domains are extracted directly from cert_data['domains'] when present."""
    cert_data = {
        "domain": "app.example.com",
        "domains": ["app.example.com", "api.example.com"],
    }
    extracted = extract_domains_for_renewal(cert_data, "/tmp")
    assert extracted == ["app.example.com", "api.example.com"]


def test_extract_domains_for_renewal_from_cert_pem(tmp_path, cert_pem_factory):
    """Verify domains are extracted from cert.pem SANs when cert_data['domains'] is absent."""
    cert_pem, _ = cert_pem_factory(["site.example.com", "cdn.example.com"])
    cert_path = str(tmp_path / "cert.pem")
    with open(cert_path, "wb") as f:
        f.write(cert_pem)

    cert_data = {"domain": "site.example.com", "certificate_path": cert_path}
    extracted = extract_domains_for_renewal(cert_data, str(tmp_path))
    assert extracted == ["site.example.com", "cdn.example.com"]


def test_extract_domains_for_renewal_fallback_domain():
    """Verify fallback to cert_data['domain'] when no cert.pem or domains list is available."""
    cert_data = {"domain": "single.example.com"}
    extracted = extract_domains_for_renewal(cert_data, "/nonexistent")
    assert extracted == ["single.example.com"]


def test_renew_certificate_single_domain_no_duplicate_identifiers(
    temp_pyacme_home, cert_pem_factory, mock_sleep, fake_acme
):
    """Verify single-domain renewal produces exactly 1 identifier (no duplicated apex)."""
    domain = "single.example.com"
    domain_dir = os.path.join(temp_pyacme_home, domain)
    os.makedirs(domain_dir, exist_ok=True)

    cert_pem, key_pem = cert_pem_factory([domain])
    cert_path = os.path.join(domain_dir, "cert.pem")
    privkey_path = os.path.join(domain_dir, "privkey.pem")
    acct_key_path = os.path.join(domain_dir, "account.key.pem")
    acct_url_path = os.path.join(domain_dir, "account_url.result")
    json_path = os.path.join(domain_dir, "certificate.json")

    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    with open(privkey_path, "wb") as f:
        f.write(key_pem)
    with open(acct_key_path, "wb") as f:
        f.write(key_pem)
    with open(acct_url_path, "w") as f:
        f.write("https://acme.org/acct/1")

    initial_meta = {
        "domain": domain,
        "certificate_path": cert_path,
        "private_key_path": privkey_path,
        "expiry_date": "2026-01-01T00:00:00Z",
        "renew_before_days": 30,
        "last_renewed": "2025-01-01T00:00:00Z",
        "renew_command": "",
        "status": "valid",
        "provider": "dns",
        "provider_conf": None,
        "email": "test@example.com",
    }
    with open(json_path, "w") as f:
        json.dump(initial_meta, f)

    fake = fake_acme(cert_pem)
    with (
        patch("pyacmecli.acme.helper.wait_for_dns"),
        patch("builtins.input", return_value=""),
    ):
        renew_certificate(json_path)

    # Verify updated certificate.json
    with open(json_path, "r") as f:
        renewed_meta = json.load(f)
    assert renewed_meta["status"] == "valid"
    assert renewed_meta["domains"] == [domain]
    captured_order_payloads = fake.payloads("/new-order")
    assert len(captured_order_payloads) == 1
    assert captured_order_payloads[0]["identifiers"] == [
        {"type": "dns", "value": domain}
    ]


def test_renew_certificate_multi_san_domains(
    temp_pyacme_home, cert_pem_factory, mock_sleep, fake_acme
):
    """Verify multi-SAN renewal preserves all domains and sends all to ACME order."""
    domains = ["app.example.com", "api.example.com", "admin.example.com"]
    folder_domain = domains[0]
    domain_dir = os.path.join(temp_pyacme_home, folder_domain)
    os.makedirs(domain_dir, exist_ok=True)

    cert_pem, key_pem = cert_pem_factory(domains)
    cert_path = os.path.join(domain_dir, "cert.pem")
    privkey_path = os.path.join(domain_dir, "privkey.pem")
    acct_key_path = os.path.join(domain_dir, "account.key.pem")
    acct_url_path = os.path.join(domain_dir, "account_url.result")
    json_path = os.path.join(domain_dir, "certificate.json")

    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    with open(privkey_path, "wb") as f:
        f.write(key_pem)
    with open(acct_key_path, "wb") as f:
        f.write(key_pem)
    with open(acct_url_path, "w") as f:
        f.write("https://acme.org/acct/multi")

    initial_meta = {
        "domain": folder_domain,
        "domains": domains,
        "certificate_path": cert_path,
        "private_key_path": privkey_path,
        "expiry_date": "2026-01-01T00:00:00Z",
        "renew_before_days": 30,
        "last_renewed": "2025-01-01T00:00:00Z",
        "renew_command": "",
        "status": "valid",
        "provider": "dns",
        "provider_conf": None,
        "email": "test@example.com",
    }
    with open(json_path, "w") as f:
        json.dump(initial_meta, f)

    fake = fake_acme(cert_pem)
    with (
        patch("pyacmecli.acme.helper.wait_for_dns"),
        patch("builtins.input", return_value=""),
    ):
        renew_certificate(json_path)

    with open(json_path, "r") as f:
        renewed_meta = json.load(f)
    assert renewed_meta["status"] == "valid"
    assert renewed_meta["domains"] == domains
    captured_order_payloads = fake.payloads("/new-order")
    assert len(captured_order_payloads) == 1
    assert captured_order_payloads[0]["identifiers"] == [
        {"type": "dns", "value": d} for d in domains
    ]
