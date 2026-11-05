import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

import dns.exception
import dns.resolver
import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from pyacmecli.acme.helper import (
    extract_domains_for_renewal,
    renew_certificate,
    wait_for_dns,
)
from pyacmecli.tls.ssl_object import SSLCertificate


# ==============================================================================
# R1 ADVERSARIAL TESTS: SSLCertificate Status, Typing & Serialization
# ==============================================================================


@pytest.mark.parametrize(
    "status_input, expected_status",
    [
        ("valid", "valid"),
        ("expired", "expired"),
        ("revoked", "revoked"),
        ("", ""),
        ("custom_unknown_status", "custom_unknown_status"),
        (("valid",), "valid"),  # Original 1-tuple bug reproduction
        (("expired", "extra"), "expired"),
        ((), "valid"),  # Empty tuple defaults to 'valid'
        (["valid"], "valid"),  # 1-element list
        (["revoked", "reason"], "revoked"),
        ([], "valid"),  # Empty list defaults to 'valid'
        (12345, "12345"),  # Numeric status converted to str
        (None, "None"),  # NoneType converted to str
        (True, "True"),  # Boolean converted to str
        ({"code": 200}, "{'code': 200}"),  # Dict converted to str
    ],
)
def test_r1_status_always_str_under_adversarial_inputs(
    status_input, expected_status
):
    """Stress-test SSLCertificate status assignment with various types."""
    cert = SSLCertificate(
        domain="adversarial.example.com",
        certificate_path="/tmp/fake/cert.pem",
        private_key_path="/tmp/fake/privkey.pem",
        expiry_date="2027-01-01T00:00:00Z",
        renew_before_days=30,
        last_renewed="2026-01-01T00:00:00Z",
        renew_command="echo 1",
        status=status_input,
        provider="cloudflare",
        provider_conf="fake-token",
        email="admin@example.com",
    )
    assert isinstance(cert.status, str), (
        f"Expected str for status, got {type(cert.status)}"
    )
    assert cert.status == expected_status
    assert repr(cert).startswith("<SSLCertificate")
    assert f"status={expected_status}" in repr(cert)


def test_r1_serialization_and_deserialization_roundtrip(tmp_path):
    """Ensure JSON serialization writes raw string status and roundtrips cleanly."""
    json_path = str(tmp_path / "certificate.json")

    cert = SSLCertificate(
        domain="roundtrip.com",
        certificate_path="/tmp/cert.pem",
        private_key_path="/tmp/privkey.pem",
        expiry_date="2026-12-31T23:59:59Z",
        renew_before_days=15,
        last_renewed="2026-01-01T12:00:00Z",
        renew_command="systemctl reload nginx",
        status=("valid",),  # Tuple input
        provider="arvancloud",
        provider_conf="my-token",
        email="ops@roundtrip.com",
        domains=["roundtrip.com", "www.roundtrip.com"],
        staging=True,
    )

    cert.save(json_path)

    # Inspect raw file content to confirm no tuple/list artifacts
    with open(json_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    assert isinstance(raw_data["status"], str)
    assert raw_data["status"] == "valid"
    assert raw_data["domains"] == ["roundtrip.com", "www.roundtrip.com"]
    assert raw_data["staging"] is True

    # Deserialization check via SSLCertificate.open
    loaded = SSLCertificate.open(json_path)
    assert isinstance(loaded.status, str)
    assert loaded.status == "valid"
    assert loaded.domains == ["roundtrip.com", "www.roundtrip.com"]
    assert loaded.staging is True


def test_r1_deserialization_from_legacy_list_json(tmp_path):
    """Ensure SSLCertificate.open can load legacy/external JSON containing a list for status."""
    json_path = str(tmp_path / "legacy.json")
    legacy_payload = {
        "domain": "legacy.com",
        "certificate_path": "/tmp/legacy.pem",
        "private_key_path": "/tmp/legacy.key",
        "expiry_date": "2026-12-31T00:00:00Z",
        "renew_before_days": 30,
        "last_renewed": "2026-01-01T00:00:00Z",
        "renew_command": "",
        "status": ["valid"],  # legacy list format
        "provider": "dns",
        "provider_conf": "",
        "email": "legacy@domain.com",
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(legacy_payload, f)

    loaded = SSLCertificate.open(json_path)
    assert isinstance(loaded.status, str)
    assert loaded.status == "valid"


def test_r1_save_missing_path_raises():
    """Ensure calling save with file_path=None raises ValueError."""
    cert = SSLCertificate(
        domain="example.com",
        certificate_path="/tmp/cert.pem",
        private_key_path="/tmp/privkey.pem",
        expiry_date="2026-12-31T00:00:00Z",
        renew_before_days=30,
        last_renewed="2026-01-01T00:00:00Z",
        renew_command="",
        status="valid",
        provider="dns",
        provider_conf="",
        email="",
    )
    with pytest.raises(ValueError, match="File path must be provided"):
        cert.save(None)


# ==============================================================================
# R2 ADVERSARIAL TESTS: wait_for_dns Timeout, Retries & LifetimeTimeout
# ==============================================================================


def test_r2_instant_success_first_attempt(monkeypatch):
    """Empirically verify instant success on the very first attempt without sleeping."""
    mock_rdata = MagicMock()
    mock_rdata.strings = [b"challenge-token-12345"]

    mock_resolver_inst = MagicMock()
    mock_resolver_inst.resolve.return_value = [mock_rdata]

    monkeypatch.setattr("dns.resolver.Resolver", lambda: mock_resolver_inst)
    sleep_mock = MagicMock()
    monkeypatch.setattr("time.sleep", sleep_mock)

    wait_for_dns(
        "_acme-challenge.example.com",
        "challenge-token-12345",
        interval=10,
        timeout=300,
    )

    assert mock_resolver_inst.resolve.call_count == 1
    sleep_mock.assert_not_called()


def test_r2_multiple_strings_in_rdata(monkeypatch):
    """Verify TXT record discovery when rdata contains multiple strings."""
    mock_rdata = MagicMock()
    mock_rdata.strings = [b"unrelated-token", b"target-token-xyz"]

    mock_resolver_inst = MagicMock()
    mock_resolver_inst.resolve.return_value = [mock_rdata]

    monkeypatch.setattr("dns.resolver.Resolver", lambda: mock_resolver_inst)
    sleep_mock = MagicMock()
    monkeypatch.setattr("time.sleep", sleep_mock)

    wait_for_dns(
        "_acme-challenge.example.com",
        "target-token-xyz",
        interval=5,
        timeout=60,
    )
    assert mock_resolver_inst.resolve.call_count == 1
    sleep_mock.assert_not_called()


def test_r2_instant_failure_timeout_zero(monkeypatch):
    """Empirically verify immediate failure when timeout is 0 or negative."""
    mock_resolver_inst = MagicMock()
    mock_resolver_inst.resolve.side_effect = dns.resolver.NXDOMAIN()

    monkeypatch.setattr("dns.resolver.Resolver", lambda: mock_resolver_inst)
    sleep_mock = MagicMock()
    monkeypatch.setattr("time.sleep", sleep_mock)

    with pytest.raises(TimeoutError, match="DNS propagation timed out"):
        wait_for_dns("_acme-challenge.fail.com", "token", interval=5, timeout=0)

    assert mock_resolver_inst.resolve.call_count == 1
    sleep_mock.assert_not_called()


def test_r2_max_retries_exact_limit(monkeypatch):
    """Empirically verify loop stops and raises TimeoutError after exactly max_retries attempts."""
    mock_resolver_inst = MagicMock()
    mock_resolver_inst.resolve.side_effect = dns.resolver.NoAnswer()

    monkeypatch.setattr("dns.resolver.Resolver", lambda: mock_resolver_inst)
    sleep_mock = MagicMock()
    monkeypatch.setattr("time.sleep", sleep_mock)

    with pytest.raises(TimeoutError, match=r"\(4 attempt\(s\)\)"):
        wait_for_dns(
            "_acme-challenge.fail.com",
            "token",
            interval=2,
            timeout=300,
            max_retries=4,
        )

    assert mock_resolver_inst.resolve.call_count == 4
    assert sleep_mock.call_count == 3  # Slept 3 times between 4 attempts


def test_r2_max_retries_one(monkeypatch):
    """Verify max_retries=1 terminates immediately on attempt 1 without sleeping."""
    mock_resolver_inst = MagicMock()
    mock_resolver_inst.resolve.side_effect = dns.resolver.NXDOMAIN()

    monkeypatch.setattr("dns.resolver.Resolver", lambda: mock_resolver_inst)
    sleep_mock = MagicMock()
    monkeypatch.setattr("time.sleep", sleep_mock)

    with pytest.raises(TimeoutError, match=r"\(1 attempt\(s\)\)"):
        wait_for_dns(
            "_acme-challenge.fail.com",
            "token",
            interval=10,
            timeout=300,
            max_retries=1,
        )

    assert mock_resolver_inst.resolve.call_count == 1
    sleep_mock.assert_not_called()


def test_r2_lifetime_timeout_resilience_and_recovery(monkeypatch):
    """Stress test: resolver raises LifetimeTimeout, then succeeds on retry 3."""
    mock_rdata = MagicMock()
    mock_rdata.strings = [b"recovered-token"]

    mock_resolver_inst = MagicMock()
    # Attempt 1: LifetimeTimeout, Attempt 2: generic Timeout, Attempt 3: Success
    mock_resolver_inst.resolve.side_effect = [
        dns.resolver.LifetimeTimeout("The resolution lifetime expired"),
        dns.exception.Timeout("Query timed out"),
        [mock_rdata],
    ]

    monkeypatch.setattr("dns.resolver.Resolver", lambda: mock_resolver_inst)
    sleep_mock = MagicMock()
    monkeypatch.setattr("time.sleep", sleep_mock)

    wait_for_dns(
        "_acme-challenge.recover.com",
        "recovered-token",
        interval=5,
        timeout=60,
        max_retries=5,
    )

    assert mock_resolver_inst.resolve.call_count == 3
    assert sleep_mock.call_count == 2


def test_r2_generic_dns_exception_handled(monkeypatch):
    """Verify generic DNSException is caught and does not cause an unhandled crash."""
    mock_resolver_inst = MagicMock()
    mock_resolver_inst.resolve.side_effect = [
        dns.exception.DNSException("Subsystem error"),
        dns.resolver.NoNameservers(),
    ]

    monkeypatch.setattr("dns.resolver.Resolver", lambda: mock_resolver_inst)
    sleep_mock = MagicMock()
    monkeypatch.setattr("time.sleep", sleep_mock)

    with pytest.raises(TimeoutError):
        wait_for_dns(
            "_acme-challenge.err.com",
            "token",
            interval=1,
            timeout=10,
            max_retries=2,
        )

    assert mock_resolver_inst.resolve.call_count == 2


def test_r2_txt_record_value_mismatch_retries(monkeypatch):
    """Verify that existing TXT record with wrong value does not count as success."""
    wrong_rdata = MagicMock()
    wrong_rdata.strings = [b"wrong-token-abc"]

    right_rdata = MagicMock()
    right_rdata.strings = [b"correct-token-xyz"]

    mock_resolver_inst = MagicMock()
    # Attempt 1 & 2: wrong token, Attempt 3: right token
    mock_resolver_inst.resolve.side_effect = [
        [wrong_rdata],
        [wrong_rdata],
        [right_rdata],
    ]

    monkeypatch.setattr("dns.resolver.Resolver", lambda: mock_resolver_inst)
    sleep_mock = MagicMock()
    monkeypatch.setattr("time.sleep", sleep_mock)

    wait_for_dns(
        "_acme-challenge.match.com", "correct-token-xyz", interval=5, timeout=60
    )
    assert mock_resolver_inst.resolve.call_count == 3
    assert sleep_mock.call_count == 2


# ==============================================================================
# R4 ADVERSARIAL TESTS: extract_domains_for_renewal & renew_certificate
# ==============================================================================


def test_r4_extract_domains_single_domain_no_duplicates():
    """Verify single domain extraction contains exactly 1 item with 0 duplicate identifiers."""
    cert_data = {"domain": "single.com", "domains": ["single.com"]}
    extracted = extract_domains_for_renewal(cert_data, "/tmp/single.com")
    assert extracted == ["single.com"]
    assert len(extracted) == 1


def test_r4_extract_domains_multi_san_preserved():
    """Verify multi-domain SANs with 5 distinct domains are preserved in order."""
    domain_list = [
        "main.example.org",
        "api.example.org",
        "auth.example.org",
        "billing.external.com",
        "status.internal.net",
    ]
    cert_data = {"domain": "main.example.org", "domains": domain_list}
    extracted = extract_domains_for_renewal(cert_data, "/tmp/main.example.org")
    assert extracted == domain_list


def test_r4_extract_domains_non_wildcard_lists():
    """Verify non-wildcard domain list is never altered or mangled by apex logic."""
    domain_list = ["foo.bar.baz.com", "service.sub.corp.ir"]
    cert_data = {"domain": "foo.bar.baz.com", "domains": domain_list}
    extracted = extract_domains_for_renewal(cert_data, "/tmp/foo.bar.baz.com")
    assert extracted == domain_list
    assert not any("*" in d for d in extracted)


def test_r4_extract_domains_deduplication():
    """Verify aggressive duplicate elimination while preserving initial order."""
    dirty_domains = [
        "app.com",
        "api.com",
        "app.com",
        "cdn.com",
        "api.com",
        "auth.com",
        "cdn.com",
    ]
    cert_data = {"domain": "app.com", "domains": dirty_domains}
    extracted = extract_domains_for_renewal(cert_data, "/tmp/app.com")
    assert extracted == ["app.com", "api.com", "cdn.com", "auth.com"]


def test_r4_extract_domains_empty_and_whitespace_cleaning():
    """Verify empty strings and whitespace-padded entries are cleaned up."""
    dirty_domains = ["  example.com  ", "", "   ", "api.example.com"]
    cert_data = {"domain": "example.com", "domains": dirty_domains}
    extracted = extract_domains_for_renewal(cert_data, "/tmp/example.com")
    assert extracted == ["example.com", "api.example.com"]


def test_r4_extract_domains_with_none_element():
    """Adversarial check: if domains contains None (e.g. from JSON null), str(None) becomes 'None'."""
    dirty_domains = ["example.com", None]
    cert_data = {"domain": "example.com", "domains": dirty_domains}
    extracted = extract_domains_for_renewal(cert_data, "/tmp/example.com")
    # str(None) evaluates to 'None', which is truthy and not empty
    assert "None" in extracted


def test_r4_extract_domains_fallback_to_cert_pem_san(
    tmp_path, cert_pem_factory
):
    """Verify fallback to cert.pem SAN extension when 'domains' key is missing."""
    cert_dir = tmp_path / "cert_folder"
    cert_dir.mkdir()
    cert_pem, key_pem = cert_pem_factory(["pem1.com", "pem2.com", "pem3.com"])

    cert_file = cert_dir / "cert.pem"
    cert_file.write_bytes(cert_pem)

    cert_data = {
        # 'domains' missing
        "domain": "pem1.com",
        "certificate_path": str(cert_file),
    }

    extracted = extract_domains_for_renewal(cert_data, str(cert_dir))
    assert extracted == ["pem1.com", "pem2.com", "pem3.com"]


def test_r4_extract_domains_fallback_to_cert_data_domain(tmp_path):
    """Verify fallback to cert_data['domain'] when cert.pem and domains list are missing."""
    cert_dir = tmp_path / "empty_folder"
    cert_dir.mkdir()

    cert_data = {
        "domain": "solitary.org",
        # No domains, no cert.pem
    }
    extracted = extract_domains_for_renewal(cert_data, str(cert_dir))
    assert extracted == ["solitary.org"]


def test_r4_extract_domains_all_missing_raises(tmp_path):
    """Verify RuntimeError is raised when domains cannot be determined anywhere."""
    cert_dir = tmp_path / "nowhere"
    cert_dir.mkdir()
    cert_data = {"domains": [], "domain": ""}

    with pytest.raises(
        RuntimeError, match="Could not determine domains for renewal"
    ):
        extract_domains_for_renewal(cert_data, str(cert_dir))


def test_r4_renew_certificate_folder_name_alignment(
    tmp_path, monkeypatch, cert_pem_factory
):
    """Stress test renew_certificate: ensure primary_domain is aligned with folder name."""
    home_dir = tmp_path / ".pyacme"
    home_dir.mkdir()
    monkeypatch.setattr("pyacmecli.acme.helper.PYACME_HOME_PATH", str(home_dir))

    # Folder is named 'admin.portal.com', but cert_data['domains'] has 'portal.com' first
    folder_domain = "admin.portal.com"
    cert_dir = home_dir / folder_domain
    cert_dir.mkdir()

    cert_pem, key_pem = cert_pem_factory([folder_domain, "portal.com"])
    (cert_dir / "cert.pem").write_bytes(cert_pem)
    (cert_dir / "privkey.pem").write_bytes(key_pem)
    (cert_dir / "account.key.pem").write_bytes(key_pem)
    (cert_dir / "account_url.result").write_text("https://acme.test/acct/999")

    cert_json_path = cert_dir / "certificate.json"
    cert_payload = {
        "domain": "portal.com",
        "domains": ["portal.com", folder_domain],  # folder_domain is second
        "certificate_path": str(cert_dir / "cert.pem"),
        "private_key_path": str(cert_dir / "privkey.pem"),
        "provider": "cloudflare",
        "provider_conf": "cf-token",
        "status": "valid",
    }
    with open(cert_json_path, "w", encoding="utf-8") as f:
        json.dump(cert_payload, f)

    captured_order_payload = {}

    # Mock ACME networking
    mock_session = MagicMock()
    monkeypatch.setattr("requests.Session", lambda: mock_session)
    monkeypatch.setattr(
        "pyacmecli.acme.helper.get_directory",
        lambda s, u: {
            "newNonce": "https://acme.test/nonce",
            "newOrder": "https://acme.test/new-order",
        },
    )

    def mock_post_jws(session, url, payload_obj, *args, **kwargs):
        nonlocal captured_order_payload
        resp = MagicMock()
        if "new-order" in url:
            captured_order_payload = payload_obj
            resp.status_code = 201
            resp.json.return_value = {
                "authorizations": [],
                "finalize": "https://acme.test/finalize",
            }
            resp.headers = {"Location": "https://acme.test/order/1"}
            return resp
        if "finalize" in url or "order" in url:
            resp.status_code = 200
            resp.json.return_value = {
                "status": "valid",
                "certificate": "https://acme.test/cert/1",
            }
            return resp
        resp.status_code = 200
        resp.json.return_value = {}
        return resp

    monkeypatch.setattr("pyacmecli.acme.helper.post_jws", mock_post_jws)

    mock_cert_resp = MagicMock()
    mock_cert_resp.text = cert_pem.decode("utf-8")
    mock_cert_resp.raise_for_status = MagicMock()
    mock_session.get.return_value = mock_cert_resp

    renew_certificate(str(cert_json_path))

    # Verify primary domain in ACME order was aligned with folder_domain ('admin.portal.com')
    identifiers = captured_order_payload.get("identifiers", [])
    assert len(identifiers) == 2
    assert identifiers[0] == {"type": "dns", "value": folder_domain}
    assert identifiers[1] == {"type": "dns", "value": "portal.com"}

    # Verify certificate.json updated with ordered_domains starting with folder_domain
    with open(cert_json_path, "r", encoding="utf-8") as f:
        updated_data = json.load(f)

    assert updated_data["domains"] == [folder_domain, "portal.com"]
    assert updated_data["status"] == "valid"


def test_r1_datetime_timezone_awareness_and_comparisons():
    """Ensure expiry_date and last_renewed handle UTC offsets and do not trigger TypeError."""
    cert = SSLCertificate(
        domain="time.example.com",
        certificate_path="/tmp/cert.pem",
        private_key_path="/tmp/privkey.pem",
        expiry_date="2026-12-31T23:59:59Z",
        renew_before_days=30,
        last_renewed="2026-01-01T00:00:00+00:00",
        renew_command="",
        status="valid",
        provider="dns",
        provider_conf="",
        email="",
    )
    assert cert.expiry_date.tzinfo is not None
    assert cert.last_renewed.tzinfo is not None
    # Must not raise TypeError: can't compare offset-naive and offset-aware datetimes
    assert isinstance(cert.needs_renewal(), bool)
    assert isinstance(cert.days_until_expiry(), int)


def test_r1_verify_private_key_match_corrupted_file(tmp_path):
    """Ensure verify_private_key_match handles corrupted key file gracefully without raising."""
    cert_file = tmp_path / "cert.pem"
    key_file = tmp_path / "privkey.pem"
    cert_file.write_text("NOT A VALID CERT")
    key_file.write_text("NOT A VALID KEY")

    cert = SSLCertificate(
        domain="corrupted.com",
        certificate_path=str(cert_file),
        private_key_path=str(key_file),
        expiry_date="2026-12-31T00:00:00Z",
        renew_before_days=30,
        last_renewed="2026-01-01T00:00:00Z",
        renew_command="",
        status="valid",
        provider="dns",
        provider_conf="",
        email="",
    )
    # Must return False rather than unhandled exception
    assert cert.verify_private_key_match() is False


def test_r1_from_pem_without_san_extension(tmp_path, session_rsa_key):
    """Test from_pem on a legacy certificate that only has CN and no SAN extension."""
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, "cn-only.example.com")]
            )
        )
        .issuer_name(
            x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, "cn-only.example.com")]
            )
        )
        .public_key(session_rsa_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.resolution)
        .sign(session_rsa_key, hashes.SHA256(), default_backend())
    )
    cert_file = tmp_path / "cn_cert.pem"
    key_file = tmp_path / "cn_key.pem"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        session_rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    obj = SSLCertificate.from_pem(
        cert_path=str(cert_file),
        key_path=str(key_file),
        provider="dns",
        provider_conf="",
    )
    assert obj.domain == "cn-only.example.com"
    assert obj.domains == ["cn-only.example.com"]
    assert isinstance(obj.status, str)


def test_r4_renew_certificate_missing_json_raises():
    """Verify renew_certificate raises RuntimeError if certificate.json does not exist."""
    with pytest.raises(
        RuntimeError, match="No certificate.json found at /non/existent/path"
    ):
        renew_certificate("/non/existent/path/certificate.json")
