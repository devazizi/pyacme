"""Tests for SSLCertificate and PEM parsing in pyacmecli.tls.ssl_object."""

import datetime
from datetime import timezone
import json

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from pyacmecli.tls.ssl_object import SSLCertificate


def test_ssl_certificate_status_is_str():
    """Verify R1: self.status is a string, not a single-element tuple."""
    cert = SSLCertificate(
        domain="example.com",
        certificate_path="/tmp/cert.pem",
        private_key_path="/tmp/privkey.pem",
        expiry_date="2027-01-01T00:00:00Z",
        renew_before_days=30,
        last_renewed="2026-01-01T00:00:00Z",
        renew_command="systemctl reload nginx",
        status="valid",
        provider="cloudflare",
        provider_conf="token123",
        email="admin@example.com",
    )
    assert isinstance(cert.status, str)
    assert cert.status == "valid"
    assert not isinstance(cert.status, (tuple, list))


def test_ssl_certificate_status_unpack_tuple():
    """Verify backward compatibility: if status is passed as tuple/list, it is unpacked to str."""
    cert = SSLCertificate(
        domain="example.com",
        certificate_path="/tmp/cert.pem",
        private_key_path="/tmp/privkey.pem",
        expiry_date="2027-01-01T00:00:00Z",
        renew_before_days=30,
        last_renewed="2026-01-01T00:00:00Z",
        renew_command="",
        status=("valid",),  # Legacy bug format
        provider="dns",
        provider_conf=None,
        email="admin@example.com",
    )
    assert isinstance(cert.status, str)
    assert cert.status == "valid"


def test_ssl_certificate_save_load_roundtrip(tmp_path):
    """Verify SSLCertificate.save and SSLCertificate.open roundtrip cleanly."""
    json_path = str(tmp_path / "certificate.json")
    cert = SSLCertificate(
        domain="app.example.com",
        certificate_path="/etc/ssl/cert.pem",
        private_key_path="/etc/ssl/privkey.pem",
        expiry_date="2027-06-15T12:00:00Z",
        renew_before_days=30,
        last_renewed="2026-06-15T12:00:00Z",
        renew_command="touch /tmp/renewed",
        status="valid",
        provider="arvancloud",
        provider_conf="secret",
        email="ops@example.com",
        domains=["app.example.com", "api.example.com"],
        staging=True,
    )
    cert.save(json_path)

    # Inspect raw JSON on disk
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["status"] == "valid"
    assert isinstance(data["status"], str)
    assert data["domains"] == ["app.example.com", "api.example.com"]
    assert data["staging"] is True

    # Reopen and check object
    loaded = SSLCertificate.open(json_path)
    assert isinstance(loaded.status, str)
    assert loaded.status == "valid"
    assert loaded.domain == "app.example.com"
    assert loaded.domains == ["app.example.com", "api.example.com"]
    assert loaded.staging is True
    assert loaded.provider == "arvancloud"


def test_ssl_certificate_save_missing_path_raises():
    """Verify save() raises ValueError when no file_path is provided."""
    cert = SSLCertificate(
        domain="example.com",
        certificate_path="",
        private_key_path="",
        expiry_date="2027-01-01T00:00:00Z",
        renew_before_days=30,
        last_renewed="2026-01-01T00:00:00Z",
        renew_command="",
        status="valid",
        provider="dns",
        provider_conf=None,
        email="test@example.com",
    )
    with pytest.raises(ValueError, match="File path must be provided to save"):
        cert.save(None)


def test_ssl_certificate_needs_renewal_and_days_until_expiry():
    """Verify renewal trigger and days_until_expiry calculation."""
    now = datetime.datetime.now(timezone.utc)
    future_exp = (
        (now + datetime.timedelta(days=10)).isoformat().replace("+00:00", "Z")
    )
    far_exp = (
        (now + datetime.timedelta(days=60)).isoformat().replace("+00:00", "Z")
    )

    expiring_soon = SSLCertificate(
        domain="soon.example.com",
        certificate_path="",
        private_key_path="",
        expiry_date=future_exp,
        renew_before_days=30,
        last_renewed=now.isoformat().replace("+00:00", "Z"),
        renew_command="",
        status="valid",
        provider="dns",
        provider_conf=None,
        email="",
    )
    assert expiring_soon.needs_renewal() is True
    assert 9 <= expiring_soon.days_until_expiry() <= 10

    not_expiring = SSLCertificate(
        domain="far.example.com",
        certificate_path="",
        private_key_path="",
        expiry_date=far_exp,
        renew_before_days=30,
        last_renewed=now.isoformat().replace("+00:00", "Z"),
        renew_command="",
        status="valid",
        provider="dns",
        provider_conf=None,
        email="",
    )
    assert not_expiring.needs_renewal() is False
    assert 59 <= not_expiring.days_until_expiry() <= 60


def test_ssl_certificate_repr():
    """Verify __repr__ formats status as string and does not fail."""
    cert = SSLCertificate(
        domain="example.com",
        certificate_path="",
        private_key_path="",
        expiry_date="2027-01-01T00:00:00Z",
        renew_before_days=30,
        last_renewed="2026-01-01T00:00:00Z",
        renew_command="",
        status="valid",
        provider="dns",
        provider_conf=None,
        email="",
    )
    rep = repr(cert)
    assert "<SSLCertificate" in rep
    assert "domain=example.com" in rep
    assert "status=valid" in rep
    assert "status=('valid',)" not in rep


def test_ssl_certificate_from_pem(tmp_path, cert_pem_factory):
    """Verify SSLCertificate.from_pem loads SAN domains and valid status as str."""
    domains = ["web.example.com", "api.example.com"]
    cert_pem, key_pem = cert_pem_factory(domains, expires_in_days=45)

    cert_path = str(tmp_path / "cert.pem")
    key_path = str(tmp_path / "privkey.pem")
    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    with open(key_path, "wb") as f:
        f.write(key_pem)

    cert_obj = SSLCertificate.from_pem(
        cert_path=cert_path,
        key_path=key_path,
        provider="cloudflare",
        provider_conf="cf-token",
        renew_before_days=20,
        renew_command="reload.sh",
        email="admin@example.com",
    )
    assert cert_obj.domain == "web.example.com"
    assert cert_obj.domains == ["web.example.com", "api.example.com"]
    assert isinstance(cert_obj.status, str)
    assert cert_obj.status == "valid"
    assert cert_obj.verify_private_key_match() is True


def test_ssl_certificate_verify_private_key_mismatch(
    tmp_path, cert_pem_factory
):
    """Verify key mismatch returns False."""
    cert_pem, _ = cert_pem_factory(["example.com"])
    # Generate a different key
    other_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    other_key_pem = other_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_path = str(tmp_path / "cert.pem")
    key_path = str(tmp_path / "other.pem")
    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    with open(key_path, "wb") as f:
        f.write(other_key_pem)

    cert_obj = SSLCertificate.from_pem(
        cert_path=cert_path,
        key_path=key_path,
        provider="dns",
        provider_conf=None,
    )
    assert cert_obj.verify_private_key_match() is False
