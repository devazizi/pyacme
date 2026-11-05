"""Tests for certificate listing utilities in pyacmecli.common.certificates."""

import json

import pytest

from pyacmecli.common.certificates import (
    CertificateListItem,
    get_certificate_list,
)


def test_get_certificate_list_empty(tmp_path):
    """Verify empty list when directory contains no certificate.json files."""
    certs = get_certificate_list(str(tmp_path))
    assert certs == []


def test_get_certificate_list_multiple(tmp_path):
    """Verify collecting certificates from multiple directories."""
    dir1 = tmp_path / "site1.com"
    dir2 = tmp_path / "site2.com"
    dir1.mkdir()
    dir2.mkdir()

    data1 = {
        "domain": "site1.com",
        "certificate_path": str(dir1 / "cert.pem"),
        "expiry_date": "2026-12-01T00:00:00Z",
        "status": "valid",
        "renew_command": "nginx -s reload",
        "last_renewed": "2025-12-01T00:00:00Z",
    }
    data2 = {
        "domain": "site2.com",
        "certificate_path": str(dir2 / "cert.pem"),
        "expiry_date": "2027-01-01T00:00:00Z",
        "status": "valid",
        "renew_command": "",
        "last_renewed": "2026-01-01T00:00:00Z",
    }

    with open(str(dir1 / "certificate.json"), "w") as f:
        json.dump(data1, f)
    with open(str(dir2 / "certificate.json"), "w") as f:
        json.dump(data2, f)

    certs = get_certificate_list(str(tmp_path))
    assert len(certs) == 2
    domains = {c.domain for c in certs}
    assert domains == {"site1.com", "site2.com"}
    assert all(isinstance(c, CertificateListItem) for c in certs)


def test_get_certificate_list_invalid_json(tmp_path):
    """Verify json.JSONDecodeError is raised if certificate.json is corrupted."""
    bad_dir = tmp_path / "bad.com"
    bad_dir.mkdir()
    with open(str(bad_dir / "certificate.json"), "w") as f:
        f.write("{invalid json...")

    with pytest.raises(json.JSONDecodeError):
        get_certificate_list(str(tmp_path))
