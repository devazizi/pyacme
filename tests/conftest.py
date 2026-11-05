"""Shared pytest fixtures for offline pyacme testing."""

import datetime
from datetime import timezone
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pyacmecli.happylog import remove_file_handlers


@pytest.fixture(autouse=True)
def clean_logger():
    """Ensure file handlers are cleaned up between tests."""
    remove_file_handlers()
    yield
    remove_file_handlers()


@pytest.fixture
def mock_sleep(monkeypatch):
    """Eliminate all sleep calls to ensure tests run instantly."""
    mock = MagicMock()
    monkeypatch.setattr("time.sleep", mock)
    return mock


@pytest.fixture
def temp_pyacme_home(tmp_path, monkeypatch):
    """Isolate tests from ~/.pyacme using a temporary directory."""
    home_dir = str(tmp_path / ".pyacme")
    monkeypatch.setattr("pyacmecli.acme.helper.PYACME_HOME_PATH", home_dir)
    monkeypatch.setattr("pyacmecli.__main__.PYACME_HOME_PATH", home_dir)
    return home_dir


@pytest.fixture(scope="session")
def session_rsa_key():
    """Generate a single RSA key for the test session to save CPU time."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )


@pytest.fixture
def cert_pem_factory(session_rsa_key):
    """Factory fixture to generate valid X.509 PEM certificates with custom SANs & expiry."""

    def _create(domains, expires_in_days=90):
        key = session_rsa_key
        common_name = domains[0]
        san_list = [x509.DNSName(d) for d in domains]

        now = datetime.datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
                )
            )
            .issuer_name(
                x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
                )
            )
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=expires_in_days))
            .add_extension(
                x509.SubjectAlternativeName(san_list), critical=False
            )
            .sign(key, hashes.SHA256(), default_backend())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return cert_pem, key_pem

    return _create
