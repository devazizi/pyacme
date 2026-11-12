"""Tests for certificate key generation, rotation and installation."""

import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from pyacmecli.acme import helper


@pytest.mark.parametrize(
    ("key_type", "kind", "size"),
    [
        ("rsa2048", rsa.RSAPrivateKey, 2048),
        ("ec256", ec.EllipticCurvePrivateKey, 256),
    ],
)
def test_generate_private_key(key_type, kind, size):
    key = helper.generate_private_key(key_type)
    assert isinstance(key, kind)
    assert key.key_size == size


def test_generate_private_key_rejects_unknown_type():
    with pytest.raises(ValueError, match="Unsupported key type"):
        helper.generate_private_key("dsa1024")


def test_install_certificate_rotates_and_keeps_previous_pair(
    temp_pyacme_home, cert_pem_factory
):
    domain_dir = os.path.join(temp_pyacme_home, "example.com")
    os.makedirs(domain_dir)
    old_cert, old_key = cert_pem_factory(["example.com"])
    with open(os.path.join(domain_dir, "cert.pem"), "wb") as f:
        f.write(old_cert)
    with open(os.path.join(domain_dir, "privkey.pem"), "wb") as f:
        f.write(old_key)

    new_key = helper.generate_private_key("ec256")
    cert_path = helper.install_certificate(
        "example.com", "NEW-CERT-PEM\n", new_key
    )

    def read(name):
        with open(os.path.join(domain_dir, name), "rb") as f:
            return f.read()

    def mode(name):
        return os.stat(os.path.join(domain_dir, name)).st_mode & 0o777

    assert cert_path == os.path.join(domain_dir, "cert.pem")
    assert read("cert.pem") == b"NEW-CERT-PEM\n"
    assert read("cert.pem.prev") == old_cert
    assert read("privkey.pem.prev") == old_key
    loaded = serialization.load_pem_private_key(read("privkey.pem"), None)
    assert loaded.public_key().public_numbers() == (
        new_key.public_key().public_numbers()
    )
    assert mode("privkey.pem") == 0o600
    assert mode("privkey.pem.prev") == 0o600
    assert mode("cert.pem") == 0o644
