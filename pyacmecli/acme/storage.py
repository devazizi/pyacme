"""On-disk layout under the pyacme home directory (default ~/.pyacme).

Every path is derived from PYACME_HOME_PATH at call time, so tests and
callers can redirect the whole store by patching that one attribute.
"""

import os
import re
import shutil
from contextlib import AbstractContextManager
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from validators import domain as domain_validator

from pyacmecli.common.fsutil import (
    PRIVATE_FILE_MODE,
    PUBLIC_FILE_MODE,
    exclusive_lock,
    write_atomic,
    write_private_file,
)
from pyacmecli.happylog import LOG

PYACME_HOME_PATH = os.path.expanduser("~/.pyacme")

# Shared ACME accounts live under accounts/<directory host and path>, one per
# CA directory, so staging and production never share an account.
ACCOUNT_DIR_RE = re.compile(r"accounts/(?!\.{1,2}$)[A-Za-z0-9._-]+")


def home() -> str:
    """Return the current pyacme home directory."""
    return PYACME_HOME_PATH


def init_dir() -> None:
    """Create the pyacme home directory if it does not exist."""
    os.makedirs(home(), exist_ok=True)


def validate_domain_name(name: str) -> str:
    """Return name if it is a DNS name (a leading '*.' is allowed).

    Domain names are used as directory names under the home directory, so
    this is also what keeps '..', absolute paths and empty names out of file
    paths.
    """
    candidate = name[2:] if name.startswith("*.") else name
    if not domain_validator(candidate):
        raise ValueError(f"Invalid domain name: {name!r}")
    return name


def certificate_dir(domain: str) -> str:
    """Return the storage directory of a certificate, rejecting unsafe names."""
    return os.path.join(home(), validate_domain_name(domain))


def pyacme_lock() -> AbstractContextManager[None]:
    """Serialize state-changing runs (new, cron, revoke, delete).

    Two overlapping runs would otherwise race on the same key, certificate
    and _acme-challenge TXT record.
    """
    return exclusive_lock(os.path.join(home(), ".lock"))


def load_or_make_rsa_key(
    file_name: str | None = None, bits: int = 2048
) -> rsa.RSAPrivateKey:
    """Load an RSA key relative to the home directory, creating it if absent."""
    init_dir()
    path = os.path.join(home(), file_name or "account.key.pem")
    os.makedirs(os.path.dirname(path), exist_ok=True)

    if os.path.exists(path):
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise RuntimeError(f"{path} is not an RSA private key")
        return key

    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    write_private_file(path, pem)
    LOG.info(f"Generated new RSA key: {path}")
    return key


def account_dir_for(directory_url: str) -> str:
    """Return the account directory (relative to home) for a CA directory."""
    parts = urlsplit(directory_url)
    slug = re.sub(r"[^A-Za-z0-9.-]+", "_", f"{parts.netloc}{parts.path}")
    slug = slug.strip("_.")
    if not slug:
        raise ValueError(
            f"Cannot derive an account name from {directory_url!r}"
        )
    return f"accounts/{slug}"


def account_directory_url(account_dir: str) -> str:
    """Return the stored account URL for account_dir.

    Raises RuntimeError if the account was never registered.
    """
    path = os.path.join(home(), account_dir, "account_url.result")
    if not os.path.exists(path):
        raise RuntimeError(
            f"ACME account URL file for '{account_dir}' not found. "
            "You must create an account first."
        )
    with open(path, encoding="utf-8") as f:
        return f.read().strip()


def save_account_url(account_dir: str, account_url: str) -> None:
    """Persist the account URL returned by the CA at registration."""
    write_private_file(
        os.path.join(home(), account_dir, "account_url.result"), account_url
    )


def resolve_account_dir(cert_data: dict[str, object], legacy_dir: str) -> str:
    """Account directory recorded for a certificate, else its legacy one."""
    stored = cert_data.get("account")
    if not stored:
        return legacy_dir
    if not ACCOUNT_DIR_RE.fullmatch(str(stored)):
        raise RuntimeError(f"Invalid account reference in metadata: {stored!r}")
    return str(stored)


def install_certificate(
    domain_dir_name: str,
    certificate_pem: str,
    private_key: CertificateIssuerPrivateKeyTypes,
) -> str:
    """Store a newly issued certificate and its key; return the cert path.

    The previous pair is kept as cert.pem.prev / privkey.pem.prev for manual
    rollback. Each file is replaced atomically, the key before the
    certificate; the renew command that reloads the server runs only after
    both are in place.
    """
    domain_dir = os.path.join(home(), domain_dir_name)
    cert_path = os.path.join(domain_dir, "cert.pem")
    key_path = os.path.join(domain_dir, "privkey.pem")

    for path, mode in (
        (cert_path, PUBLIC_FILE_MODE),
        (key_path, PRIVATE_FILE_MODE),
    ):
        if os.path.exists(path):
            with open(path, "rb") as f:
                write_atomic(f"{path}.prev", f.read(), mode)

    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    write_private_file(key_path, key_pem)
    write_atomic(cert_path, certificate_pem, PUBLIC_FILE_MODE)
    return cert_path


def delete_certificate_data(domain: str) -> bool:
    """Delete a certificate directory; return False if it did not exist."""
    domain_dir = certificate_dir(domain)
    if not os.path.exists(domain_dir):
        return False
    shutil.rmtree(domain_dir)
    return True
