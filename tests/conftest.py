"""Shared pytest fixtures for offline pyacme testing."""

import base64
import datetime
import json
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


@pytest.fixture(autouse=True)
def isolate_pyacme_home(tmp_path, monkeypatch):
    """Never let a test read or write the real ~/.pyacme (e.g. the lock)."""
    home_dir = str(tmp_path / "default-pyacme-home")
    monkeypatch.setattr("pyacmecli.acme.helper.PYACME_HOME_PATH", home_dir)
    monkeypatch.setattr("pyacmecli.__main__.PYACME_HOME_PATH", home_dir)
    return home_dir


@pytest.fixture(autouse=True)
def no_authoritative_dns_lookup(monkeypatch):
    """Keep tests offline: skip nameserver discovery unless a test opts in."""
    monkeypatch.setattr(
        "pyacmecli.acme.helper.find_authoritative_servers",
        lambda name: (name, None),
    )


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


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class FakeResponse:
    def __init__(self, status=200, body=None, text=None, headers=None):
        self.status_code = status
        self._body = body
        self.text = text if text is not None else json.dumps(body or {})
        self.headers = {
            "Replay-Nonce": "nonce-from-response",
            **(headers or {}),
        }

    def json(self):
        if self._body is None:
            raise ValueError("no JSON body")
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class FakeAcme:
    """In-memory ACME server behind a mocked requests.Session.

    Only the directory is fetched with GET; every other resource must be
    requested with a signed POST (or POST-as-GET), as RFC 8555 requires.
    """

    BASE = "https://acme.test"

    def __init__(self, cert_pem: bytes, authz_states=("pending", "valid")):
        self.cert_pem = cert_pem.decode()
        self.authz_states = list(authz_states)
        self.posts: list[tuple[str, dict | None]] = []
        self.identifiers: list[dict] = []
        self._authz_polls: dict[str, int] = {}
        self.session = MagicMock()
        self.session.get.side_effect = self._get
        self.session.head.side_effect = lambda url, **kw: FakeResponse(
            headers={"Replay-Nonce": "nonce-from-head"}
        )
        self.session.post.side_effect = self._post

    def directory(self) -> dict:
        b = self.BASE
        return {
            "newNonce": f"{b}/nonce",
            "newAccount": f"{b}/new-account",
            "newOrder": f"{b}/new-order",
            "revokeCert": f"{b}/revoke",
        }

    def _get(self, url, **kwargs):
        if url.endswith("/directory"):
            return FakeResponse(body=self.directory())
        raise AssertionError(f"unexpected GET {url}; use POST-as-GET")

    def payloads(self, suffix: str) -> list:
        return [p for url, p in self.posts if url.endswith(suffix)]

    def _post(self, url, json=None, **kwargs):
        payload = _b64d(json["payload"]) if json["payload"] else None
        payload = __import__("json").loads(payload) if payload else None
        self.posts.append((url, payload))
        b = self.BASE
        path = url.removeprefix(b)
        if path == "/new-account":
            return FakeResponse(201, {}, headers={"Location": f"{b}/acct/1"})
        if path == "/new-order":
            self.identifiers = payload["identifiers"]
            body = {
                "status": "pending",
                "authorizations": [
                    f"{b}/authz/{i}" for i in range(len(self.identifiers))
                ],
                "finalize": f"{b}/finalize/1",
            }
            return FakeResponse(201, body, headers={"Location": f"{b}/order/1"})
        if path.startswith("/authz/"):
            assert payload is None, "authz must be fetched with POST-as-GET"
            idx = int(path.rsplit("/", 1)[1])
            n = self._authz_polls.get(path, 0)
            self._authz_polls[path] = n + 1
            state = self.authz_states[min(n, len(self.authz_states) - 1)]
            ident = self.identifiers[idx]["value"]
            return FakeResponse(
                body={
                    "status": state,
                    "identifier": {
                        "type": "dns",
                        "value": ident.removeprefix("*."),
                    },
                    "challenges": [
                        {
                            "type": "dns-01",
                            "token": f"token-{idx}",
                            "url": f"{b}/chall/{idx}",
                        }
                    ],
                }
            )
        if path.startswith("/chall/"):
            return FakeResponse(body={"status": "processing"})
        if path.startswith("/finalize/"):
            return FakeResponse(body={"status": "processing"})
        if path.startswith("/order/"):
            return FakeResponse(
                body={"status": "valid", "certificate": f"{b}/cert/1"}
            )
        if path.startswith("/cert/"):
            assert payload is None, "cert must be fetched with POST-as-GET"
            return FakeResponse(text=self.cert_pem)
        if path == "/revoke":
            return FakeResponse(body={})
        raise AssertionError(f"unexpected POST {url}")


@pytest.fixture
def fake_acme(monkeypatch):
    """Factory: install a FakeAcme as requests.Session and the directory."""

    def _make(cert_pem: bytes, **kwargs) -> FakeAcme:
        fake = FakeAcme(cert_pem, **kwargs)
        monkeypatch.setattr("requests.Session", lambda: fake.session)
        monkeypatch.setattr(
            "pyacmecli.acme.helper.get_directory_url",
            lambda staging=False, custom_url=None: f"{FakeAcme.BASE}/directory",
        )
        return fake

    return _make
