"""ACME protocol client (RFC 8555): JWS signing, nonces and resources.

AcmeClient bundles what every ACME request needs (HTTP session, directory,
account key, account URL and the current nonce) so the certificate flows
in operations.py do not thread five values through every call.
"""

import base64
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from pyacmecli.happylog import LOG

LETSENCRYPT_PRODUCTION_DIRECTORY = (
    "https://acme-v02.api.letsencrypt.org/directory"
)
LETSENCRYPT_STAGING_DIRECTORY = (
    "https://acme-staging-v02.api.letsencrypt.org/directory"
)
DEFAULT_DIRECTORY_URL = LETSENCRYPT_PRODUCTION_DIRECTORY
DIRECTORY_ADDRESS = DEFAULT_DIRECTORY_URL

# Upper bound for polling the CA after a challenge or finalize request.
ACME_POLL_INTERVAL = 2
ACME_POLL_ATTEMPTS = 150  # 150 * 2s = 5 minutes
# RFC 8555 7.1.6: none of these authorization states can become valid.
AUTHZ_FAILED_STATES = ("invalid", "deactivated", "expired", "revoked")

# Longest Retry-After pyacme waits for inline; longer back-offs (typically
# rate limits measured in hours) fail fast so cron can report them.
MAX_INLINE_RETRY_AFTER = 60

JSON = dict[str, Any]


def get_directory_url(
    staging: bool = False, custom_url: str | None = None
) -> str:
    """Return the ACME directory URL based on staging flag or custom URL."""
    if custom_url:
        return custom_url
    return (
        LETSENCRYPT_STAGING_DIRECTORY
        if staging
        else LETSENCRYPT_PRODUCTION_DIRECTORY
    )


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def int_to_b64u(n: int) -> str:
    length = (n.bit_length() + 7) // 8 or 1
    return b64u(n.to_bytes(length, "big"))


def jwk_from_privkey(privkey: rsa.RSAPrivateKey) -> dict[str, str]:
    """Build a JWK from an RSA private key for ACME requests."""
    nums = privkey.public_key().public_numbers()
    return {"kty": "RSA", "n": int_to_b64u(nums.n), "e": int_to_b64u(nums.e)}


def thumbprint(jwk: dict[str, str]) -> str:
    """RFC 7638 JWK thumbprint, used in key authorizations."""
    jwk_json = json.dumps(
        {"e": jwk["e"], "kty": jwk["kty"], "n": jwk["n"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    return b64u(hashlib.sha256(jwk_json.encode("utf8")).digest())


def get_directory(session: requests.Session, directory_url: str) -> JSON:
    """Fetch and return the ACME directory JSON."""
    r = session.get(directory_url, timeout=10)
    r.raise_for_status()
    directory: JSON = r.json()
    return directory


def get_nonce(session: requests.Session, new_nonce_url: str) -> str:
    r = session.head(new_nonce_url, timeout=10)
    nonce = r.headers.get("Replay-Nonce")
    if not nonce:
        r = session.get(new_nonce_url, timeout=10)
        nonce = r.headers.get("Replay-Nonce")
    if not nonce:
        raise RuntimeError("No Replay-Nonce returned by server")
    return str(nonce)


class AcmeError(RuntimeError):
    """An ACME request failed; carries the RFC 7807 problem document."""

    def __init__(self, url: str, status: int, problem: JSON) -> None:
        self.url = url
        self.status = status
        self.problem = problem
        self.type = str(problem.get("type", ""))
        self.detail = str(problem.get("detail", ""))
        super().__init__(
            f"ACME request to {url} failed with HTTP {status}: "
            f"{self.type or 'no problem type'} {self.detail}".rstrip()
        )


def make_jws(
    privkey: rsa.RSAPrivateKey,
    payload_obj: JSON | None,
    url: str,
    nonce: str,
    jwk: dict[str, str] | None = None,
    kid: str | None = None,
) -> dict[str, str]:
    """Build a flattened JWS; payload_obj None makes a POST-as-GET body."""
    payload64 = (
        "" if payload_obj is None else b64u(json.dumps(payload_obj).encode())
    )
    protected: JSON = {"alg": "RS256", "nonce": nonce, "url": url}
    if jwk:
        protected["jwk"] = jwk
    else:
        protected["kid"] = kid
    protected64 = b64u(json.dumps(protected, separators=(",", ":")).encode())
    signing_input = f"{protected64}.{payload64}".encode("ascii")
    signature = privkey.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return {
        "protected": protected64,
        "payload": payload64,
        "signature": b64u(signature),
    }


def _retry_after_seconds(resp: requests.Response) -> float | None:
    """Parse a Retry-After header (seconds or HTTP date)."""
    value = resp.headers.get("Retry-After")
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    if value.isdigit():
        return float(value)
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


def post_jws(
    session: requests.Session,
    url: str,
    payload_obj: JSON | None,
    privkey: rsa.RSAPrivateKey,
    new_nonce_url: str,
    jwk: dict[str, str] | None = None,
    kid: str | None = None,
    max_retries: int = 5,
    nonces: list[str] | None = None,
) -> requests.Response:
    """POST a signed request; retry only what RFC 8555 says is retryable.

    badNonce is retried with the fresh nonce the server returned. A 503 or
    rateLimited response is retried only when Retry-After is short. Every
    other error raises AcmeError at once instead of being resent blindly.

    nonces is an optional pool: a nonce is taken from it before falling back
    to newNonce, and every Replay-Nonce the server returns is put back, so a
    caller that keeps the list (AcmeClient) saves one round trip per request.
    """
    pool = nonces if nonces is not None else []
    for attempt in range(1, max_retries + 1):
        nonce = pool.pop() if pool else get_nonce(session, new_nonce_url)
        jws = make_jws(privkey, payload_obj, url, nonce, jwk=jwk, kid=kid)
        r = session.post(
            url,
            json=jws,
            headers={"Content-Type": "application/jose+json"},
            timeout=30,
        )
        replay_nonce = r.headers.get("Replay-Nonce")
        if isinstance(replay_nonce, str):
            pool.append(replay_nonce)

        if 200 <= r.status_code < 300:
            return r

        try:
            problem = r.json()
        except ValueError:
            problem = {}
        if not isinstance(problem, dict):
            problem = {}
        error = AcmeError(url, r.status_code, problem)

        if attempt == max_retries:
            raise error
        if error.type.endswith(":badNonce"):
            LOG.debug(f"badNonce from {url}; retrying ({attempt})")
            continue
        retry_after = _retry_after_seconds(r)
        if (
            r.status_code == 503 or error.type.endswith(":rateLimited")
        ) and retry_after is not None:
            if retry_after <= MAX_INLINE_RETRY_AFTER:
                LOG.warning(
                    f"{url} asked to retry after {retry_after:.0f}s; waiting"
                )
                time.sleep(retry_after)
                continue
            raise AcmeError(
                url,
                r.status_code,
                {
                    **problem,
                    "detail": f"{error.detail} (retry after "
                    f"{retry_after:.0f}s)".strip(),
                },
            )
        raise error

    raise RuntimeError("unreachable: max_retries must be at least 1")


def post_as_get(
    session: requests.Session,
    url: str,
    privkey: rsa.RSAPrivateKey,
    new_nonce_url: str,
    account_url: str,
) -> requests.Response:
    """Fetch an ACME resource with POST-as-GET (RFC 8555 6.3)."""
    return post_jws(session, url, None, privkey, new_nonce_url, kid=account_url)


@dataclass
class Order:
    """An ACME order as returned by newOrder."""

    url: str
    authorizations: list[str]
    finalize_url: str
    data: JSON = field(default_factory=dict)


class AcmeClient:
    """One ACME account talking to one CA directory."""

    def __init__(
        self,
        session: requests.Session,
        directory: JSON,
        key: rsa.RSAPrivateKey,
        account_url: str | None = None,
    ) -> None:
        self.session = session
        self.directory = directory
        self.key = key
        self.account_url = account_url
        self.jwk = jwk_from_privkey(key)
        self._nonces: list[str] = []

    @classmethod
    def connect(
        cls,
        directory_url: str,
        key: rsa.RSAPrivateKey,
        account_url: str | None = None,
    ) -> "AcmeClient":
        """Fetch the directory of directory_url and return a client for it."""
        session = requests.Session()
        return cls(
            session, get_directory(session, directory_url), key, account_url
        )

    def _post(
        self, url: str, payload: JSON | None, use_jwk: bool = False
    ) -> requests.Response:
        if not use_jwk and not self.account_url:
            raise RuntimeError("ACME account is not registered yet")
        return post_jws(
            self.session,
            url,
            payload,
            self.key,
            self.directory["newNonce"],
            jwk=self.jwk if use_jwk else None,
            kid=None if use_jwk else self.account_url,
            nonces=self._nonces,
        )

    def post(self, url: str, payload: JSON) -> requests.Response:
        """Signed POST with the account URL as key ID."""
        return self._post(url, payload)

    def post_as_get(self, url: str) -> requests.Response:
        """Fetch a resource with POST-as-GET (RFC 8555 6.3)."""
        return self._post(url, None)

    def register(self, email: str) -> str:
        """Create (or look up) the account for this key; return its URL."""
        resp = self._post(
            self.directory["newAccount"],
            {"termsOfServiceAgreed": True, "contact": [f"mailto:{email}"]},
            use_jwk=True,
        )
        account_url = resp.headers.get("Location")
        if not account_url:
            raise RuntimeError(f"CA returned no account URL: {resp.text}")
        self.account_url = account_url
        return account_url

    def new_order(self, domains: list[str]) -> Order:
        resp = self.post(
            self.directory["newOrder"],
            {"identifiers": [{"type": "dns", "value": d} for d in domains]},
        )
        data: JSON = resp.json()
        order_url = resp.headers.get("Location")
        if not order_url:
            raise RuntimeError(f"No order URL returned: {data}")
        LOG.info(f"Order URL: {order_url}")
        return Order(
            url=order_url,
            authorizations=list(data.get("authorizations", [])),
            finalize_url=data.get("finalize", ""),
            data=data,
        )

    def get_authorization(self, authz_url: str) -> JSON:
        authz: JSON = self.post_as_get(authz_url).json()
        return authz

    def key_authorization_digest(self, token: str) -> str:
        """TXT value for a dns-01 challenge token (RFC 8555 8.4)."""
        key_auth = f"{token}.{thumbprint(self.jwk)}"
        return b64u(hashlib.sha256(key_auth.encode()).digest())

    def answer_challenge(self, challenge_url: str) -> None:
        self.post(challenge_url, {})

    def wait_for_authorization(self, authz_url: str, domain: str) -> None:
        """Poll until the authorization is valid; raise if it fails."""
        status = "pending"
        for _ in range(ACME_POLL_ATTEMPTS):
            time.sleep(ACME_POLL_INTERVAL)
            authz = self.get_authorization(authz_url)
            status = authz["status"]
            if status == "valid":
                return
            if status in AUTHZ_FAILED_STATES:
                errors = [
                    c["error"]
                    for c in authz.get("challenges", [])
                    if c.get("type") == "dns-01" and c.get("error")
                ]
                raise RuntimeError(
                    f"Authorization for {domain} is {status}: {errors or authz}"
                )
        raise TimeoutError(
            f"Authorization for {domain} still '{status}' after "
            f"{ACME_POLL_ATTEMPTS * ACME_POLL_INTERVAL}s"
        )

    def finalize(self, order: Order, csr_der: bytes) -> str:
        """Submit the CSR, wait for issuance and return the PEM chain."""
        self.post(order.finalize_url, {"csr": b64u(csr_der)})

        status = "processing"
        for _ in range(ACME_POLL_ATTEMPTS):
            time.sleep(ACME_POLL_INTERVAL)
            data: JSON = self.post_as_get(order.url).json()
            status = data["status"]
            LOG.info(f"Order status: {status}")
            if status == "valid":
                break
            if status == "invalid":
                raise RuntimeError(f"Order finalization failed: {data}")
        else:
            raise TimeoutError(
                f"Order {order.url} still '{status}' after "
                f"{ACME_POLL_ATTEMPTS * ACME_POLL_INTERVAL}s"
            )

        cert_url = data.get("certificate")
        if not cert_url:
            raise RuntimeError(
                "Certificate URL not returned after finalization"
            )
        return self.post_as_get(cert_url).text

    def revoke(self, certificate_der: bytes, reason: int = 0) -> None:
        revoke_url = self.directory.get("revokeCert")
        if not revoke_url:
            raise RuntimeError("Directory does not specify revokeCert endpoint")
        self.post(
            revoke_url, {"certificate": b64u(certificate_der), "reason": reason}
        )
