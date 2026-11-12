"""ACME protocol helpers: account creation, JWS, DNS-01 challenge, order finalization."""

import base64
import hashlib
import json
import os
import time
import weakref
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import dns.exception
import dns.resolver
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import NameOID
from validators import domain as domain_validator

from pyacmecli.common.fsutil import (
    PUBLIC_FILE_MODE,
    exclusive_lock,
    write_atomic,
    write_private_file,
)
from pyacmecli.happylog import LOG
from pyacmecli.tls.ssl_object import SSLCertificate
from pyacmecli.webhooks.acmedns import AcmeDNS
from pyacmecli.webhooks.arvancloud import ArvanCloud
from pyacmecli.webhooks.base import Base
from pyacmecli.webhooks.cloudflare import Cloudflare
from pyacmecli.webhooks.digitalocean import DigitalOcean
from pyacmecli.webhooks.hetzner import Hetzner
from pyacmecli.webhooks.ovh import OVH
from pyacmecli.webhooks.powerdns import PowerDNS
from pyacmecli.webhooks.route53 import Route53

PYACME_HOME_PATH = os.path.expanduser("~/.pyacme")
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

# Certificate key types. rsa2048 stays the default for client compatibility.
DEFAULT_KEY_TYPE = "rsa2048"
KEY_TYPES = ("rsa2048", "rsa4096", "ec256", "ec384")


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


def validate_domain_name(name: str) -> str:
    """Return name if it is a DNS name (a leading '*.' is allowed).

    Domain names are used as directory names under PYACME_HOME_PATH, so this
    is also what keeps '..', absolute paths and empty names out of file paths.
    """
    candidate = name[2:] if name.startswith("*.") else name
    if not domain_validator(candidate):
        raise ValueError(f"Invalid domain name: {name!r}")
    return name


def certificate_dir(domain: str) -> str:
    """Return the storage directory of a certificate, rejecting unsafe names."""
    return os.path.join(PYACME_HOME_PATH, validate_domain_name(domain))


def pyacme_lock():
    """Serialize state-changing runs (new, cron, revoke, delete).

    Two overlapping runs would otherwise race on the same key, certificate
    and _acme-challenge TXT record.
    """
    return exclusive_lock(os.path.join(PYACME_HOME_PATH, ".lock"))


def create_acme_account(
    email: str,
    domain: str,
    staging: bool = False,
    directory_url: str | None = None,
) -> str:
    session = requests.Session()

    # Load or create domain-specific account key
    privkey = load_or_make_rsa_key(f"{domain}/account.key.pem")
    jwk = jwk_from_privkey(privkey)

    target_directory = get_directory_url(
        staging=staging, custom_url=directory_url
    )
    directory = get_directory(session, target_directory)
    new_nonce_url = directory["newNonce"]
    new_account_url = directory.get("newAccount")

    account_payload = {
        "termsOfServiceAgreed": True,
        "contact": [f"mailto:{email}"],
    }

    resp = post_jws(
        session,
        new_account_url,
        account_payload,
        privkey,
        new_nonce_url,
        jwk=jwk,
    )
    acct_url = resp.headers.get("Location")
    if not acct_url:
        raise RuntimeError(
            f"Failed to create account for {domain}: {resp.text}"
        )

    # Save account URL in domain-specific directory
    path = os.path.join(PYACME_HOME_PATH, domain, "account_url.result")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(acct_url)

    LOG.info(f"Created ACME account for {domain} -> {acct_url}")
    return acct_url


def init_dir() -> None:
    """Create the pyacme home directory if it does not exist."""
    os.makedirs(PYACME_HOME_PATH, exist_ok=True)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def int_to_b64u(n: int) -> str:
    length = (n.bit_length() + 7) // 8 or 1
    return b64u(n.to_bytes(length, "big"))


def load_or_make_rsa_key(
    file_name: str | None = None, bits: int = 2048
) -> rsa.RSAPrivateKey:
    init_dir()
    path = os.path.join(PYACME_HOME_PATH, file_name or "account.key.pem")

    dir_path = os.path.dirname(path)
    os.makedirs(dir_path, exist_ok=True)

    if os.path.exists(path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )

    key = rsa.generate_private_key(
        public_exponent=65537, key_size=bits, backend=default_backend()
    )
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    write_private_file(path, pem)

    LOG.info(f"Generated new RSA key: {path}")
    return key


def jwk_from_privkey(privkey: rsa.RSAPrivateKey) -> dict[str, str]:
    """Build a JWK from an RSA private key for ACME requests."""
    pub = privkey.public_key()
    nums = pub.public_numbers()
    return {"kty": "RSA", "n": int_to_b64u(nums.n), "e": int_to_b64u(nums.e)}


def get_directory(session: requests.Session, directory_url: str) -> dict:
    """Fetch and return the ACME directory JSON."""
    r = session.get(directory_url, timeout=10)
    r.raise_for_status()
    return r.json()


def get_nonce(session: requests.Session, new_nonce_url: str) -> str:
    r = session.head(new_nonce_url, timeout=10)
    nonce = r.headers.get("Replay-Nonce")
    if not nonce:
        r = session.get(new_nonce_url, timeout=10)
        nonce = r.headers.get("Replay-Nonce")
    if not nonce:
        raise RuntimeError("No Replay-Nonce returned by server")
    return nonce


class AcmeError(RuntimeError):
    """An ACME request failed; carries the RFC 7807 problem document."""

    def __init__(self, url: str, status: int, problem: dict) -> None:
        self.url = url
        self.status = status
        self.problem = problem
        self.type = str(problem.get("type", ""))
        self.detail = str(problem.get("detail", ""))
        super().__init__(
            f"ACME request to {url} failed with HTTP {status}: "
            f"{self.type or 'no problem type'} {self.detail}".rstrip()
        )


# Longest Retry-After pyacme waits for inline; longer back-offs (typically
# rate limits measured in hours) fail fast so cron can report them.
MAX_INLINE_RETRY_AFTER = 60

# Replay-Nonce from the previous response, per session (RFC 8555 7.2).
_SESSION_NONCES: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()


def make_jws(privkey, payload_obj, url, nonce, jwk=None, kid=None):
    """Build a flattened JWS; payload_obj None makes a POST-as-GET body."""
    payload64 = (
        "" if payload_obj is None else b64u(json.dumps(payload_obj).encode())
    )
    protected = {"alg": "RS256", "nonce": nonce, "url": url}
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


def _retry_after_seconds(resp) -> float | None:
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
    session,
    url,
    payload_obj,
    privkey,
    new_nonce_url,
    jwk=None,
    kid=None,
    max_retries=5,
):
    """POST a signed request; retry only what RFC 8555 says is retryable.

    badNonce is retried with the fresh nonce the server returned. A 503 or
    rateLimited response is retried only when Retry-After is short. Every
    other error raises AcmeError at once instead of being resent blindly.
    """
    for attempt in range(1, max_retries + 1):
        nonce = _SESSION_NONCES.pop(session, None) or get_nonce(
            session, new_nonce_url
        )
        jws = make_jws(privkey, payload_obj, url, nonce, jwk=jwk, kid=kid)
        r = session.post(
            url,
            json=jws,
            headers={"Content-Type": "application/jose+json"},
            timeout=30,
        )
        replay_nonce = r.headers.get("Replay-Nonce")
        if isinstance(replay_nonce, str):
            _SESSION_NONCES[session] = replay_nonce

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


def post_as_get(session, url, privkey, new_nonce_url, account_url):
    """Fetch an ACME resource with POST-as-GET (RFC 8555 6.3)."""
    return post_jws(session, url, None, privkey, new_nonce_url, kid=account_url)


def account_directory_url(domain: str) -> str:
    """
    Returns the account URL for a given domain.
    Raises an error if the account URL file does not exist.
    """
    path = os.path.join(PYACME_HOME_PATH, domain, "account_url.result")
    if not os.path.exists(path):
        raise RuntimeError(
            f"ACME account URL file for '{domain}' not found. You must create an account first."
        )
    with open(path, "r") as f:
        acct_url = f.read().strip()
    return acct_url


def create_csr(privkey: rsa.RSAPrivateKey, domains: list[str]) -> bytes:
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])])
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
            critical=False,
        )
        .sign(privkey, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.DER)


def thumbprint(jwk: dict[str, str]) -> str:
    jwk_json = json.dumps(
        {"e": jwk["e"], "kty": jwk["kty"], "n": jwk["n"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    return b64u(hashlib.sha256(jwk_json.encode("utf8")).digest())


def dns_challenge_provider(
    provider_name: str, domain: str, access_token: str | None = None
) -> Base | None:
    cfg_dir = f"{PYACME_HOME_PATH}/{domain}"
    if provider_name == "cloudflare":
        return Cloudflare(domain, access_token)
    elif provider_name == "dns":
        return None
    elif provider_name == "arvancloud":
        return ArvanCloud(domain, access_token)
    elif provider_name == "acmedns":
        return AcmeDNS(domain, cfg_dir)
    elif provider_name == "digitalocean":
        return DigitalOcean(domain, access_token or "")
    elif provider_name == "hetzner":
        return Hetzner(domain, access_token or "")
    elif provider_name == "powerdns":
        return PowerDNS(domain, access_token or "")
    elif provider_name == "route53":
        return Route53(domain, access_token)
    elif provider_name == "ovh":
        return OVH(domain, access_token or "")
    else:
        raise RuntimeError(f"Invalid provider: {provider_name}")


def perform_dns_challenge(
    session,
    privkey,
    account_url,
    new_nonce_url,
    authz_url,
    jwk,
    provider_name,
    access_token: str | None = None,
):
    authz_data = post_as_get(
        session, authz_url, privkey, new_nonce_url, account_url
    ).json()

    dns_challenge = None
    for challenge in authz_data["challenges"]:
        if challenge["type"] == "dns-01":
            dns_challenge = challenge
            break

    if not dns_challenge:
        raise RuntimeError(f"No DNS-01 challenge found for {authz_url}")

    token = dns_challenge["token"]
    key_auth = f"{token}.{thumbprint(jwk)}"
    txt_value = b64u(hashlib.sha256(key_auth.encode()).digest())

    domain = authz_data["identifier"]["value"]
    record_name = f"_acme-challenge.{domain}"

    dns_provider = dns_challenge_provider(provider_name, domain, access_token)
    LOG.info(f"DNS-01 challenge for {domain}")
    LOG.info(f"TXT record name: {record_name}")
    LOG.info(f"TXT record value: {txt_value}")
    if dns_provider:
        dns_provider.delete_txt_record()
        dns_provider.add_txt_record(name=record_name, content=txt_value)
        LOG.info("Using DNS provider; TXT record set.")
    else:
        LOG.info(
            "No DNS provider selected. Add the TXT record manually to your "
            "DNS zone, then continue."
        )
        input(
            "Have you added the TXT record to your zone? Press Enter to continue. "
        )

    wait_for_dns(record_name, txt_value)

    challenge_url = dns_challenge["url"]
    post_jws(
        session, challenge_url, {}, privkey, new_nonce_url, kid=account_url
    )

    for _ in range(ACME_POLL_ATTEMPTS):
        time.sleep(ACME_POLL_INTERVAL)
        authz = post_as_get(
            session, authz_url, privkey, new_nonce_url, account_url
        ).json()
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


def wait_for_dns(
    record_name: str,
    txt_value: str,
    interval: int = 10,
    timeout: int = 300,
    max_retries: int | None = None,
) -> None:
    """Wait for DNS propagation of record_name with txt_value.

    Args:
        record_name: The TXT record name (e.g. _acme-challenge.example.com).
        txt_value: The expected challenge token value.
        interval: Time in seconds between polling attempts (default: 10).
        timeout: Total timeout in seconds before failing (default: 300).
        max_retries: Maximum number of polling attempts (default: None).

    Raises:
        TimeoutError: If DNS record does not match within timeout or max_retries.
    """
    LOG.info(
        f"Waiting for DNS propagation of {record_name} (timeout={timeout}s, interval={interval}s)"
    )

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    resolver.timeout = min(5.0, float(interval)) if interval > 0 else 5.0
    resolver.lifetime = min(10.0, float(interval)) if interval > 0 else 10.0

    start_time = time.time()
    attempts = 0

    while True:
        attempts += 1
        elapsed = time.time() - start_time

        try:
            answers = resolver.resolve(record_name, "TXT")
            for rdata in answers:
                txt_records = [txt.decode() for txt in rdata.strings]
                if txt_value in txt_records:
                    LOG.info(
                        f"DNS record found for {record_name} after {attempts} attempt(s) ({elapsed:.1f}s)."
                    )
                    return
            LOG.info("TXT record found, but value not matching. Retrying...")
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.exception.DNSException,
        ) as e:
            LOG.warning(
                f"DNS query failed or no answer yet (attempt {attempts}): {e}"
            )

        elapsed = time.time() - start_time
        if elapsed >= timeout or (
            max_retries is not None and attempts >= max_retries
        ):
            msg = (
                f"DNS propagation timed out for {record_name} after {elapsed:.1f}s "
                f"({attempts} attempt(s)). Expected TXT: {txt_value}"
            )
            LOG.error(msg)
            raise TimeoutError(msg)

        sleep_time = min(float(interval), max(0.1, float(timeout - elapsed)))
        time.sleep(sleep_time)


def generate_private_key(key_type: str = DEFAULT_KEY_TYPE):
    """Return a new certificate private key of the given type."""
    if key_type == "rsa2048":
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if key_type == "rsa4096":
        return rsa.generate_private_key(public_exponent=65537, key_size=4096)
    if key_type == "ec256":
        return ec.generate_private_key(ec.SECP256R1())
    if key_type == "ec384":
        return ec.generate_private_key(ec.SECP384R1())
    raise ValueError(
        f"Unsupported key type {key_type!r}; choose one of {KEY_TYPES}"
    )


def install_certificate(
    domain_dir_name: str, certificate_pem: str, private_key
) -> str:
    """Store a newly issued certificate and its key; return the cert path.

    The previous pair is kept as cert.pem.prev / privkey.pem.prev for manual
    rollback. Each file is replaced atomically, the key before the
    certificate; the renew command that reloads the server runs only after
    both are in place.
    """
    domain_dir = os.path.join(PYACME_HOME_PATH, domain_dir_name)
    cert_path = os.path.join(domain_dir, "cert.pem")
    key_path = os.path.join(domain_dir, "privkey.pem")

    for path, mode in ((cert_path, PUBLIC_FILE_MODE), (key_path, 0o600)):
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


def finalize_order(
    session,
    privkey,
    account_url,
    new_nonce_url,
    order_data,
    domains,
    order_url,
    key_type: str = DEFAULT_KEY_TYPE,
):
    # A fresh key on every issuance limits the exposure of a leaked key to
    # one certificate lifetime.
    cert_privkey = generate_private_key(key_type)

    csr = create_csr(cert_privkey, domains)
    csr64 = b64u(csr)

    finalize_payload = {"csr": csr64}
    finalize_url = order_data["finalize"]

    resp = post_jws(
        session,
        finalize_url,
        finalize_payload,
        privkey,
        new_nonce_url,
        kid=account_url,
    )
    resp.raise_for_status()

    if not order_url:
        raise RuntimeError("Missing order URL after finalization")

    for _ in range(ACME_POLL_ATTEMPTS):
        time.sleep(ACME_POLL_INTERVAL)
        resp = post_jws(
            session, order_url, None, privkey, new_nonce_url, kid=account_url
        )
        status = resp.json()["status"]
        LOG.info(f"Order status: {status}")
        if status == "valid":
            break
        elif status == "invalid":
            raise RuntimeError(f"Order finalization failed: {resp.json()}")
    else:
        raise TimeoutError(
            f"Order {order_url} still '{status}' after "
            f"{ACME_POLL_ATTEMPTS * ACME_POLL_INTERVAL}s"
        )

    cert_url = resp.json()["certificate"]
    if not cert_url:
        raise RuntimeError("Certificate URL not returned after finalization")

    certificate_pem = post_as_get(
        session, cert_url, privkey, new_nonce_url, account_url
    ).text

    cert_path = install_certificate(domains[0], certificate_pem, cert_privkey)
    LOG.info(f"Certificate and new private key saved: {cert_path}")


def extract_domains_for_renewal(cert_data: dict, cert_dir: str) -> list[str]:
    """Extract list of domains for renewal from cert_data or cert.pem."""
    # 1. From cert_data['domains']
    stored_domains = cert_data.get("domains")
    if isinstance(stored_domains, list) and len(stored_domains) > 0:
        cleaned = [str(d).strip() for d in stored_domains if str(d).strip()]
        if cleaned:
            return list(dict.fromkeys(cleaned))

    # 2. From cert.pem SAN extension
    cert_path = cert_data.get("certificate_path") or os.path.join(
        cert_dir, "cert.pem"
    )
    if os.path.exists(cert_path):
        try:
            with open(cert_path, "rb") as f:
                cert_obj = x509.load_pem_x509_certificate(
                    f.read(), default_backend()
                )
            try:
                san_ext = cert_obj.extensions.get_extension_for_oid(
                    x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                san_domains = san_ext.value.get_values_for_type(x509.DNSName)
                if san_domains:
                    return list(dict.fromkeys(san_domains))
            except x509.ExtensionNotFound:
                pass

            cns = cert_obj.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if cns and cns[0].value:
                return [str(cns[0].value)]
        except Exception as exc:
            LOG.warning(
                f"Could not parse certificate SANs from {cert_path}: {exc}"
            )

    # 3. Fallback to cert_data['domain']
    domain_val = cert_data.get("domain", "").strip()
    if domain_val:
        return [domain_val]

    raise RuntimeError(
        f"Could not determine domains for renewal from {cert_dir}"
    )


def get_certificate_for_domains_dns(
    domains: list[str],
    dns_provider: str,
    email: str,
    access_token: str | None,
    renew_command: str,
    staging: bool = False,
    directory_url: str | None = None,
    key_type: str = DEFAULT_KEY_TYPE,
) -> None:
    target_directory = get_directory_url(
        staging=staging, custom_url=directory_url
    )
    create_acme_account(
        domain=domains[0],
        email=email,
        staging=staging,
        directory_url=target_directory,
    )
    LOG.info(f"Starting certificate request for domains: {domains}")

    session = requests.Session()
    directory = get_directory(session, target_directory)
    new_nonce_url = directory["newNonce"]

    privkey = load_or_make_rsa_key(file_name=f"{domains[0]}/account.key.pem")
    jwk = jwk_from_privkey(privkey)
    account_url = account_directory_url(domains[0])

    order_payload = {
        "identifiers": [{"type": "dns", "value": d} for d in domains]
    }
    resp = post_jws(
        session,
        directory["newOrder"],
        order_payload,
        privkey,
        new_nonce_url,
        kid=account_url,
    )
    order_data = resp.json()
    order_url = resp.headers.get("Location")

    if not order_url:
        raise RuntimeError(f"No order URL returned: {order_data}")

    LOG.info(f"Order URL: {order_url}")
    LOG.info(f"Order data: {order_data}")

    for authz_url in order_data["authorizations"]:
        perform_dns_challenge(
            session,
            privkey,
            account_url,
            new_nonce_url,
            authz_url,
            jwk,
            dns_provider,
            access_token=access_token,
        )

    finalize_order(
        session,
        privkey,
        account_url,
        new_nonce_url,
        order_data,
        domains,
        order_url,
        key_type=key_type,
    )

    cert = SSLCertificate.from_pem(
        cert_path=f"{PYACME_HOME_PATH}/{domains[0]}/cert.pem",
        key_path=f"{PYACME_HOME_PATH}/{domains[0]}/privkey.pem",
        renew_before_days=20,
        renew_command=renew_command,
        provider=dns_provider,
        provider_conf=access_token,
        email=email,
    )
    cert.domains = domains
    cert.staging = staging
    cert.key_type = key_type

    cert.save(f"{PYACME_HOME_PATH}/{domains[0]}/certificate.json")


def renew_certificate(
    cert_json_path: str,
    staging: bool | None = None,
    directory_url: str | None = None,
) -> None:
    if not os.path.exists(cert_json_path):
        raise RuntimeError(f"No certificate.json found at {cert_json_path}")

    with open(cert_json_path, "r", encoding="utf-8") as f:
        cert_data = json.load(f)

    cert_dir = os.path.dirname(os.path.abspath(cert_json_path))
    folder_domain = os.path.basename(cert_dir)

    dns_provider = cert_data["provider"]
    access_token = cert_data.get("provider_conf")

    domains = extract_domains_for_renewal(cert_data, cert_dir)
    if not domains:
        raise RuntimeError(f"No domains found for renewal in {cert_dir}")

    # Determine primary domain aligned with storage directory
    if folder_domain in domains:
        primary_domain = folder_domain
    elif cert_data.get("domain") in domains:
        primary_domain = cert_data["domain"]
    else:
        primary_domain = domains[0]

    ordered_domains = [primary_domain] + [
        d for d in domains if d != primary_domain
    ]

    # Resolve account directory
    if os.path.exists(
        os.path.join(PYACME_HOME_PATH, folder_domain, "account_url.result")
    ):
        account_dir_name = folder_domain
    elif os.path.exists(
        os.path.join(PYACME_HOME_PATH, primary_domain, "account_url.result")
    ):
        account_dir_name = primary_domain
    else:
        non_wildcard = primary_domain.replace("*.", "")
        if os.path.exists(
            os.path.join(PYACME_HOME_PATH, non_wildcard, "account_url.result")
        ):
            account_dir_name = non_wildcard
        else:
            account_dir_name = folder_domain

    is_staging = cert_data.get("staging", False) if staging is None else staging
    target_directory = get_directory_url(
        staging=is_staging, custom_url=directory_url
    )

    session = requests.Session()
    directory = get_directory(session, target_directory)
    new_nonce_url = directory["newNonce"]

    privkey = load_or_make_rsa_key(
        file_name=f"{account_dir_name}/account.key.pem"
    )
    jwk = jwk_from_privkey(privkey)
    account_url = account_directory_url(account_dir_name)

    identifiers = [{"type": "dns", "value": d} for d in ordered_domains]
    resp = post_jws(
        session,
        directory["newOrder"],
        {"identifiers": identifiers},
        privkey,
        new_nonce_url,
        kid=account_url,
    )
    order_data = resp.json()
    order_url = resp.headers.get("Location")
    if not order_url:
        raise RuntimeError(f"No order URL returned: {order_data}")

    for authz_url in order_data["authorizations"]:
        perform_dns_challenge(
            session=session,
            privkey=privkey,
            account_url=account_url,
            new_nonce_url=new_nonce_url,
            authz_url=authz_url,
            jwk=jwk,
            provider_name=dns_provider,
            access_token=access_token,
        )

    finalize_order(
        session,
        privkey,
        account_url,
        new_nonce_url,
        order_data,
        ordered_domains,
        order_url,
        key_type=cert_data.get("key_type", DEFAULT_KEY_TYPE),
    )

    cert_path = cert_data.get("certificate_path") or os.path.join(
        PYACME_HOME_PATH, primary_domain, "cert.pem"
    )

    with open(cert_path, "rb") as f:
        cert_obj = x509.load_pem_x509_certificate(f.read(), default_backend())
    new_expiry_date = cert_obj.not_valid_after_utc.strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    cert_data.update(
        {
            "domains": ordered_domains,
            "expiry_date": new_expiry_date,
            "last_renewed": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "status": "valid",
        }
    )
    if is_staging:
        cert_data["staging"] = True

    write_private_file(cert_json_path, json.dumps(cert_data, indent=4))

    LOG.info(
        f"Renewal successful for {primary_domain} (domains: {ordered_domains})"
    )


def inspect_certificate(domain: str) -> dict[str, str]:
    """Inspect detailed information of a locally stored certificate."""
    domain_dir = certificate_dir(domain)
    cert_path = os.path.join(domain_dir, "cert.pem")
    key_path = os.path.join(domain_dir, "privkey.pem")
    json_path = os.path.join(domain_dir, "certificate.json")

    if not os.path.exists(cert_path):
        raise FileNotFoundError(f"Certificate not found for domain: {domain}")

    with open(cert_path, "rb") as f:
        cert_data = f.read()

    cert = x509.load_pem_x509_certificate(cert_data, default_backend())

    try:
        cn = str(
            cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        )
    except IndexError:
        cn = "N/A"

    try:
        san_ext = cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        sans = []

    try:
        issuer = str(
            cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[
                0
            ].value
        )
    except IndexError:
        try:
            issuer = str(
                cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            )
        except IndexError:
            issuer = "Unknown"

    now = datetime.now(timezone.utc)
    valid_from = cert.not_valid_before_utc
    valid_to = cert.not_valid_after_utc
    days_left = (valid_to - now).days

    meta = {}
    if os.path.exists(json_path):
        try:
            with open(json_path, "r", encoding="utf-8") as jf:
                meta = json.load(jf)
        except Exception:
            pass

    status_str = meta.get("status", "valid" if now <= valid_to else "expired")

    key_type = "Unknown"
    key_matches = "Unknown"
    if os.path.exists(key_path):
        try:
            with open(key_path, "rb") as kf:
                k_data = kf.read()
            priv_key = serialization.load_pem_private_key(
                k_data, password=None, backend=default_backend()
            )
            pub_key = cert.public_key()
            if isinstance(priv_key, rsa.RSAPrivateKey):
                key_type = f"RSA ({priv_key.key_size} bit)"
                key_matches = (
                    "Yes"
                    if priv_key.public_key().public_numbers()
                    == pub_key.public_numbers()
                    else "No"
                )
            elif isinstance(priv_key, ec.EllipticCurvePrivateKey):
                key_type = f"EC ({priv_key.curve.name})"
                key_matches = (
                    "Yes"
                    if priv_key.public_key().public_numbers()
                    == pub_key.public_numbers()
                    else "No"
                )
        except Exception:
            key_matches = "Error reading key"

    return {
        "Domain": domain,
        "Common Name": cn,
        "SANs": ", ".join(sans) if sans else cn,
        "Issuer": issuer,
        "Serial Number": f"{cert.serial_number:X}",
        "Valid From": valid_from.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Valid Until": valid_to.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Days Remaining": f"{days_left} days",
        "Status": status_str,
        "Key Type": key_type,
        "Private Key Match": key_matches,
        "Provider": meta.get("provider", "N/A"),
        "Staging": "Yes" if meta.get("staging") else "No",
        "Renew Command": meta.get("renew_command", "N/A"),
        "Last Renewed": meta.get("last_renewed", "N/A"),
    }


def export_certificate(
    domain: str,
    output_path: str,
    export_format: str = "pem-bundle",
    password: str | None = None,
) -> str:
    """Export certificate and key as a PEM bundle or PKCS#12 (PFX)."""
    domain_dir = certificate_dir(domain)
    cert_path = os.path.join(domain_dir, "cert.pem")
    key_path = os.path.join(domain_dir, "privkey.pem")

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        raise FileNotFoundError(
            f"Certificate or private key not found for domain: {domain}"
        )

    with open(cert_path, "rb") as f:
        cert_bytes = f.read()
    with open(key_path, "rb") as f:
        key_bytes = f.read()

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    if export_format == "pem-bundle":
        bundle = cert_bytes.strip() + b"\n\n" + key_bytes.strip() + b"\n"
        write_private_file(output_path, bundle)
    elif export_format in ("pfx", "pkcs12"):
        from cryptography.hazmat.primitives.serialization import pkcs12

        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        key = serialization.load_pem_private_key(
            key_bytes, password=None, backend=default_backend()
        )
        encryption = (
            serialization.BestAvailableEncryption(password.encode("utf-8"))
            if password
            else serialization.NoEncryption()
        )
        pfx_bytes = pkcs12.serialize_key_and_certificates(
            name=domain.encode("utf-8"),
            key=key,
            cert=cert,
            cas=None,
            encryption_algorithm=encryption,
        )
        write_private_file(output_path, pfx_bytes)
    else:
        raise ValueError(
            f"Unsupported format: {export_format}. Choose 'pem-bundle' or 'pfx'."
        )

    return output_path


def delete_certificate_data(domain: str) -> bool:
    """Safely delete certificate directory from ~/.pyacme."""
    import shutil

    domain_dir = certificate_dir(domain)
    if not os.path.exists(domain_dir):
        return False
    shutil.rmtree(domain_dir)
    return True


def revoke_certificate(
    domain: str,
    reason: int = 0,
    staging: bool | None = None,
) -> None:
    """Revoke a certificate using the ACME revokeCert endpoint."""
    domain_dir = certificate_dir(domain)
    cert_path = os.path.join(domain_dir, "cert.pem")
    cert_json_path = os.path.join(domain_dir, "certificate.json")

    if not os.path.exists(cert_path):
        raise FileNotFoundError(f"Certificate not found at {cert_path}")

    with open(cert_path, "rb") as f:
        cert_pem = f.read()

    cert_obj = x509.load_pem_x509_certificate(cert_pem, default_backend())
    cert_der = cert_obj.public_bytes(serialization.Encoding.DER)

    is_staging = False
    if staging is not None:
        is_staging = staging
    elif os.path.exists(cert_json_path):
        try:
            with open(cert_json_path, "r", encoding="utf-8") as jf:
                cdata = json.load(jf)
            is_staging = cdata.get("staging", False)
        except Exception:
            pass

    target_directory = get_directory_url(staging=is_staging)
    session = requests.Session()
    directory = get_directory(session, target_directory)
    revoke_url = directory.get("revokeCert")
    if not revoke_url:
        raise RuntimeError("Directory does not specify revokeCert endpoint")

    new_nonce_url = directory["newNonce"]
    privkey = load_or_make_rsa_key(file_name=f"{domain}/account.key.pem")
    account_url = account_directory_url(domain)

    payload = {
        "certificate": b64u(cert_der),
        "reason": reason,
    }

    resp = post_jws(
        session,
        revoke_url,
        payload,
        privkey,
        new_nonce_url,
        kid=account_url,
    )
    if resp.status_code not in (200, 201, 204):
        resp.raise_for_status()

    if os.path.exists(cert_json_path):
        try:
            with open(cert_json_path, "r", encoding="utf-8") as jf:
                cdata = json.load(jf)
            cdata["status"] = "revoked"
            write_private_file(cert_json_path, json.dumps(cdata, indent=4))
        except Exception:
            pass

    LOG.info(f"Certificate for {domain} has been successfully revoked.")
