import hashlib
import os
import sys
import time
import base64
import json
from typing import Optional
import datetime
import requests
import dns.resolver
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509 import NameOID

from src.tls.ssl_object import SSLCertificate
from src.webhooks.acmedns import AcmeDNS
from src.webhooks.arvancloud import ArvanCloud
from src.webhooks.cloudflare import Cloudflare
from src.happylog import LOG

PYACME_HOME_PATH = os.path.expanduser("~/.pyacme")
#DIRECTORY_ADDRESS = "https://acme-staging-v02.api.letsencrypt.org/directory"
DIRECTORY_ADDRESS = 'https://acme-v02.api.letsencrypt.org/directory'

def create_acme_account(email: str, domain: str):
    session = requests.Session()

    # Load or create domain-specific account key
    privkey = load_or_make_rsa_key(f"{domain}/account.key.pem")
    jwk = jwk_from_privkey(privkey)

    directory = get_directory(session, DIRECTORY_ADDRESS)
    new_nonce_url = directory["newNonce"]
    new_account_url = directory.get("newAccount")

    account_payload = {
        "termsOfServiceAgreed": True,
        "contact": [f"mailto:{email}"]
    }

    resp = post_jws(session, new_account_url, account_payload, privkey, new_nonce_url, jwk=jwk)
    acct_url = resp.headers.get("Location")
    if not acct_url:
        raise RuntimeError(f"Failed to create account for {domain}: {resp.text}")

    # Save account URL in domain-specific directory
    path = os.path.expanduser(f"~/.pyacme/{domain}/account_url.result")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(acct_url)

    LOG.info(f"Created ACME account for {domain} -> {acct_url}")
    return acct_url


# -------------------------
# Helper Functions
# -------------------------
def init_dir():
    os.makedirs(PYACME_HOME_PATH, exist_ok=True)


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def int_to_b64u(n: int) -> str:
    length = (n.bit_length() + 7) // 8 or 1
    return b64u(n.to_bytes(length, "big"))


def load_or_make_rsa_key(file_name: str | None = None, bits: int = 2048):
    init_dir()
    path = os.path.join(PYACME_HOME_PATH, file_name or "account.key.pem")

    dir_path = os.path.dirname(path)
    os.makedirs(dir_path, exist_ok=True)

    if os.path.exists(path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    key = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with open(path, "wb") as f:
        f.write(pem)

    LOG.info(f"Generated new RSA key: {path}")
    return key


def jwk_from_privkey(privkey):
    pub = privkey.public_key()
    nums = pub.public_numbers()
    return {"kty": "RSA", "n": int_to_b64u(nums.n), "e": int_to_b64u(nums.e)}


def get_directory(session: requests.Session, directory_url: str):
    r = session.get(directory_url, timeout=10)
    r.raise_for_status()
    return r.json()


def get_nonce(session: requests.Session, new_nonce_url: str):
    r = session.head(new_nonce_url, timeout=10)
    nonce = r.headers.get("Replay-Nonce")
    if not nonce:
        r = session.get(new_nonce_url, timeout=10)
        nonce = r.headers.get("Replay-Nonce")
    if not nonce:
        raise RuntimeError("No Replay-Nonce returned by server")
    return nonce


def make_jws(privkey, payload_obj, url, nonce, jwk=None, kid=None):
    payload_b = json.dumps(payload_obj).encode("utf8")
    payload64 = b64u(payload_b)
    protected = {"alg": "RS256", "nonce": nonce, "url": url}
    if jwk:
        protected["jwk"] = jwk
    else:
        protected["kid"] = kid
    protected_b = json.dumps(protected, separators=(",", ":")).encode("utf8")
    protected64 = b64u(protected_b)
    signing_input = (protected64 + "." + payload64).encode("ascii")
    signature = privkey.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return {"protected": protected64, "payload": payload64, "signature": b64u(signature)}


def post_jws(session, url, payload_obj, privkey, new_nonce_url, jwk=None, kid=None, max_retries=5):
    for attempt in range(max_retries):
        nonce = get_nonce(session, new_nonce_url)

        if payload_obj is None:
            payload_b = b""
            payload64 = ""
        else:
            payload_b = json.dumps(payload_obj).encode("utf8")
            payload64 = b64u(payload_b)

        protected = {"alg": "RS256", "nonce": nonce, "url": url}
        if jwk:
            protected["jwk"] = jwk
        else:
            protected["kid"] = kid

        protected_b = json.dumps(protected, separators=(",", ":")).encode("utf8")
        protected64 = b64u(protected_b)

        signing_input = (protected64 + "." + payload64).encode("ascii")
        signature = privkey.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

        jws = {"protected": protected64, "payload": payload64, "signature": b64u(signature)}

        headers = {"Content-Type": "application/jose+json"}
        r = session.post(url, json=jws, headers=headers, timeout=30)

        if r.status_code in (200, 201, 204):
            return r

        try:
            body = r.json()
        except Exception:
            body = {}

        if body.get("type") == "urn:ietf:params:acme:error:badNonce" or r.status_code == 400:
            time.sleep(0.5)
            continue

        LOG.error(f"DEBUG JWS failed: {r.status_code} {r.text}")
        r.raise_for_status()

    raise RuntimeError(f"Failed after retries; last status: {r.status_code}, body: {getattr(r, 'text', '<no body>')}")


def account_directory_url(domain: str) -> str:
    """
    Returns the account URL for a given domain.
    Raises an error if the account URL file does not exist.
    """
    path = os.path.expanduser(f"~/.pyacme/{domain}/account_url.result")
    if not os.path.exists(path):
        raise RuntimeError(f"ACME account URL file for '{domain}' not found. You must create an account first.")
    with open(path, "r") as f:
        acct_url = f.read().strip()
    return acct_url


def create_csr(privkey, domains):
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domains[0])]))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in domains]),
            critical=False,
        )
        .sign(privkey, hashes.SHA256())
    )
    return csr.public_bytes(serialization.Encoding.DER)


def thumbprint(jwk):
    jwk_json = json.dumps(
        {"e": jwk["e"], "kty": jwk["kty"], "n": jwk["n"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    return b64u(hashlib.sha256(jwk_json.encode("utf8")).digest())


def dns_challenge_provider(provider_name: str, domain: str, access_token: str | None = None):
    cfg_dir = f'{PYACME_HOME_PATH}/{domain}'
    if provider_name == 'cloudflare':
        return Cloudflare(domain, access_token)
    elif provider_name == 'dns':
        return None
    elif provider_name == 'arvancloud':
        return ArvanCloud(domain, access_token)
    elif provider_name == 'acmedns':
        return AcmeDNS(domain, cfg_dir)
    else:
        raise RuntimeError('Invalid provider')


def perform_dns_challenge(session, privkey, account_url, new_nonce_url, authz_url, jwk, provider_name,
                          access_token: str | None = None):
    # Step 1: GET authz details
    resp = session.get(authz_url, timeout=10)
    resp.raise_for_status()
    authz_data = resp.json()

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
    if dns_provider:
        dns_provider.delete_txt_record()
        dns_provider.add_txt_record(name=record_name, content=txt_value)
        LOG.info("You dont choose any dns provider you should add txt record in your dns server")
        LOG.info(f"DNS-01 challenge found for {domain}")
        LOG.info(f"TXT record name: {record_name}")
        LOG.info(f"TXT record value: {txt_value}")
    else:
        LOG.info("You dont choose any dns provider you should add txt record in your dns server")
        LOG.info(f"DNS-01 challenge found for {domain}")
        LOG.info(f"TXT record name: {record_name}")
        LOG.info(f"TXT record value: {txt_value}")
        input("Are you add it to you zones? ")

    wait_for_dns(record_name, txt_value)

    challenge_url = dns_challenge["url"]
    resp = post_jws(session, challenge_url, {}, privkey, new_nonce_url, kid=account_url)

    while True:
        time.sleep(2)
        resp = session.get(authz_url, timeout=10)
        status = resp.json()["status"]
        if status == "valid":
            break
        elif status == "invalid":
            LOG.warning("Already Invalid try to validate again")


def wait_for_dns(record_name, txt_value, interval=10):
    LOG.info(f"Waiting for DNS propagation of {record_name}")

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]

    while True:
        try:
            answers = resolver.resolve(record_name, "TXT")
            for rdata in answers:
                txt_records = [txt.decode() for txt in rdata.strings]
                if txt_value in txt_records:
                    LOG.info("DNS record found.")
                    return
            LOG.info(f"TXT record found, but value not matching. Retrying...")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers) as e:
            LOG.warning(f"DNS query failed or no answer yet: {e}")

        time.sleep(interval)


def finalize_order(session, privkey, account_url, new_nonce_url, order_data, domains, order_url):
    cert_privkey = load_or_make_rsa_key(file_name=f"{domains[0]}/privkey.pem", bits=2048)

    csr = create_csr(cert_privkey, domains)
    csr64 = b64u(csr)

    finalize_payload = {"csr": csr64}
    finalize_url = order_data["finalize"]

    resp = post_jws(session, finalize_url, finalize_payload, privkey, new_nonce_url, kid=account_url)
    resp.raise_for_status()

    if not order_url:
        raise RuntimeError("Missing order URL after finalization")

    while True:
        time.sleep(2)
        resp = post_jws(session, order_url, None, privkey, new_nonce_url, kid=account_url)
        status = resp.json()["status"]
        LOG.info(f"Order status: {status}")
        if status == "valid":
            break
        elif status == "invalid":
            raise RuntimeError("Order finalization failed")

    cert_url = resp.json()["certificate"]
    if not cert_url:
        raise RuntimeError("Certificate URL not returned after finalization")

    cert_resp = session.get(cert_url)
    cert_resp.raise_for_status()
    certificate_pem = cert_resp.text

    cert_path = os.path.join(PYACME_HOME_PATH, domains[0], "cert.pem")
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    with open(cert_path, "w") as f:
        f.write(certificate_pem)

    LOG.info(f"Certificate saved: {cert_path}")
    LOG.info(f"Certificate private key saved: {domains[0]}/privkey.pem")


def get_certificate_for_domains_dns(domains: list[str], dns_provider: str, email: str, access_token: str,
                                    renew_command: str):
    create_acme_account(domain=domains[0], email=email)
    LOG.info(f"Starting certificate request for domains: {domains}")

    session = requests.Session()
    directory = get_directory(session, DIRECTORY_ADDRESS)
    new_nonce_url = directory["newNonce"]

    privkey = load_or_make_rsa_key(file_name=f"{domains[0]}/account.key.pem")
    jwk = jwk_from_privkey(privkey)
    account_url = account_directory_url(domains[0])

    order_payload = {"identifiers": [{"type": "dns", "value": d} for d in domains]}
    resp = post_jws(session, directory["newOrder"], order_payload, privkey, new_nonce_url, kid=account_url)
    order_data = resp.json()
    order_url = resp.headers.get("Location")

    if not order_url:
        raise RuntimeError(f"No order URL returned: {order_data}")

    LOG.info(f"Order URL: {order_url}")
    LOG.info(f"Order data: {order_data}")

    for authz_url in order_data["authorizations"]:
        perform_dns_challenge(session, privkey, account_url, new_nonce_url, authz_url, jwk, dns_provider,
                              access_token=access_token)

    finalize_order(session, privkey, account_url, new_nonce_url, order_data, domains, order_url)

    cert = SSLCertificate.from_pem(
        cert_path=f"{PYACME_HOME_PATH}/{domains[0]}/cert.pem",
        key_path=f"{PYACME_HOME_PATH}/{domains[0]}/privkey.pem",
        renew_before_days=20,
        renew_command=renew_command,
        provider=dns_provider,
        provider_conf=access_token,
        email=email
    )

    cert.save(f"{PYACME_HOME_PATH}/{domains[0]}/certificate.json")

def renew_certificate(cert_json_path: str):
    if not os.path.exists(cert_json_path):
        raise RuntimeError("No certificate.json found for domain")

    with open(cert_json_path, "r") as f:
        cert_data = json.load(f)

    domain = cert_data['domain'].replace('*.', '')
    dns_provider = cert_data["provider"]
    access_token = cert_data.get("provider_conf")

    session = requests.Session()
    directory = get_directory(session, DIRECTORY_ADDRESS)
    new_nonce_url = directory["newNonce"]

    privkey = load_or_make_rsa_key(file_name=f"{domain}/account.key.pem")
    jwk = jwk_from_privkey(privkey)
    account_url = account_directory_url(domain)


    identifiers = [{"type": "dns", "value": cert_data["domain"]}, {"type": "dns", "value": domain}]
    resp = post_jws(session, directory["newOrder"], {"identifiers": identifiers}, privkey, new_nonce_url, kid=account_url)
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
            access_token=access_token
        )

    finalize_order(session, privkey, account_url, new_nonce_url, order_data, [domain, cert_data["domain"]], order_url)

    cert_path = os.path.join(PYACME_HOME_PATH, domain, "cert.pem")

    with open(cert_path, "rb") as f:
        cert_obj = x509.load_pem_x509_certificate(f.read(), default_backend())
    new_expiry_date = cert_obj.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    cert_data.update({
        "expiry_date": new_expiry_date,
        "last_renewed": datetime.datetime.utcnow().isoformat() + "Z",
        "status": "valid",
    })

    with open(cert_json_path, "w") as f:
        json.dump(cert_data, f, indent=4)

    LOG.info(f"Renewal successful for {domain}")
