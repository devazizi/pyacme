"""Certificate operations: issue, renew, revoke, inspect and export.

Collaborators are referenced through their modules (client.X, storage.X,
dnscheck.X) rather than imported by name, so a test or caller can replace
one of them by patching the module that defines it.
"""

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    CertificateIssuerPrivateKeyTypes,
)
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import NameOID

from pyacmecli.acme import client, dnscheck, storage
from pyacmecli.acme.client import AcmeClient, Order
from pyacmecli.common.fsutil import write_private_file
from pyacmecli.happylog import LOG
from pyacmecli.tls.ssl_object import SSLCertificate
from pyacmecli.webhooks import PROVIDERS, provider_token_env
from pyacmecli.webhooks.base import Base

# Used when the certificate lifetime cannot be read from cert.pem.
DEFAULT_RENEWAL_WINDOW = timedelta(days=30)

# Certificate key types. rsa2048 stays the default for client compatibility.
DEFAULT_KEY_TYPE = "rsa2048"
KEY_TYPES = ("rsa2048", "rsa4096", "ec256", "ec384")

CertData = dict[str, Any]


def generate_private_key(
    key_type: str = DEFAULT_KEY_TYPE,
) -> CertificateIssuerPrivateKeyTypes:
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


def create_csr(
    privkey: CertificateIssuerPrivateKeyTypes, domains: list[str]
) -> bytes:
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


def renewal_window(cert_path: str) -> timedelta:
    """Return how long before expiry a certificate becomes due for renewal.

    One third of the certificate's lifetime: 30 days for today's 90-day
    Let's Encrypt certificates, and proportionally less for the shorter
    lifetimes the CA/Browser Forum is phasing in, where a fixed 30 days
    would renew a 45-day certificate almost immediately.
    """
    try:
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
    except (OSError, ValueError):
        return DEFAULT_RENEWAL_WINDOW
    return (cert.not_valid_after_utc - cert.not_valid_before_utc) / 3


def dns_challenge_provider(
    provider_name: str, domain: str, access_token: str | None = None
) -> Base | None:
    spec = PROVIDERS.get(provider_name)
    if spec is None:
        raise RuntimeError(f"Invalid provider: {provider_name}")
    if spec.factory is None:
        return None
    return spec.factory(domain, access_token, f"{storage.home()}/{domain}")


def resolve_access_token(provider: str, stored: str | None) -> str | None:
    """Credential for provider: its environment variable, else the stored one.

    The variable wins so a rotated token can be supplied without editing
    every certificate.json, and so tokens need not be stored at all.
    """
    token = os.environ.get(provider_token_env(provider)) or stored
    spec = PROVIDERS.get(provider)
    if spec and spec.token_required and not token:
        raise RuntimeError(
            f"No credential for provider {provider!r}: set "
            f"{provider_token_env(provider)}"
        )
    return token


def connect_account(
    directory_url: str,
    email: str,
    account_dir: str | None = None,
    register: bool = True,
) -> tuple[str, AcmeClient]:
    """Return (account_dir, client) for an ACME account at directory_url.

    Without account_dir the shared account of that CA is used: one per CA,
    because Let's Encrypt limits new registrations per IP and one key is
    easier to protect than one per domain. Certificates issued by older
    versions pass their per-domain account_dir instead.

    An account that has no stored URL yet is registered, unless register is
    False (revocation must use the account that already exists).
    """
    account_dir = account_dir or storage.account_dir_for(directory_url)
    key = storage.load_or_make_rsa_key(f"{account_dir}/account.key.pem")
    acme = AcmeClient.connect(directory_url, key)
    try:
        acme.account_url = storage.account_directory_url(account_dir)
    except RuntimeError:
        if not register:
            raise
        account_url = acme.register(email)
        storage.save_account_url(account_dir, account_url)
        LOG.info(f"Registered ACME account {account_url}")
    return account_dir, acme


def _cleanup_txt_record(dns_provider: Base, record_name: str) -> None:
    """Delete the challenge record; a failure here must not fail issuance."""
    try:
        dns_provider.delete_txt_record()
    except Exception as exc:
        LOG.warning(f"Could not delete TXT record {record_name}: {exc}")


def perform_dns_challenge(
    acme: AcmeClient,
    authz_url: str,
    provider_name: str,
    access_token: str | None = None,
) -> None:
    """Satisfy one authorization with a dns-01 challenge."""
    authz = acme.get_authorization(authz_url)
    dns_challenge = next(
        (c for c in authz["challenges"] if c["type"] == "dns-01"), None
    )
    if not dns_challenge:
        raise RuntimeError(f"No DNS-01 challenge found for {authz_url}")

    txt_value = acme.key_authorization_digest(dns_challenge["token"])
    domain = authz["identifier"]["value"]
    record_name = f"_acme-challenge.{domain}"

    dns_provider = dns_challenge_provider(provider_name, domain, access_token)
    LOG.info(f"DNS-01 challenge for {domain}")
    LOG.info(f"TXT record name: {record_name}")
    LOG.info(f"TXT record value: {txt_value}")
    if dns_provider:
        # Clear leftovers of an interrupted earlier run first.
        _cleanup_txt_record(dns_provider, record_name)
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

    try:
        lookup_name, nameservers = dnscheck.find_authoritative_servers(
            record_name
        )
        dnscheck.wait_for_dns(lookup_name, txt_value, nameservers=nameservers)
        acme.answer_challenge(dns_challenge["url"])
        acme.wait_for_authorization(authz_url, domain)
    finally:
        # The token is useless once the authorization is decided; leaving it
        # only clutters the zone. Runs on failure too.
        if dns_provider:
            _cleanup_txt_record(dns_provider, record_name)
        else:
            LOG.info(f"You can now remove the TXT record {record_name}.")


def finalize_order(
    acme: AcmeClient,
    order: Order,
    domains: list[str],
    key_type: str = DEFAULT_KEY_TYPE,
) -> str:
    """Finalize order with a fresh key, store the result, return cert path."""
    # A fresh key on every issuance limits the exposure of a leaked key to
    # one certificate lifetime.
    cert_privkey = generate_private_key(key_type)
    certificate_pem = acme.finalize(order, create_csr(cert_privkey, domains))
    cert_path = storage.install_certificate(
        domains[0], certificate_pem, cert_privkey
    )
    LOG.info(f"Certificate and new private key saved: {cert_path}")
    return cert_path


def _issue(
    acme: AcmeClient,
    domains: list[str],
    provider_name: str,
    access_token: str | None,
    key_type: str,
) -> str:
    order = acme.new_order(domains)
    for authz_url in order.authorizations:
        perform_dns_challenge(acme, authz_url, provider_name, access_token)
    return finalize_order(acme, order, domains, key_type=key_type)


def extract_domains_for_renewal(
    cert_data: CertData, cert_dir: str
) -> list[str]:
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
                cert_obj = x509.load_pem_x509_certificate(f.read())
            try:
                san_ext = cert_obj.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
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
    domain_val = str(cert_data.get("domain", "")).strip()
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
    store_token: bool = True,
) -> None:
    target_directory = client.get_directory_url(
        staging=staging, custom_url=directory_url
    )
    LOG.info(f"Starting certificate request for domains: {domains}")

    account_dir, acme = connect_account(target_directory, email)
    _issue(acme, domains, dns_provider, access_token, key_type)

    home = storage.home()
    cert = SSLCertificate.from_pem(
        cert_path=f"{home}/{domains[0]}/cert.pem",
        key_path=f"{home}/{domains[0]}/privkey.pem",
        renew_before_days=20,
        renew_command=renew_command,
        provider=dns_provider,
        provider_conf=access_token if store_token else None,
        email=email,
    )
    cert.domains = domains
    cert.staging = staging
    cert.key_type = key_type
    cert.directory_url = directory_url
    cert.account = account_dir

    cert.save(f"{home}/{domains[0]}/certificate.json")


def _legacy_account_dir(folder_domain: str, primary_domain: str) -> str | None:
    """Per-domain account dir written by versions before 0.2.0, if any."""
    for candidate in (
        folder_domain,
        primary_domain,
        primary_domain.replace("*.", ""),
    ):
        if os.path.exists(
            os.path.join(storage.home(), candidate, "account_url.result")
        ):
            return candidate
    return None


def renew_certificate(
    cert_json_path: str,
    staging: bool | None = None,
    directory_url: str | None = None,
) -> None:
    if not os.path.exists(cert_json_path):
        raise RuntimeError(f"No certificate.json found at {cert_json_path}")

    with open(cert_json_path, encoding="utf-8") as f:
        cert_data: CertData = json.load(f)

    cert_dir = os.path.dirname(os.path.abspath(cert_json_path))
    folder_domain = os.path.basename(cert_dir)

    dns_provider = cert_data["provider"]
    access_token = resolve_access_token(
        dns_provider, cert_data.get("provider_conf")
    )

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

    # Recorded shared account, else the legacy per-domain account of
    # certificates issued by older versions, else (neither on disk) the
    # shared account, which is then recorded.
    if cert_data.get("account"):
        account_dir: str | None = storage.resolve_account_dir(
            cert_data, folder_domain
        )
    else:
        account_dir = _legacy_account_dir(folder_domain, primary_domain)

    is_staging = cert_data.get("staging", False) if staging is None else staging
    target_directory = client.get_directory_url(
        staging=is_staging,
        custom_url=directory_url or cert_data.get("directory_url"),
    )

    account_dir, acme = connect_account(
        target_directory, cert_data.get("email", ""), account_dir=account_dir
    )
    if not _legacy_account_dir(folder_domain, primary_domain):
        cert_data["account"] = account_dir

    cert_path = _issue(
        acme,
        ordered_domains,
        dns_provider,
        access_token,
        cert_data.get("key_type", DEFAULT_KEY_TYPE),
    )
    cert_path = cert_data.get("certificate_path") or cert_path

    with open(cert_path, "rb") as f:
        cert_obj = x509.load_pem_x509_certificate(f.read())
    cert_data.update(
        {
            "domains": ordered_domains,
            "expiry_date": cert_obj.not_valid_after_utc.strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
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


def _read_metadata(json_path: str) -> CertData:
    if not os.path.exists(json_path):
        return {}
    try:
        with open(json_path, encoding="utf-8") as f:
            data: CertData = json.load(f)
        return data
    except (OSError, ValueError) as exc:
        LOG.warning(f"Could not read {json_path}: {exc}")
        return {}


def _key_details(key_path: str, cert: x509.Certificate) -> tuple[str, str]:
    """Return (key type, whether the key matches the certificate)."""
    if not os.path.exists(key_path):
        return "Unknown", "Unknown"
    try:
        with open(key_path, "rb") as f:
            priv_key = serialization.load_pem_private_key(f.read(), None)
    except (OSError, ValueError, TypeError):
        return "Unknown", "Error reading key"

    pub_key = cert.public_key()
    if isinstance(priv_key, rsa.RSAPrivateKey) and isinstance(
        pub_key, rsa.RSAPublicKey
    ):
        match = (
            priv_key.public_key().public_numbers() == pub_key.public_numbers()
        )
        return f"RSA ({priv_key.key_size} bit)", "Yes" if match else "No"
    if isinstance(priv_key, ec.EllipticCurvePrivateKey) and isinstance(
        pub_key, ec.EllipticCurvePublicKey
    ):
        match = (
            priv_key.public_key().public_numbers() == pub_key.public_numbers()
        )
        return f"EC ({priv_key.curve.name})", "Yes" if match else "No"
    if isinstance(priv_key, rsa.RSAPrivateKey):
        return f"RSA ({priv_key.key_size} bit)", "No"
    if isinstance(priv_key, ec.EllipticCurvePrivateKey):
        return f"EC ({priv_key.curve.name})", "No"
    return "Unknown", "Unknown"


def inspect_certificate(domain: str) -> dict[str, str]:
    """Inspect detailed information of a locally stored certificate."""
    domain_dir = storage.certificate_dir(domain)
    cert_path = os.path.join(domain_dir, "cert.pem")
    key_path = os.path.join(domain_dir, "privkey.pem")
    json_path = os.path.join(domain_dir, "certificate.json")

    if not os.path.exists(cert_path):
        raise FileNotFoundError(f"Certificate not found for domain: {domain}")

    with open(cert_path, "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())

    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = str(cns[0].value) if cns else "N/A"

    try:
        sans = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    issuer_attrs = cert.issuer.get_attributes_for_oid(
        NameOID.ORGANIZATION_NAME
    ) or cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    issuer = str(issuer_attrs[0].value) if issuer_attrs else "Unknown"

    now = datetime.now(timezone.utc)
    valid_from = cert.not_valid_before_utc
    valid_to = cert.not_valid_after_utc

    meta = _read_metadata(json_path)
    key_type, key_matches = _key_details(key_path, cert)

    return {
        "Domain": domain,
        "Common Name": cn,
        "SANs": ", ".join(sans) if sans else cn,
        "Issuer": issuer,
        "Serial Number": f"{cert.serial_number:X}",
        "Valid From": valid_from.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Valid Until": valid_to.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "Days Remaining": f"{(valid_to - now).days} days",
        "Status": str(
            meta.get("status", "valid" if now <= valid_to else "expired")
        ),
        "Key Type": key_type,
        "Private Key Match": key_matches,
        "Provider": str(meta.get("provider", "N/A")),
        "Staging": "Yes" if meta.get("staging") else "No",
        "Renew Command": str(meta.get("renew_command", "N/A")),
        "Last Renewed": str(meta.get("last_renewed", "N/A")),
    }


def export_certificate(
    domain: str,
    output_path: str,
    export_format: str = "pem-bundle",
    password: str | None = None,
) -> str:
    """Export certificate and key as a PEM bundle or PKCS#12 (PFX)."""
    domain_dir = storage.certificate_dir(domain)
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
        cert = x509.load_pem_x509_certificate(cert_bytes)
        key = serialization.load_pem_private_key(key_bytes, password=None)
        if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
            raise ValueError(f"Unsupported private key type in {key_path}")
        encryption: serialization.KeySerializationEncryption = (
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


def revoke_certificate(
    domain: str,
    reason: int = 0,
    staging: bool | None = None,
    directory_url: str | None = None,
) -> None:
    """Revoke a certificate using the ACME revokeCert endpoint."""
    domain_dir = storage.certificate_dir(domain)
    cert_path = os.path.join(domain_dir, "cert.pem")
    cert_json_path = os.path.join(domain_dir, "certificate.json")

    if not os.path.exists(cert_path):
        raise FileNotFoundError(f"Certificate not found at {cert_path}")

    with open(cert_path, "rb") as f:
        cert_obj = x509.load_pem_x509_certificate(f.read())
    cert_der = cert_obj.public_bytes(serialization.Encoding.DER)

    cdata = _read_metadata(cert_json_path)
    is_staging = cdata.get("staging", False) if staging is None else staging
    target_directory = client.get_directory_url(
        staging=is_staging,
        custom_url=directory_url or cdata.get("directory_url"),
    )

    _, acme = connect_account(
        target_directory,
        cdata.get("email", ""),
        account_dir=storage.resolve_account_dir(cdata, domain),
        register=False,
    )
    acme.revoke(cert_der, reason)

    if cdata:
        cdata["status"] = "revoked"
        write_private_file(cert_json_path, json.dumps(cdata, indent=4))

    LOG.info(f"Certificate for {domain} has been successfully revoked.")
